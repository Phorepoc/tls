// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0

// tlsconnection_mbed.cpp -- the modern-TLS SSL.DLL drop-in on the REAL Symbian ABI.
//
// securesocket.dll (the 2010 release, unmodified) loads SSL.DLL BY NAME and calls its ordinals as plain function
// pointers (secsock/SecureSocket.cpp, securesocket_internal.h):
//     @1  MSecureSocket* CTlsConnection::NewL(RSocket&, const TDesC&)
//     @2  void           CTlsConnection::UnloadDll(TAny*)
//     @3  MSecureSocket* CTlsConnection::NewL(MGenericSecureSocket&, const TDesC&)
// (the frozen networksecurity/tls/eabi/sslU.def). Everything after that goes through the MSecureSocket vtable
// (securesocketinterface.h). This file answers both with mbedTLS 3.6 (TLS 1.2 + 1.3, ECDHE/AES-GCM/ChaCha20, SNI,
// certificate verification against the Mozilla roots) where the 2010 SSL.DLL speaks TLS 1.0 / SSL 3.0.
//
// Differences from a host (non-Symbian) build:
//  - the real headers: the MSecureSocket vtable order, TSockXfrLength, TDialogMode, sslerr.h codes, CX509Certificate;
//  - a concurrent read and write: the HTTP transport (httptransporthandler: CSocketReader + CSocketWriter) keeps a
//    RecvOneOrMore outstanding while it Sends, so the one-op pump became two transport AOs (a sender draining the
//    ciphertext queue, a receiver armed whenever mbedTLS wants bytes) and three independent client ops
//    (handshake / read / write) advanced by Progress();
//  - descriptors instead of std::vector; NewL leaves (the loader calls it inside a leaving ConstructL);
//  - Close() closes the transport, as CTlsConnection::Close does;
//  - a certificate that fails verification: attended dialog mode asks the user through the S60 security dialog
//    (MSecurityDialog::ServerAuthenticationFailure), as the 2010 TLS provider does; unattended mode refuses it.
// Trust anchors: z:\resource\ssl\ca-bundle.crt (the Mozilla roots, ROM data) -- the CACerts.dat bridge is P2.
#define MBEDTLS_CONFIG_FILE "phorepoc_mbedtls_config.h"

#include <e32base.h>
#include <e32debug.h>
#include <f32file.h>
#include <es_sock.h>
#include <securesocketinterface.h>
#include <ssl_internal.h>
#include <sslerr.h>
#include <x509cert.h>
#include <genericsecuresocket.h>
#include <secdlg.h>

#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"
#include "mbedtls/sha256.h"
#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "psa/crypto.h"
#endif

_LIT(KCaBundleName, "ca-bundle.crt");
_LIT(KCaBundleDir, "\\resource\\ssl\\");
static const TInt KRecvScratch = 16 * 1024 + 512;	// one TLS record + header

// PHOREPOC_SSL_TRACE: one RDebug line per handshake result / error
// PHOREPOC_SSL_FILELOG: the same lines appended to C:\data\ssl_trace.txt (a phone has no debug port)
#if defined(PHOREPOC_SSL_TRACE) && defined(PHOREPOC_SSL_FILELOG)
class TTlsLogOverflow : public TDes8Overflow
	{
public:
	void Overflow(TDes8& /*aDes*/) {}
	};

static void TlsFileLog(const char* aFmt, ...)
	{
	TBuf8<256> line;
	line.AppendNum(User::NTickCount());
	line.Append(' ');
	TTlsLogOverflow overflow;
	VA_LIST list;
	VA_START(list, aFmt);
	line.AppendFormatList(TPtrC8(reinterpret_cast<const TUint8*>(aFmt)), list, &overflow);
	VA_END(list);
	if (line.Length() < line.MaxLength())
		line.Append('\n');
	RFs fs;
	if (fs.Connect() != KErrNone)
		return;
	_LIT(KLogFile, "C:\\data\\ssl_trace.txt");
	RFile file;
	TInt err = file.Open(fs, KLogFile, EFileWrite | EFileShareAny);
	if (err == KErrNotFound)
		err = file.Create(fs, KLogFile, EFileWrite | EFileShareAny);
	if (err == KErrNone)
		{
		TInt pos = 0;
		file.Seek(ESeekEnd, pos);
		file.Write(line);
		file.Close();
		}
	fs.Close();
	}
#define TLSLOG(...) TlsFileLog(__VA_ARGS__)
#elif defined(PHOREPOC_SSL_TRACE)
#define TLSLOG(aFmt, ...) RDebug::Printf("PH: " aFmt, ##__VA_ARGS__)   // "PH:" = what the kernel forwards to the debug link
#else
#define TLSLOG(...)
#endif

class CTlsConnection;

// One transport direction: completes into CTlsConnection::IoDone.
class CTlsIo : public CActive
	{
public:
	CTlsIo(CTlsConnection& aOwner, TBool aSend) : CActive(EPriorityStandard), iOwner(aOwner), iSend(aSend)
		{ CActiveScheduler::Add(this); }
	~CTlsIo() { Cancel(); }
	void Go() { SetActive(); }
	TRequestStatus& Status() { return iStatus; }
private:
	void RunL();
	void DoCancel();
	CTlsConnection& iOwner;
	TBool iSend;
	};

// The "server authentication failure" query (the S60 security dialog notifier): completes into
// CTlsConnection::DialogDone.
class CTlsDialogAo : public CActive
	{
public:
	CTlsDialogAo(CTlsConnection& aOwner) : CActive(EPriorityStandard), iOwner(aOwner)
		{ CActiveScheduler::Add(this); }
	~CTlsDialogAo() { Cancel(); if (iDialog) iDialog->Release(); }
	void StartL(const TDesC8& aHost, TValidationError aReason, const TDesC8& aCert)
		{
		if (!iDialog)
			iDialog = SecurityDialogFactory::CreateL();
		iStatus = KRequestPending;
		iDialog->ServerAuthenticationFailure(aHost, aReason, aCert, iStatus);
		SetActive();
		}
private:
	void RunL();
	void DoCancel() { iDialog->Cancel(); }
	CTlsConnection& iOwner;
	MSecurityDialog* iDialog;
	};

class CTlsConnection : public CBase, public MSecureSocket
	{
public:
	IMPORT_C static MSecureSocket* NewL(RSocket& aSocket, const TDesC& aProtocol);
	IMPORT_C static MSecureSocket* NewL(MGenericSecureSocket& aSocket, const TDesC& aProtocol);
	IMPORT_C static void UnloadDll(TAny* aPtr);
	~CTlsConnection();

	// MSecureSocket, in securesocketinterface.h order
	TInt AvailableCipherSuites(TDes8& aCiphers);
	void CancelAll();
	void CancelHandshake();
	void CancelRecv();
	void CancelSend();
	const CX509Certificate* ClientCert() { TLSLOG("[ssl] ClientCert"); return NULL; }
	TClientCertMode ClientCertMode() { TLSLOG("[ssl] ClientCertMode"); return EClientCertModeIgnore; }
	void Close();
	TInt CurrentCipherSuite(TDes8& aCipherSuite);
	TDialogMode DialogMode() { TLSLOG("[ssl] DialogMode"); return iDialogMode; }
	void FlushSessionCache() { TLSLOG("[ssl] FlushSessionCache"); }
	TInt GetOpt(TUint aOptionName, TUint aOptionLevel, TDes8& aOption);
	TInt GetOpt(TUint aOptionName, TUint aOptionLevel, TInt& aOption);
	TInt Protocol(TDes& aProtocol);
	void Recv(TDes8& aDesc, TRequestStatus& aStatus);
	void RecvOneOrMore(TDes8& aDesc, TRequestStatus& aStatus, TSockXfrLength& aLen);
	void RenegotiateHandshake(TRequestStatus& aStatus) { TLSLOG("[ssl] Renegotiate"); Fail(aStatus, KErrNotSupported); }
	void Send(const TDesC8& aDesc, TRequestStatus& aStatus);
	void Send(const TDesC8& aDesc, TRequestStatus& aStatus, TSockXfrLength& aLen);
	const CX509Certificate* ServerCert();
	TInt SetAvailableCipherSuites(const TDesC8& aCiphers);
	TInt SetClientCert(const CX509Certificate&) { TLSLOG("[ssl] SetClientCert"); return KErrNotSupported; }
	TInt SetClientCertMode(const TClientCertMode aMode) { TLSLOG("[ssl] SetClientCertMode %d", aMode); return aMode == EClientCertModeIgnore ? KErrNone : KErrNotSupported; }
	TInt SetDialogMode(const TDialogMode aDialogMode) { TLSLOG("[ssl] SetDialogMode %d", aDialogMode); iDialogMode = aDialogMode; return KErrNone; }
	TInt SetOpt(TUint aOptionName, TUint aOptionLevel, const TDesC8& aOption);
	TInt SetOpt(TUint aOptionName, TUint aOptionLevel, TInt aOption);
	TInt SetProtocol(const TDesC& aProtocol);
	TInt SetServerCert(const CX509Certificate&) { TLSLOG("[ssl] SetServerCert"); return KErrNotSupported; }
	void StartClientHandshake(TRequestStatus& aStatus);
	void StartServerHandshake(TRequestStatus& aStatus) { TLSLOG("[ssl] StartServerHandshake"); Fail(aStatus, KErrNotSupported); }

	void IoDone(TBool aSend, TInt aResult);
	void IoCancel(TBool aSend);
	void DialogDone(TInt aResult);

private:
	CTlsConnection(RSocket* aSocket, MGenericSecureSocket* aGeneric);
	void ConstructL();
	void LoadTrustAnchorsL();
	static void Fail(TRequestStatus& aStatus, TInt aErr);
	void StartWrite(const TDesC8& aDesc, TRequestStatus& aStatus, TSockXfrLength* aLen);
	void StartRead(TDes8& aDesc, TRequestStatus& aStatus, TSockXfrLength* aLen, TBool aFill);

	// the engine
	void Progress();
	void Flush();
	void ArmRecv();
	void Complete(TRequestStatus*& aCaller, TInt aCode);
	void FailAll(TInt aErr);
	TInt MapErr(int aRc);
	TInt MapVerify(uint32_t aFlags);
	TBool PeerCertAccepted(TBool aRemember);
	void StartDialogL(uint32_t aFlags, const TDesC8& aCert);
	void RefusePeerCert(TInt aErr);
	static int BioSend(void* aCtx, const unsigned char* aBuf, size_t aLen);
	static int BioRecv(void* aCtx, unsigned char* aBuf, size_t aLen);

	// the transport: an RSocket (ordinal 1) or a socket-like object (ordinal 3)
	RSocket* iSocket;
	MGenericSecureSocket* iGeneric;

	mbedtls_ssl_context iSsl;
	mbedtls_ssl_config iConf;
	mbedtls_ctr_drbg_context iDrbg;
	mbedtls_entropy_context iEntropy;
	mbedtls_x509_crt iCa;
	TBool iConnected;
	TBool iClosed;
	TInt iFatal;					// sticky transport / protocol error
	TDialogMode iDialogMode;
	TBool iVerifyPending;			// the handshake is done but the certificate awaits the user's answer
	TBuf8<256> iHost;				// KSoSSLDomainName (SNI, name check, the dialog)
	CTlsDialogAo* iDialogAo;

	// client ops (one of each at a time)
	TRequestStatus* iHandshake;
	TRequestStatus* iRead;
	TDes8* iReadDes;
	TSockXfrLength* iReadLen;
	TBool iReadFill;				// Recv(): fill the descriptor, not one-or-more
	TRequestStatus* iWrite;
	TPtrC8 iWriteData;
	TInt iWriteDone;
	TSockXfrLength* iWriteLen;
	TBool iWriteFlushing;			// all handed to mbedTLS; completes when the ciphertext is on the wire

	// ciphertext queues
	RBuf8 iOut;						// produced by mbedTLS, not yet handed to the transport
	RBuf8 iSending;					// the outstanding transport send
	RBuf8 iIn;						// received, not yet consumed by mbedTLS
	TInt iInPos;
	RBuf8 iRecvBuf;					// the outstanding transport receive
	TPtr8 iRecvView;				// (the generic transport: the exact-length window into iRecvBuf)
	TSockXfrLength iRecvXfr;
	TInt iWant;						// bytes mbedTLS asked for last (the generic transport reads exactly that)
	CTlsIo* iSender;
	CTlsIo* iReceiver;
	CX509Certificate* iServerCert;
	};

// ---- the transport AOs ------------------------------------------------------------------------------------------
void CTlsIo::RunL() { iOwner.IoDone(iSend, iStatus.Int()); }
void CTlsIo::DoCancel() { iOwner.IoCancel(iSend); }
void CTlsDialogAo::RunL() { iOwner.DialogDone(iStatus.Int()); }

void CTlsConnection::IoCancel(TBool aSend)
	{
	if (iSocket)
		{
		if (aSend) iSocket->CancelSend(); else iSocket->CancelRecv();
		}
	else
		{
		if (aSend) iGeneric->CancelSend(); else iGeneric->CancelRecv();
		}
	}

// ---- construction -----------------------------------------------------------------------------------------------
EXPORT_C MSecureSocket* CTlsConnection::NewL(RSocket& aSocket, const TDesC& /*aProtocol*/)
	{
	TLSLOG("[ssl] NewL(RSocket)");
	CTlsConnection* self = new(ELeave) CTlsConnection(&aSocket, NULL);
	CleanupStack::PushL(self);
	self->ConstructL();
	CleanupStack::Pop(self);
	return self;
	}

EXPORT_C MSecureSocket* CTlsConnection::NewL(MGenericSecureSocket& aSocket, const TDesC& /*aProtocol*/)
	{
	TLSLOG("[ssl] NewL(generic)");
	CTlsConnection* self = new(ELeave) CTlsConnection(NULL, &aSocket);
	CleanupStack::PushL(self);
	self->ConstructL();
	CleanupStack::Pop(self);
	return self;
	}

EXPORT_C void CTlsConnection::UnloadDll(TAny* /*aPtr*/)
	{
	}

CTlsConnection::CTlsConnection(RSocket* aSocket, MGenericSecureSocket* aGeneric)
	: iSocket(aSocket), iGeneric(aGeneric), iDialogMode(EDialogModeAttended), iRecvView(NULL, 0)
	{
	mbedtls_ssl_init(&iSsl);
	mbedtls_ssl_config_init(&iConf);
	mbedtls_ctr_drbg_init(&iDrbg);
	mbedtls_entropy_init(&iEntropy);
	mbedtls_x509_crt_init(&iCa);
	}

void CTlsConnection::ConstructL()
	{
	iOut.CreateL(2048);
	iSending.CreateL(2048);
	iIn.CreateL(KRecvScratch);
	iRecvBuf.CreateL(KRecvScratch);
	iSender = new(ELeave) CTlsIo(*this, ETrue);
	iReceiver = new(ELeave) CTlsIo(*this, EFalse);

#if defined(MBEDTLS_USE_PSA_CRYPTO)
	// TLS 1.3 runs on PSA crypto: its global state is set up once per process (repeat calls return at once)
	TLSLOG("[ssl] %08x psa init", this);
	if (psa_crypto_init() != PSA_SUCCESS)
		User::Leave(KErrGeneral);
#endif
	static const char KPers[] = "phorepoc-ssl.dll";
	if (mbedtls_ctr_drbg_seed(&iDrbg, mbedtls_entropy_func, &iEntropy, (const unsigned char*)KPers, sizeof(KPers) - 1))
		User::Leave(KErrGeneral);
	if (mbedtls_ssl_config_defaults(&iConf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
									MBEDTLS_SSL_PRESET_DEFAULT))
		User::Leave(KErrGeneral);
	mbedtls_ssl_conf_min_tls_version(&iConf, MBEDTLS_SSL_VERSION_TLS1_2);
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
	mbedtls_ssl_conf_max_tls_version(&iConf, MBEDTLS_SSL_VERSION_TLS1_3);
#else
	mbedtls_ssl_conf_max_tls_version(&iConf, MBEDTLS_SSL_VERSION_TLS1_2);
#endif
	mbedtls_ssl_conf_rng(&iConf, mbedtls_ctr_drbg_random, &iDrbg);
	TLSLOG("[ssl] %08x rng seeded, loading trust anchors", this);
	LoadTrustAnchorsL();
	mbedtls_ssl_conf_ca_chain(&iConf, &iCa, NULL);
	// OPTIONAL: a certificate that fails verification ends the handshake here, not in mbedTLS -- attended mode then
	// asks the user as the 2010 TLS provider does (Progress), unattended mode refuses it
	mbedtls_ssl_conf_authmode(&iConf, MBEDTLS_SSL_VERIFY_OPTIONAL);
	if (mbedtls_ssl_setup(&iSsl, &iConf))
		User::Leave(KErrNoMemory);
	mbedtls_ssl_set_bio(&iSsl, this, &CTlsConnection::BioSend, &CTlsConnection::BioRecv, NULL);
	TLSLOG("[ssl] %08x constructed", this);
	}

// The CA bundle (PEM): read with the file server (no libc stdio in the client's process needed), NUL-terminated
// for mbedtls_x509_crt_parse. A certificate mbedTLS cannot parse is skipped (parse returns the count of failures).
void CTlsConnection::LoadTrustAnchorsL()
	{
	RFs fs;
	User::LeaveIfError(fs.Connect());
	CleanupClosePushL(fs);
	// every drive, the loader's order (C: before Z:): Phorepoc ships the bundle as ROM data, a stock phone carries it
	// on C: next to this DLL's eclipsing copy
	TFindFile find(fs);
	User::LeaveIfError(find.FindByDir(KCaBundleName, KCaBundleDir));
	RFile f;
	User::LeaveIfError(f.Open(fs, find.File(), EFileRead | EFileShareReadersOnly));
	CleanupClosePushL(f);
	TInt size = 0;
	User::LeaveIfError(f.Size(size));
	RBuf8 pem;
	pem.CreateL(size + 1);
	CleanupClosePushL(pem);
	User::LeaveIfError(f.Read(pem));
	pem.Append(TChar(0));
	int rc = mbedtls_x509_crt_parse(&iCa, pem.Ptr(), (size_t)pem.Length());
#ifdef PHOREPOC_SSL_TRACE
	TInt n = 0;
	for (const mbedtls_x509_crt* c = &iCa; c && c->raw.p; c = c->next)
		++n;
	TLSLOG("[ssl] %d trust anchors (%d skipped)", n, rc);
#endif
	(void)rc;
	CleanupStack::PopAndDestroy(3, &fs);
	if (!iCa.raw.p)
		User::Leave(KErrNotFound);
	}

CTlsConnection::~CTlsConnection()
	{
	TLSLOG("[ssl] %08x destroyed", this);
	delete iDialogAo;
	delete iSender;
	delete iReceiver;
	delete iServerCert;
	mbedtls_ssl_free(&iSsl);
	mbedtls_ssl_config_free(&iConf);
	mbedtls_ctr_drbg_free(&iDrbg);
	mbedtls_entropy_free(&iEntropy);
	mbedtls_x509_crt_free(&iCa);
	iOut.Close();
	iSending.Close();
	iIn.Close();
	iRecvBuf.Close();
	}

// ---- mbedTLS BIO: queues, never blocks --------------------------------------------------------------------------
int CTlsConnection::BioSend(void* aCtx, const unsigned char* aBuf, size_t aLen)
	{
	CTlsConnection* self = static_cast<CTlsConnection*>(aCtx);
	TPtrC8 data(aBuf, (TInt)aLen);
	if (self->iOut.Length() + (TInt)aLen > self->iOut.MaxLength()
		&& self->iOut.ReAlloc(self->iOut.Length() + (TInt)aLen + 1024) != KErrNone)
		return MBEDTLS_ERR_SSL_ALLOC_FAILED;
	self->iOut.Append(data);
	return (int)aLen;
	}

int CTlsConnection::BioRecv(void* aCtx, unsigned char* aBuf, size_t aLen)
	{
	CTlsConnection* self = static_cast<CTlsConnection*>(aCtx);
	TInt avail = self->iIn.Length() - self->iInPos;
	if (avail == 0)
		{
		self->iWant = (TInt)aLen;
		return self->iClosed ? 0 : MBEDTLS_ERR_SSL_WANT_READ;
		}
	TInt n = Min((TInt)aLen, avail);
	Mem::Copy(aBuf, self->iIn.Ptr() + self->iInPos, n);
	self->iInPos += n;
	if (self->iInPos == self->iIn.Length())
		{
		self->iIn.Zero();
		self->iInPos = 0;
		}
	return n;
	}

// ---- the engine -------------------------------------------------------------------------------------------------
void CTlsConnection::Fail(TRequestStatus& aStatus, TInt aErr)
	{
	TRequestStatus* s = &aStatus;
	User::RequestComplete(s, aErr);
	}

void CTlsConnection::Complete(TRequestStatus*& aCaller, TInt aCode)
	{
	if (aCaller)
		User::RequestComplete(aCaller, aCode);	// nulls aCaller
	}

void CTlsConnection::FailAll(TInt aErr)
	{
	if (!iFatal)
		iFatal = aErr;
	Complete(iHandshake, aErr);
	Complete(iRead, aErr);
	Complete(iWrite, aErr);
	}

TInt CTlsConnection::MapErr(int aRc)
	{
	switch (aRc)
		{
	case MBEDTLS_ERR_X509_CERT_VERIFY_FAILED:
		return MapVerify(mbedtls_ssl_get_verify_result(&iSsl));
	case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
		return KErrEof;
	case MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE:
		return KErrSSLAlertHandshakeFailure;
	case MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE:
		return KErrSSLAlertHandshakeFailure;
	case MBEDTLS_ERR_SSL_ALLOC_FAILED:
		return KErrNoMemory;
	default:
		// an mbedTLS error with no TLS-alert counterpart: always logged (rare), it is the only clue a caller gets
		RDebug::Printf("PH: [ssl] mbedTLS error -0x%04x -> KErrSSLAlertInternalError", (TUint)-aRc);
		return KErrSSLAlertInternalError;
		}
	}

// As the 2010 TLS provider's unattended mode (CTlsProvider.cpp, EValidateCertificate)
TInt CTlsConnection::MapVerify(uint32_t aFlags)
	{
	TLSLOG("[ssl] certificate verify failed: flags 0x%x", (TUint)aFlags);
	if (aFlags & MBEDTLS_X509_BADCERT_NOT_TRUSTED)
		return KErrSSLAlertUnknownCA;
	if (aFlags & MBEDTLS_X509_BADCERT_REVOKED)
		return KErrSSLAlertCertificateRevoked;
	if (aFlags & (MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE))
		return KErrSSLAlertCertificateExpired;
	return KErrSSLAlertBadCertificate;
	}

// The reason as the S60 dialog reads it (CTSecurityDialogsAO.cpp): EValidatedOK / EDateOutOfRange = a trusted
// certificate with a name or date problem (the dialog tells them apart by comparing the CN with the host),
// EChainHasNoRoot = untrusted (can be accepted), ECertificateRevoked = refused outright.
static TValidationError DialogReason(uint32_t aFlags)
	{
	if (aFlags & MBEDTLS_X509_BADCERT_REVOKED)
		return ECertificateRevoked;
	if (aFlags & ~(MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE | MBEDTLS_X509_BADCERT_CN_MISMATCH))
		return EChainHasNoRoot;
	if (aFlags & (MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE))
		return EDateOutOfRange;
	return EValidatedOK;
	}

// Certificates the user accepted, per process (the 2010 provider keeps them in its cache server for the session;
// "accept permanently" goes to the dialog's own trusted-sites store): SHA-256 of the leaf + the host.
const TInt KMaxAccepted = 16;
static TUint8 gAccepted[KMaxAccepted][32];
static TInt gAcceptedCount;
static TInt gAcceptedNext;

TBool CTlsConnection::PeerCertAccepted(TBool aRemember)
	{
	const mbedtls_x509_crt* peer = mbedtls_ssl_get_peer_cert(&iSsl);
	if (!peer)
		return EFalse;
	TUint8 digest[32];
	mbedtls_sha256_context sha;
	mbedtls_sha256_init(&sha);
	mbedtls_sha256_starts(&sha, 0);
	mbedtls_sha256_update(&sha, peer->raw.p, peer->raw.len);
	mbedtls_sha256_update(&sha, iHost.Ptr(), iHost.Length());
	mbedtls_sha256_finish(&sha, digest);
	mbedtls_sha256_free(&sha);
	for (TInt i = 0; i < gAcceptedCount; ++i)
		if (Mem::Compare(gAccepted[i], 32, digest, 32) == 0)
			return ETrue;
	if (aRemember)
		{
		Mem::Copy(gAccepted[gAcceptedNext], digest, 32);
		gAcceptedNext = (gAcceptedNext + 1) % KMaxAccepted;
		if (gAcceptedCount < KMaxAccepted)
			++gAcceptedCount;
		}
	return EFalse;
	}

void CTlsConnection::StartDialogL(uint32_t aFlags, const TDesC8& aCert)
	{
	if (!iDialogAo)
		iDialogAo = new(ELeave) CTlsDialogAo(*this);
	iDialogAo->StartL(iHost, DialogReason(aFlags), aCert);
	}

void CTlsConnection::RefusePeerCert(TInt aErr)
	{
	mbedtls_ssl_send_alert_message(&iSsl, MBEDTLS_SSL_ALERT_LEVEL_FATAL, MBEDTLS_SSL_ALERT_MSG_BAD_CERT);
	Flush();
	FailAll(aErr);
	}

void CTlsConnection::DialogDone(TInt aResult)
	{
	TLSLOG("[ssl] %08x certificate query: %d", this, aResult);
	iVerifyPending = EFalse;
	if (aResult != KErrNone)
		{
		RefusePeerCert(KErrAbort);		// as the provider's EStop / EEntryDenied
		return;
		}
	PeerCertAccepted(ETrue);
	iConnected = ETrue;
	if (iOut.Length() == 0 && !iSender->IsActive())
		Complete(iHandshake, KErrNone);
	Progress();
	}

// Hand queued ciphertext to the transport (one send outstanding).
void CTlsConnection::Flush()
	{
	if (iSender->IsActive() || iOut.Length() == 0 || iFatal)
		return;
	iSending.Swap(iOut);
	iOut.Zero();
	if (iSocket)
		iSocket->Send(iSending, 0, iSender->Status());
	else
		iGeneric->Send(iSending, 0, iSender->Status());
	iSender->Go();
	}

// mbedTLS wants bytes: one receive outstanding.
void CTlsConnection::ArmRecv()
	{
	if (iReceiver->IsActive() || iClosed || iFatal)
		return;
	iRecvBuf.Zero();
	if (iSocket)
		{
		iSocket->RecvOneOrMore(iRecvBuf, 0, iReceiver->Status(), iRecvXfr);
		}
	else
		{
		// a socket-like object has no one-or-more read (its Recv fills the descriptor): ask for exactly what mbedTLS
		// wants next -- a record header, then the record body (mbedTLS fetches records with exact lengths)
		iRecvView.Set(const_cast<TUint8*>(iRecvBuf.Ptr()), 0, Max(1, Min(iWant, iRecvBuf.MaxLength())));
		iGeneric->Recv(iRecvView, 0, iReceiver->Status());
		}
	iReceiver->Go();
	}

void CTlsConnection::IoDone(TBool aSend, TInt aResult)
	{
	TLSLOG("[ssl] %08x io %s %d n=%d", this, aSend ? "tx" : "rx", aResult, aSend ? iSending.Length() : (iGeneric ? iRecvView.Length() : iRecvBuf.Length()));
	if (aSend)
		{
		iSending.Zero();
		if (aResult != KErrNone)
			{
			FailAll(aResult);
			return;
			}
		}
	else
		{
		if (aResult == KErrEof)
			iClosed = ETrue;			// mbedTLS sees EOF (BioRecv 0) -> the read completes with KErrEof
		else if (aResult != KErrNone)
			{
			FailAll(aResult);
			return;
			}
		if (iGeneric)
			iRecvBuf.SetLength(iRecvView.Length());
		if (iRecvBuf.Length())
			{
			if (iIn.Length() + iRecvBuf.Length() > iIn.MaxLength()
				&& iIn.ReAlloc(iIn.Length() + iRecvBuf.Length()) != KErrNone)
				{
				FailAll(KErrNoMemory);
				return;
				}
			iIn.Append(iRecvBuf);
			}
		}
	Progress();
	}

// Advance every pending client op as far as the queued bytes allow, then flush / arm the transport.
void CTlsConnection::Progress()
	{
	if (iFatal)
		{
		FailAll(iFatal);
		return;
		}
	TBool needRecv = EFalse;

	if (iHandshake && !iConnected && !iVerifyPending)
		{
		int rc = mbedtls_ssl_handshake(&iSsl);
		const uint32_t flags = rc == 0 ? mbedtls_ssl_get_verify_result(&iSsl) : 0;
		if (rc == 0 && flags && !PeerCertAccepted(EFalse))
			{
			if (iDialogMode == EDialogModeUnattended)
				{
				RefusePeerCert(MapVerify(flags));
				return;
				}
			const mbedtls_x509_crt* peer = mbedtls_ssl_get_peer_cert(&iSsl);
			TLSLOG("[ssl] %08x certificate flags 0x%x: asking the user", this, (TUint)flags);
			TInt err = KErrNotFound;
			if (peer)
				TRAP(err, StartDialogL(flags, TPtrC8(peer->raw.p, peer->raw.len)));
			if (err != KErrNone)
				{
				RefusePeerCert(MapVerify(flags));	// no dialog available: as unattended
				return;
				}
			iVerifyPending = ETrue;
			Flush();						// (TLS 1.3: our Finished)
			return;
			}
		if (rc == 0)
			{
			iConnected = ETrue;
			TLSLOG("[ssl] handshake done: %s %s", mbedtls_ssl_get_version(&iSsl), mbedtls_ssl_get_ciphersuite(&iSsl));
			if (iOut.Length() == 0)
				Complete(iHandshake, KErrNone);
			}
		else if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE)
			needRecv = rc == MBEDTLS_ERR_SSL_WANT_READ;
		else
			{
			TLSLOG("[ssl] handshake failed: -0x%04x", -rc);
			Flush();					// the alert, if any
			FailAll(MapErr(rc));
			return;
			}
		}

	if (iWrite && iConnected && !iWriteFlushing)
		{
		while (iWriteDone < iWriteData.Length())
			{
			int rc = mbedtls_ssl_write(&iSsl, iWriteData.Ptr() + iWriteDone, (size_t)(iWriteData.Length() - iWriteDone));
			if (rc > 0)
				iWriteDone += rc;
			else if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE)
				break;
			else
				{
				FailAll(MapErr(rc));
				return;
				}
			}
		if (iWriteDone == iWriteData.Length())
			iWriteFlushing = ETrue;
		}

	if (iRead && iConnected)
		{
		for (;;)
			{
			TInt room = iReadDes->MaxLength() - iReadDes->Length();
			if (room == 0)
				break;
			int rc = mbedtls_ssl_read(&iSsl, const_cast<TUint8*>(iReadDes->Ptr()) + iReadDes->Length(), (size_t)room);
			if (rc > 0)
				{
				iReadDes->SetLength(iReadDes->Length() + rc);
				if (!iReadFill)
					break;
				}
			else if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE)
				{
				needRecv = ETrue;
				break;
				}
			else if (rc == 0 || rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
				{
				TLSLOG("[ssl] %08x read eof rc=%d have=%d", this, rc, iReadDes->Length());
				if (iReadDes->Length() == 0)
					{
					Complete(iRead, KErrEof);
					}
				break;
				}
#ifdef MBEDTLS_SSL_PROTO_TLS1_3
			else if (rc == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
				continue;
#endif
			else
				{
				TLSLOG("[ssl] %08x read error -0x%04x", this, -rc);
				FailAll(MapErr(rc));
				return;
				}
			}
		if (iRead && iReadDes->Length() > 0 && (!iReadFill || iReadDes->Length() == iReadDes->MaxLength()))
			{
			if (iReadLen)
				(*iReadLen)() = iReadDes->Length();
			TLSLOG("[ssl] %08x read done %d", this, iReadDes->Length());
			Complete(iRead, KErrNone);
			}
		}

	Flush();
	// a write / the handshake's last flight completes once its ciphertext is on the wire
	if (!iSender->IsActive() && iOut.Length() == 0)
		{
		if (iWriteFlushing && iWrite)
			{
			iWriteFlushing = EFalse;
			if (iWriteLen)
				(*iWriteLen)() = iWriteData.Length();
			Complete(iWrite, KErrNone);
			}
		if (iHandshake && iConnected)
			Complete(iHandshake, KErrNone);
		}
	if (needRecv)
		ArmRecv();
	}

// ---- MSecureSocket ----------------------------------------------------------------------------------------------
void CTlsConnection::StartClientHandshake(TRequestStatus& aStatus)
	{
	aStatus = KRequestPending;
	if (iHandshake || iConnected)
		{
		Fail(aStatus, KErrInUse);
		return;
		}
	iHandshake = &aStatus;
	TLSLOG("[ssl] %08x client handshake starts", this);
	Progress();
	}

void CTlsConnection::StartWrite(const TDesC8& aDesc, TRequestStatus& aStatus, TSockXfrLength* aLen)
	{
	aStatus = KRequestPending;
	if (iWrite)
		{
		Fail(aStatus, KErrInUse);
		return;
		}
	TLSLOG("[ssl] %08x write %d", this, aDesc.Length());
	iWrite = &aStatus;
	iWriteData.Set(aDesc);
	iWriteDone = 0;
	iWriteLen = aLen;
	iWriteFlushing = EFalse;
	if (!iConnected && !iHandshake)
		{
		Complete(iWrite, iFatal ? iFatal : KErrNotReady);
		return;
		}
	Progress();
	}

void CTlsConnection::StartRead(TDes8& aDesc, TRequestStatus& aStatus, TSockXfrLength* aLen, TBool aFill)
	{
	aStatus = KRequestPending;
	if (iRead)
		{
		Fail(aStatus, KErrInUse);
		return;
		}
	aDesc.Zero();
	TLSLOG("[ssl] %08x read max=%d fill=%d in=%d avail=%d closed=%d", this, aDesc.MaxLength(), aFill, iIn.Length(), iConnected ? (TInt)mbedtls_ssl_get_bytes_avail(&iSsl) : -1, iClosed);
	iRead = &aStatus;
	iReadDes = &aDesc;
	iReadLen = aLen;
	iReadFill = aFill;
	if (!iConnected && !iHandshake)
		{
		Complete(iRead, iFatal ? iFatal : KErrNotReady);
		return;
		}
	Progress();
	}

void CTlsConnection::Send(const TDesC8& aDesc, TRequestStatus& aStatus, TSockXfrLength& aLen)
	{
	StartWrite(aDesc, aStatus, &aLen);
	}

void CTlsConnection::Send(const TDesC8& aDesc, TRequestStatus& aStatus)
	{
	StartWrite(aDesc, aStatus, NULL);
	}

void CTlsConnection::RecvOneOrMore(TDes8& aDesc, TRequestStatus& aStatus, TSockXfrLength& aLen)
	{
	StartRead(aDesc, aStatus, &aLen, EFalse);
	}

void CTlsConnection::Recv(TDes8& aDesc, TRequestStatus& aStatus)
	{
	StartRead(aDesc, aStatus, NULL, ETrue);
	}

// A cancelled op completes with KErrCancel; the transport keeps going (a half-sent record would break the stream,
// bytes received meanwhile stay queued for the next read).
void CTlsConnection::CancelSend()
	{
	TLSLOG("[ssl] %08x CancelSend", this);
	iWriteFlushing = EFalse;
	Complete(iWrite, KErrCancel);
	}

void CTlsConnection::CancelRecv()
	{
	if (iRead)
		TLSLOG("[ssl] %08x cancel read", this);
	Complete(iRead, KErrCancel);
	}

void CTlsConnection::CancelHandshake()
	{
	if (iHandshake)
		{
		iReceiver->Cancel();
		if (iDialogAo)
			iDialogAo->Cancel();
		iVerifyPending = EFalse;
		Complete(iHandshake, KErrCancel);
		}
	}

void CTlsConnection::CancelAll()
	{
	TLSLOG("[ssl] %08x CancelAll", this);
	CancelHandshake();
	CancelRecv();
	CancelSend();
	}

// As CTlsConnection::Close: cancel everything, close the transport. A close_notify goes out first (best effort,
// synchronously: the destructor follows at once).
void CTlsConnection::Close()
	{
	TLSLOG("[ssl] %08x close in=%d", this, iIn.Length());
	CancelAll();
	iSender->Cancel();
	iReceiver->Cancel();
	if (iConnected && !iFatal)
		{
		mbedtls_ssl_close_notify(&iSsl);
		if (iOut.Length())
			{
			TRequestStatus s;
			if (iSocket)
				iSocket->Send(iOut, 0, s);
			else
				iGeneric->Send(iOut, 0, s);
			User::WaitForRequest(s);
			iOut.Zero();
			}
		}
	iConnected = EFalse;
	iFatal = KErrDisconnected;
	if (iSocket)
		iSocket->Close();
	else
		iGeneric->Close();
	}

const CX509Certificate* CTlsConnection::ServerCert()
	{
	TLSLOG("[ssl] %08x ServerCert (cached %d)", this, iServerCert != NULL);
	if (iServerCert)
		return iServerCert;
	const mbedtls_x509_crt* peer = mbedtls_ssl_get_peer_cert(&iSsl);
	if (!peer)
		return NULL;
	TPtrC8 der(peer->raw.p, (TInt)peer->raw.len);
	TRAPD(err, iServerCert = CX509Certificate::NewL(der));
	TLSLOG("[ssl] %08x ServerCert: %d bytes DER -> x509 err %d", this, der.Length(), err);
	return err == KErrNone ? iServerCert : NULL;
	}

TInt CTlsConnection::CurrentCipherSuite(TDes8& aCipherSuite)
	{
	TLSLOG("[ssl] %08x CurrentCipherSuite", this);
	if (aCipherSuite.MaxLength() < 2)
		return KErrOverflow;
	int id = iConnected ? mbedtls_ssl_get_ciphersuite_id_from_ssl(&iSsl) : 0;
	aCipherSuite.SetLength(2);
	aCipherSuite[0] = (TUint8)(id >> 8);
	aCipherSuite[1] = (TUint8)id;
	return KErrNone;
	}

// The suites mbedTLS offers ([hi][lo] pairs).
TInt CTlsConnection::AvailableCipherSuites(TDes8& aCiphers)
	{
	TLSLOG("[ssl] %08x AvailableCipherSuites max=%d", this, aCiphers.MaxLength());
	aCiphers.Zero();
	for (const int* p = mbedtls_ssl_list_ciphersuites(); *p; ++p)
		{
		if (aCiphers.Length() + 2 > aCiphers.MaxLength())
			return KErrOverflow;
		aCiphers.Append((TUint8)(*p >> 8));
		aCiphers.Append((TUint8)*p);
		}
	return KErrNone;
	}

// Callers pick from the 2010 SSL.DLL's (TLS 1.0-era) list: honouring it would switch off every modern suite, so
// the request is accepted and mbedTLS keeps its own preference order.
TInt CTlsConnection::SetAvailableCipherSuites(const TDesC8& /*aCiphers*/)
	{
	return KErrNone;
	}

TInt CTlsConnection::GetOpt(TUint aOptionName, TUint aOptionLevel, TInt& aOption)
	{
	TLSLOG("[ssl] %08x GetOpt(int) %x/%x", this, aOptionName, aOptionLevel);
	if (aOptionName == KSOReadBytesPending && aOptionLevel == KSOLSocket)
		{
		aOption = (TInt)mbedtls_ssl_get_bytes_avail(&iSsl);
		return KErrNone;
		}
	if (iSocket)
		return iSocket->GetOpt(aOptionName, aOptionLevel, aOption);
	return KErrNotSupported;
	}

TInt CTlsConnection::GetOpt(TUint aOptionName, TUint aOptionLevel, TDes8& aOption)
	{
	TLSLOG("[ssl] %08x GetOpt(des) %x/%x", this, aOptionName, aOptionLevel);
	if (aOptionLevel == KSolInetSSL)
		return KErrNotSupported;
	if (iSocket)
		return iSocket->GetOpt(aOptionName, aOptionLevel, aOption);
	return iGeneric->GetOpt(aOptionName, aOptionLevel, aOption);
	}

TInt CTlsConnection::SetOpt(TUint aOptionName, TUint aOptionLevel, const TDesC8& aOption)
	{
	TLSLOG("[ssl] %08x SetOpt(des) %x/%x len %d", this, aOptionName, aOptionLevel, aOption.Length());
	if (aOptionLevel != KSolInetSSL)
		return iSocket ? iSocket->SetOpt(aOptionName, aOptionLevel, aOption)
					   : iGeneric->SetOpt(aOptionName, aOptionLevel, aOption);
	switch (aOptionName)
		{
	case KSoSSLDomainName:
		{
		iHost.Copy(aOption.Left(255));
		TBuf8<256> host(iHost);
		return mbedtls_ssl_set_hostname(&iSsl, (const char*)host.PtrZ()) == 0 ? KErrNone : KErrArgument;
		}
	case KSoDialogMode:
		if (aOption.Length() < (TInt)sizeof(TUint))
			return KErrArgument;
		return SetDialogMode((TDialogMode)*(const TUint*)aOption.Ptr());
	case KSoUseSSLv2Handshake:	// never an SSLv2 hello
	default:
		return KErrNone;		// the other SSL options (dialogs, PSK, NULL ciphers ...) do not apply
		}
	}

TInt CTlsConnection::SetOpt(TUint aOptionName, TUint aOptionLevel, TInt aOption)
	{
	TLSLOG("[ssl] %08x SetOpt(int) %x/%x = %d", this, aOptionName, aOptionLevel, aOption);
	if (aOptionLevel == KSolInetSSL)
		return KErrNone;
	if (iSocket)
		return iSocket->SetOpt(aOptionName, aOptionLevel, aOption);
	TPckgBuf<TInt> opt(aOption);
	return iGeneric->SetOpt(aOptionName, aOptionLevel, opt);
	}

// The protocol is advisory ("TLS1.0" / "SSL3.0" from 2010 callers): we always negotiate TLS 1.2+.
TInt CTlsConnection::SetProtocol(const TDesC& /*aProtocol*/)
	{
	return KErrNone;
	}

TInt CTlsConnection::Protocol(TDes& aProtocol)
	{
	TLSLOG("[ssl] %08x Protocol max=%d", this, aProtocol.MaxLength());
	// the negotiated version once connected ("TLS1.2" / "TLS1.3"), else the highest one offered
	_LIT(KTls12, "TLS1.2");
	_LIT(KTls13, "TLS1.3");
	TPtrC name(KTls12);
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
	if (!iConnected || mbedtls_ssl_get_version_number(&iSsl) == MBEDTLS_SSL_VERSION_TLS1_3)
		name.Set(KTls13);
#endif
	if (aProtocol.MaxLength() < name.Length())
		return KErrOverflow;
	aProtocol.Copy(name);
	return KErrNone;
	}
