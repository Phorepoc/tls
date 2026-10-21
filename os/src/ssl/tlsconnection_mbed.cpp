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

#include <stdlib.h>
#include <string.h>
#include "tls_conf.h"
#include "tls_sesscache.h"
#include "tls_stubcert.h"

_LIT(KCaBundleName, "ca-bundle.crt");
_LIT(KSettingsName, "ssl.ini");
_LIT(KCaBundleDir, "\\resource\\ssl\\");
static const TInt KRecvScratch = 16 * 1024 + 512;	// one TLS record + header

// Phorepoc options on the KSolInetSSL level (no stock client uses them; our own tests and clients can):
//   GetOpt(int)  KPhSoSessionResumed: 1 if this connection resumed a cached session (no certificate exchange)
//   SetOpt(des)  KPhSoAlpn:           the ALPN protocols to offer, comma separated ("h2,http/1.1"); before the handshake
//   GetOpt(des)  KPhSoAlpn:           the protocol the server selected ("" = none)
const TUint KPhSoSessionResumed = 0x50480001;
const TUint KPhSoAlpn = 0x50480002;

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

// ---- state shared by every connection in the process ------------------------------------------------------------
// A plain spin lock: the critical sections below are a few pointer moves (the long work -- parsing the trust anchors,
// writing the session file -- happens outside them).
static void SpinLock(TInt& aLock)
	{
	while (User::LockedInc(aLock) != 0)
		{
		User::LockedDec(aLock);
		User::After(1000);
		}
	}

static void SpinUnlock(TInt& aLock)
	{
	User::LockedDec(aLock);
	}

// The runtime switches (ssl.ini, see tls_conf.h): re-read for every connection, so a change applies to the next one.
static void ReadSettings(phtls_conf& aConf)
	{
	phtls_conf_defaults(&aConf);
	RFs fs;
	if (fs.Connect() != KErrNone)
		return;
	TFindFile find(fs);
	RFile f;
	if (find.FindByDir(KSettingsName, KCaBundleDir) == KErrNone
		&& f.Open(fs, find.File(), EFileRead | EFileShareReadersOnly) == KErrNone)
		{
		TInt size = 0;
		RBuf8 text;
		if (f.Size(size) == KErrNone && size > 0 && size <= 4096 && text.Create(size) == KErrNone)
			{
			if (f.Read(text) == KErrNone)
				phtls_conf_parse(&aConf, reinterpret_cast<const char*>(text.Ptr()), (size_t)text.Length());
			text.Close();
			}
		f.Close();
		}
	fs.Close();
	}

// The trust anchors, parsed once per process and shared (read-only) by every connection. The chain stays alive while
// any connection uses it and, pinned, for the life of the process (the next connection must not parse ~140
// certificates again); UnloadDll drops the pin.
static mbedtls_x509_crt* gCa;
static TInt gCaRefs;
static TInt gCaPinned;
static TInt gCaLock;

// The CA bundle (PEM): read with the file server (no libc stdio in the client's process needed), NUL-terminated
// for mbedtls_x509_crt_parse. A certificate mbedTLS cannot parse is skipped (parse returns the count of failures).
static mbedtls_x509_crt* ParseTrustAnchorsL()
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
	mbedtls_x509_crt* crt = static_cast<mbedtls_x509_crt*>(calloc(1, sizeof(mbedtls_x509_crt)));
	if (crt)
		{
		mbedtls_x509_crt_init(crt);
		int rc = mbedtls_x509_crt_parse(crt, pem.Ptr(), (size_t)pem.Length());
#ifdef PHOREPOC_SSL_TRACE
		TInt n = 0;
		for (const mbedtls_x509_crt* c = crt; c && c->raw.p; c = c->next)
			++n;
		TLSLOG("[ssl] %d trust anchors (%d skipped)", n, rc);
#endif
		(void)rc;
		}
	CleanupStack::PopAndDestroy(3, &fs);
	if (!crt)
		User::Leave(KErrNoMemory);
	if (!crt->raw.p)
		{
		free(crt);
		User::Leave(KErrNotFound);
		}
	return crt;
	}

static void FreeChain(mbedtls_x509_crt* aCrt)
	{
	if (aCrt)
		{
		mbedtls_x509_crt_free(aCrt);
		free(aCrt);
		}
	}

static const mbedtls_x509_crt* AcquireTrustAnchorsL()
	{
	SpinLock(gCaLock);
	mbedtls_x509_crt* ca = gCa;
	if (ca)
		++gCaRefs;
	SpinUnlock(gCaLock);
	if (ca)
		return ca;
	mbedtls_x509_crt* fresh = ParseTrustAnchorsL();
	SpinLock(gCaLock);
	if (gCa)								// another thread was faster: use its chain
		{
		ca = gCa;
		++gCaRefs;
		}
	else
		{
		ca = gCa = fresh;
		fresh = NULL;
		gCaRefs = 2;						// the pin + this connection
		gCaPinned = 1;
		}
	SpinUnlock(gCaLock);
	FreeChain(fresh);
	return ca;
	}

static void ReleaseTrustAnchors()
	{
	mbedtls_x509_crt* dead = NULL;
	SpinLock(gCaLock);
	if (gCa && --gCaRefs == 0)
		{
		dead = gCa;
		gCa = NULL;
		}
	SpinUnlock(gCaLock);
	FreeChain(dead);
	}

static void UnpinTrustAnchors()
	{
	SpinLock(gCaLock);
	TInt pinned = gCaPinned;
	gCaPinned = 0;
	SpinUnlock(gCaLock);
	if (pinned)
		ReleaseTrustAnchors();
	}

// The session cache (tls_sesscache.h): in memory per process, and a file in the process's private data so a restart
// resumes too. Written to a temporary file and renamed over the old one (RFs::Replace is atomic): a crash or a power
// cut leaves the old file or the new one, never half of one; a damaged file is ignored (CRC).
static phsc gSess;
static TInt gSessLock;
static TInt gSessLoaded;
_LIT(KSessFile, "phtls_sess.dat");
_LIT(KSessTmp, "phtls_sess.tmp");
static const TInt KSessFileMax = 512 * 1024;

static TUint64 NowSeconds()
	{
	TTime now;
	now.UniversalTime();
	const TTime epoch(TDateTime(1970, EJanuary, 0, 0, 0, 0, 0));
	return static_cast<TUint64>(now.MicroSecondsFrom(epoch).Int64() / 1000000);
	}

// the process's private directory on C: (created if needed); the names go after the session path
static TBool OpenPrivate(RFs& aFs, TFileName& aDir)
	{
	if (aFs.Connect() != KErrNone)
		return EFalse;
	aFs.CreatePrivatePath(EDriveC);
	if (aFs.SetSessionToPrivate(EDriveC) != KErrNone || aFs.SessionPath(aDir) != KErrNone)
		{
		aFs.Close();
		return EFalse;
		}
	return ETrue;
	}

static void SessionsLoadOnce(TBool aPersist)
	{
	SpinLock(gSessLock);
	TInt first = !gSessLoaded;
	gSessLoaded = 1;
	SpinUnlock(gSessLock);
	if (!first || !aPersist)
		return;
	RFs fs;
	TFileName path;
	if (!OpenPrivate(fs, path))
		return;
	path.Append(KSessFile);
	RFile f;
	TInt size = 0;
	if (f.Open(fs, path, EFileRead | EFileShareReadersOnly) == KErrNone)
		{
		RBuf8 img;
		if (f.Size(size) == KErrNone && size > 0 && size <= KSessFileMax && img.Create(size) == KErrNone)
			{
			if (f.Read(img) == KErrNone)
				{
				SpinLock(gSessLock);
				phsc_deserialize(&gSess, img.Ptr(), (size_t)img.Length(), NowSeconds());
				SpinUnlock(gSessLock);
				}
			img.Close();
			}
		f.Close();
		}
	fs.Close();
	}

static void SessionsSave()
	{
	const TUint64 now = NowSeconds();
	SpinLock(gSessLock);
	size_t need = phsc_serialize(&gSess, now, NULL, 0);
	unsigned char* img = need ? static_cast<unsigned char*>(malloc(need)) : NULL;
	if (img)
		need = phsc_serialize(&gSess, now, img, need);
	SpinUnlock(gSessLock);
	RFs fs;
	TFileName dir;
	if (!OpenPrivate(fs, dir))
		{
		free(img);
		return;
		}
	TFileName path(dir), tmp(dir);
	path.Append(KSessFile);
	tmp.Append(KSessTmp);
	if (need == 0)
		fs.Delete(path);					// nothing worth keeping
	else if (img)
		{
		RFile f;
		TInt err = f.Replace(fs, tmp, EFileWrite);
		if (err == KErrNone)
			{
			err = f.Write(TPtrC8(img, (TInt)need));
			if (err == KErrNone)
				err = f.Flush();
			f.Close();
			}
		if (err == KErrNone)
			err = fs.Replace(tmp, path);
		if (err != KErrNone)
			fs.Delete(tmp);
		}
	fs.Close();
	free(img);
	}

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
	void FlushSessionCache();
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
	static int VerifyCb(void* aCtx, mbedtls_x509_crt* aCrt, int aDepth, uint32_t* aFlags);
	TUint SessionPort();
	void TryResume();
	void CacheSession();
	void ForgetSession();
	const mbedtls_x509_crt* PeerCert();
	TPtrC8 UiCertDer(const mbedtls_x509_crt& aPeer);
	CX509Certificate* NewDisplayCert(const mbedtls_x509_crt& aPeer);
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
	const mbedtls_x509_crt* iCa;	// the process-wide trust anchors (refcounted, see AcquireTrustAnchorsL)
	phtls_conf iSettings;			// ssl.ini, read when the connection was made
	TBool iSessionOffered;			// a cached session went into the ClientHello
	TBool iFullVerify;				// the certificate chain was verified in this handshake: not a resumption
	TBuf8<64> iAlpn;				// KPhSoAlpn, comma separated
	char iAlpnZ[64];				// ... NUL separated, what mbedTLS points at
	const char* iAlpnList[9];
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
	TBool iUiCertTried;
	HBufC8* iUiCertDer;				// the display certificate's DER, when the platform cannot parse the real one
	HBufC8* iResumedCert;			// the cached session's server certificate (DER)
	mbedtls_x509_crt iResumedCrt;	// ... parsed, on demand
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
	UnpinTrustAnchors();		// the shared trust anchors go once the last connection is gone
	}

// Forget every cached session (memory and file): a client asking for a clean slate.
void CTlsConnection::FlushSessionCache()
	{
	TLSLOG("[ssl] FlushSessionCache");
	SpinLock(gSessLock);
	phsc_clear(&gSess);
	SpinUnlock(gSessLock);
	if (iSettings.session_persist)
		SessionsSave();			// (an empty cache removes the file)
	}

CTlsConnection::CTlsConnection(RSocket* aSocket, MGenericSecureSocket* aGeneric)
	: iSocket(aSocket), iGeneric(aGeneric), iDialogMode(EDialogModeAttended), iRecvView(NULL, 0)
	{
	mbedtls_ssl_init(&iSsl);
	mbedtls_ssl_config_init(&iConf);
	mbedtls_ctr_drbg_init(&iDrbg);
	mbedtls_entropy_init(&iEntropy);
	phtls_conf_defaults(&iSettings);
	mbedtls_x509_crt_init(&iResumedCrt);
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
	ReadSettings(iSettings);
	mbedtls_ssl_conf_min_tls_version(&iConf, MBEDTLS_SSL_VERSION_TLS1_2);
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
	// ssl.ini "tls13 = 0": the kill switch for servers / middleboxes that break TLS 1.3 (default: on)
	mbedtls_ssl_conf_max_tls_version(&iConf, iSettings.tls13 ? MBEDTLS_SSL_VERSION_TLS1_3 : MBEDTLS_SSL_VERSION_TLS1_2);
#else
	mbedtls_ssl_conf_max_tls_version(&iConf, MBEDTLS_SSL_VERSION_TLS1_2);
#endif
	mbedtls_ssl_conf_rng(&iConf, mbedtls_ctr_drbg_random, &iDrbg);
	TLSLOG("[ssl] %08x rng seeded (tls13 %d, session cache %d), loading trust anchors", this, iSettings.tls13, iSettings.session_cache);
	iCa = AcquireTrustAnchorsL();
	mbedtls_ssl_conf_ca_chain(&iConf, const_cast<mbedtls_x509_crt*>(iCa), NULL);
	mbedtls_ssl_conf_verify(&iConf, &CTlsConnection::VerifyCb, this);
#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(MBEDTLS_SSL_SESSION_TICKETS)
	// a TLS 1.3 ticket arrives after the handshake: have mbedTLS report it from the read, where CacheSession stores it
	mbedtls_ssl_conf_tls13_enable_signal_new_session_tickets(&iConf, MBEDTLS_SSL_TLS1_3_SIGNAL_NEW_SESSION_TICKETS_ENABLED);
#endif
	// OPTIONAL: a certificate that fails verification ends the handshake here, not in mbedTLS -- attended mode then
	// asks the user as the 2010 TLS provider does (Progress), unattended mode refuses it
	mbedtls_ssl_conf_authmode(&iConf, MBEDTLS_SSL_VERIFY_OPTIONAL);
	if (mbedtls_ssl_setup(&iSsl, &iConf))
		User::Leave(KErrNoMemory);
	mbedtls_ssl_set_bio(&iSsl, this, &CTlsConnection::BioSend, &CTlsConnection::BioRecv, NULL);
	TLSLOG("[ssl] %08x constructed", this);
	}

CTlsConnection::~CTlsConnection()
	{
	TLSLOG("[ssl] %08x destroyed", this);
	delete iDialogAo;
	delete iSender;
	delete iReceiver;
	delete iServerCert;
	delete iUiCertDer;
	delete iResumedCert;
	mbedtls_x509_crt_free(&iResumedCrt);
	mbedtls_ssl_free(&iSsl);
	mbedtls_ssl_config_free(&iConf);
	mbedtls_ctr_drbg_free(&iDrbg);
	mbedtls_entropy_free(&iEntropy);
	if (iCa)
		ReleaseTrustAnchors();
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

// ---- session resumption -----------------------------------------------------------------------------------------
// mbedTLS calls this for each certificate it verifies, i.e. only in a full handshake (a resumed session sends none):
// that is how a connection knows whether it resumed. It never changes the verdict.
int CTlsConnection::VerifyCb(void* aCtx, mbedtls_x509_crt*, int, uint32_t*)
	{
	static_cast<CTlsConnection*>(aCtx)->iFullVerify = ETrue;
	return 0;
	}

// the cache is keyed by host and port: a transport that cannot say which port it is connected to is taken as 443
TUint CTlsConnection::SessionPort()
	{
	if (iSocket)
		{
		TSockAddr addr;
		iSocket->RemoteName(addr);
		if (addr.Port())
			return addr.Port();
		}
	return 443;
	}

// Before the handshake: offer the cached session for this host and port, if there is one.
void CTlsConnection::TryResume()
	{
	if (!iSettings.session_cache || iHost.Length() == 0)
		return;
	TBuf8<256> host(iHost);
	const char* name = (const char*)host.PtrZ();
	const TUint port = SessionPort();
	SessionsLoadOnce(iSettings.session_persist);
	size_t len = 0;
	unsigned char flags = 0;
	SpinLock(gSessLock);
	unsigned char* blob = phsc_take(&gSess, name, port, NowSeconds(), &len, &flags);
	SpinUnlock(gSessLock);
	if (!blob)
		return;
	unsigned char* cert = NULL;
	size_t certLen = 0;
	if (phtls_session_import(&iSsl, blob, len, &cert, &certLen) == 0)
		{
		iSessionOffered = ETrue;
		if (cert && certLen)
			{
			iResumedCert = HBufC8::New((TInt)certLen);		// (best effort: only ServerCert() wants it)
			if (iResumedCert)
				iResumedCert->Des().Copy(cert, (TInt)certLen);
			}
		}
	else
		{
		// damaged or from another mbedTLS: do not offer it again
		SpinLock(gSessLock);
		phsc_remove(&gSess, name, port);
		SpinUnlock(gSessLock);
		}
	free(blob);
	free(cert);
	TLSLOG("[ssl] %08x session %s", this, iSessionOffered ? "offered" : "import failed");
	}

// The server certificate: from the handshake, or -- on a resumed connection, which has no Certificate message (and a
// TLS 1.3 session image carries none) -- the one the cached session was established with.
const mbedtls_x509_crt* CTlsConnection::PeerCert()
	{
	const mbedtls_x509_crt* peer = mbedtls_ssl_get_peer_cert(&iSsl);
	if (peer || !iResumedCert || !iConnected || !iSessionOffered || iFullVerify)
		return peer;
	if (!iResumedCrt.raw.p
		&& mbedtls_x509_crt_parse_der(&iResumedCrt, iResumedCert->Ptr(), (size_t)iResumedCert->Length()) != 0)
		{
		mbedtls_x509_crt_free(&iResumedCrt);
		mbedtls_x509_crt_init(&iResumedCrt);
		}
	return iResumedCrt.raw.p ? &iResumedCrt : NULL;
	}

// After a clean handshake (TLS 1.2) or when a ticket arrives (TLS 1.3): remember the session.
void CTlsConnection::CacheSession()
	{
	if (!iSettings.session_cache || iHost.Length() == 0 || !iConnected)
		return;
	unsigned char* blob = NULL;
	size_t len = 0;
	unsigned char flags = 0;
	uint32_t lifetime = 0;
	if (phtls_session_export(&iSsl, &blob, &len, &flags, &lifetime) != 0)
		return;
	TBuf8<256> host(iHost);
	SpinLock(gSessLock);
	phsc_put(&gSess, (const char*)host.PtrZ(), SessionPort(), blob, len, flags, NowSeconds(), lifetime);
	SpinUnlock(gSessLock);
	free(blob);
	if (iSettings.session_persist)
		SessionsSave();
	TLSLOG("[ssl] %08x session cached (%d bytes, lifetime %d)", this, (TInt)len, (TInt)lifetime);
	}

// A handshake that failed with a cached session in it: drop the entry (a server that now refuses it outright).
void CTlsConnection::ForgetSession()
	{
	if (!iSessionOffered)
		return;
	iSessionOffered = EFalse;
	TBuf8<256> host(iHost);
	SpinLock(gSessLock);
	phsc_remove(&gSess, (const char*)host.PtrZ(), SessionPort());
	SpinUnlock(gSessLock);
	}

// ---- certificates for the platform's UI -------------------------------------------------------------------------
// The platform's X.509 parser (x509.dll) predates today's certificates (new curves, RSA-PSS keys ...), and the
// security dialog / page info built on it can crash on what it cannot parse. If it cannot parse the server
// certificate, hand out a display copy instead (tls_stubcert.h): same subject, issuer, serial and validity, a
// placeholder key. mbedTLS has already verified the real certificate.
CX509Certificate* CTlsConnection::NewDisplayCert(const mbedtls_x509_crt& aPeer)
	{
	for (TInt style = PHSTUB_FULL_NAMES; style <= PHSTUB_SIMPLE_NAMES; ++style)
		{
		unsigned char* der = NULL;
		size_t n = phstub_build(&aPeer, style, &der);
		if (!n)
			continue;
		CX509Certificate* cert = NULL;
		TRAPD(err, cert = CX509Certificate::NewL(TPtrC8(der, (TInt)n)));
		if (err == KErrNone && cert)
			{
			delete iUiCertDer;
			iUiCertDer = HBufC8::New((TInt)n);
			if (iUiCertDer)
				iUiCertDer->Des().Copy(der, (TInt)n);
			free(der);
			TLSLOG("[ssl] %08x display certificate (style %d, %d bytes)", this, style, (TInt)n);
			return cert;
			}
		free(der);
		}
	return NULL;
	}

// The DER the certificate dialog is given: the real certificate, or the display copy if the platform cannot parse
// the real one.
TPtrC8 CTlsConnection::UiCertDer(const mbedtls_x509_crt& aPeer)
	{
	TPtrC8 real(aPeer.raw.p, (TInt)aPeer.raw.len);
	if (!iUiCertTried)
		{
		iUiCertTried = ETrue;
		if (!iServerCert)
			{
			TRAPD(err, iServerCert = CX509Certificate::NewL(real));
			if (err != KErrNone)
				{
				iServerCert = NULL;
				iServerCert = NewDisplayCert(aPeer);		// (also fills iUiCertDer)
				}
			}
		}
	return iUiCertDer ? TPtrC8(*iUiCertDer) : real;
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
		const TBool resumed = iSessionOffered && !iFullVerify;		// (nothing to verify: the session was verified when it was made)
		const uint32_t flags = (rc == 0 && !resumed) ? mbedtls_ssl_get_verify_result(&iSsl) : 0;
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
				TRAP(err, StartDialogL(flags, UiCertDer(*peer)));
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
			TLSLOG("[ssl] handshake done: %s %s%s", mbedtls_ssl_get_version(&iSsl), mbedtls_ssl_get_ciphersuite(&iSsl),
				   iSessionOffered && !iFullVerify ? " (resumed)" : "");
			// TLS 1.2: the session (ticket / id) exists now; TLS 1.3: it arrives as a ticket in the first read
			if (mbedtls_ssl_get_version_number(&iSsl) == MBEDTLS_SSL_VERSION_TLS1_2)
				CacheSession();
			if (iOut.Length() == 0)
				Complete(iHandshake, KErrNone);
			}
		else if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE)
			needRecv = rc == MBEDTLS_ERR_SSL_WANT_READ;
		else
			{
			TLSLOG("[ssl] handshake failed: -0x%04x", -rc);
			ForgetSession();
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
		TInt wantRetries = 0;
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
				// mbedTLS answers WANT_READ once after it consumed a post-handshake message (a TLS 1.3 ticket) even with
				// the next record already queued: ask again rather than wait for bytes that are already here
				if (iInPos < iIn.Length() && ++wantRetries <= 4)
					continue;
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
				{
				CacheSession();			// a resumption ticket for the next connection to this host
				continue;
				}
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
	if (iAlpn.Length())
		mbedtls_ssl_conf_alpn_protocols(&iConf, iAlpnList);
	TryResume();
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
	const mbedtls_x509_crt* peer = PeerCert();
	if (!peer)
		return NULL;
	TPtrC8 der(peer->raw.p, (TInt)peer->raw.len);
	TRAPD(err, iServerCert = CX509Certificate::NewL(der));
	TLSLOG("[ssl] %08x ServerCert: %d bytes DER -> x509 err %d", this, der.Length(), err);
	if (err != KErrNone)
		{
		// the platform cannot parse this (modern) certificate: a display copy, never NULL for the UI to trip over
		iServerCert = NULL;
		iUiCertTried = ETrue;
		iServerCert = NewDisplayCert(*peer);
		}
	return iServerCert;
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
	if (aOptionLevel == KSolInetSSL && aOptionName == KPhSoSessionResumed)
		{
		aOption = (iConnected && iSessionOffered && !iFullVerify) ? 1 : 0;
		return KErrNone;
		}
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
	if (aOptionLevel == KSolInetSSL && aOptionName == KPhSoAlpn)
		{
		const char* proto = iConnected ? mbedtls_ssl_get_alpn_protocol(&iSsl) : NULL;
		aOption.Zero();
		if (proto)
			aOption.Copy(TPtrC8(reinterpret_cast<const TUint8*>(proto), (TInt)strlen(proto)).Left(aOption.MaxLength()));
		return KErrNone;
		}
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
	case KPhSoAlpn:
		{
		// "h2,http/1.1": at most 8 names, 63 bytes in all (mbedTLS keeps pointers into iAlpnZ)
		if (iConnected || iHandshake || aOption.Length() >= (TInt)sizeof(iAlpnZ))
			return KErrArgument;
		TInt n = 0, count = 0;
		TBool start = ETrue;
		for (TInt i = 0; i < aOption.Length(); ++i)
			{
			const TUint8 c = aOption[i];
			if (c == ',')
				{
				if (start || count == 8)
					return KErrArgument;
				iAlpnZ[n++] = 0;
				start = ETrue;
				continue;
				}
			if (start)
				{
				if (count == 8)
					return KErrArgument;
				iAlpnList[count++] = &iAlpnZ[n];
				start = EFalse;
				}
			iAlpnZ[n++] = (char)c;
			}
		if (start && aOption.Length())
			return KErrArgument;		// empty name
		iAlpnZ[n] = 0;
		iAlpnList[count] = NULL;
		iAlpn.Copy(aOption.Left(iAlpn.MaxLength()));
		return KErrNone;
		}
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
