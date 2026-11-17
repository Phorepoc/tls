// Copyright The Phorepoc Authors
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-Phorepoc-Build-Output-Exception-1.0

// tlsconnection_openssl.cpp -- the same SSL.DLL drop-in as tlsconnection_mbed.cpp, with OpenSSL 3.5 (static
// libssl.a + libcrypto.a, recipes/build_openssl.sh) as the TLS engine instead of mbedTLS. Everything above the engine
// (the two transport AOs, the three client ops, the dialog, the MSecureSocket surface) is the mbedTLS file's; the
// engine calls are SSL_* over a pair of memory BIOs (ciphertext in, ciphertext out; OpenSSL never touches the socket).
// Build it with ssl_openssl.mmp (ENGINE=openssl, registry/components_tls.py). Notes against the mbedTLS engine:
//  - a failed certificate chain does not fail the handshake (SSL_VERIFY_NONE records SSL_get_verify_result), so the
//    attended/unattended handling after the handshake is unchanged; the codes are X509_V_ERR_* instead of mbedTLS flags;
//  - entropy: the kernel RNG through a seed callback (seed_symbian.c: a seed-source provider);
//  - OpenSSL is built without threads: the library state is per process, TLS connections of one process must be
//    created and driven from one thread (the usual one: the active scheduler's).
//
// Original header of the mbedTLS file:
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

// OpenSSL 3 headers (thirdparty/<arch>/include/openssl3, ahead of Open C's 0.9.8 <openssl/...>)
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

#include <stdlib.h>
#include <string.h>
#include "tls_conf.h"
#include "tls_sesscache.h"		// the engine-neutral container (PHSC_NO_MBEDTLS): i2d_SSL_SESSION blobs by host:port

extern "C" int phorepoc_openssl_seed_init(void);		// seed_symbian.c


_LIT(KCaBundleName, "ca-bundle.crt");
_LIT(KSettingsName, "ssl.ini");
_LIT(KCaBundleDir, "\\resource\\ssl\\");
static const TInt KRecvScratch = 16 * 1024 + 512;	// one TLS record + header

// Phorepoc options on the KSolInetSSL level (as in the mbedTLS engine; no stock client uses them):
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
// A plain spin lock: the critical sections are short (an engine call on in-memory buffers never waits for the network or
// the user: a handshake step returns WANT_READ).
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

// A thread's own heap dies with the thread, and this OpenSSL keeps process-wide state (its library context, provider and
// algorithm caches, the error queue, the trust anchors, the session cache) that outlives any connection and is made by
// whichever thread needs it first: a program that fetches on short-lived worker threads (Catalogue's index refresh and
// icon downloads, one thread each) kept pointers into the heap of a thread that had ended. So every call into OpenSSL
// runs with the calling thread switched to one process-wide heap (multi-thread safe, created on first use, never
// closed): everything OpenSSL allocates or frees is on it, whichever thread does it. A scope never contains a Leave.
static RHeap* gSharedHeap;
static TInt gSharedHeapLock;

static RHeap* EnterShared()
	{
	SpinLock(gSharedHeapLock);
	if (!gSharedHeap)
		gSharedHeap = UserHeap::ChunkHeap(NULL, 0x8000, 0x1000000, 0x4000);	// (NULL on failure: the thread's own heap then)
	SpinUnlock(gSharedHeapLock);
	return gSharedHeap ? User::SwitchHeap(gSharedHeap) : NULL;
	}

class TSharedHeap
	{
public:
	TSharedHeap() : iOld(EnterShared()) {}
	~TSharedHeap() { if (iOld) User::SwitchHeap(iOld); }
private:
	RHeap* iOld;
	};


// OpenSSL here is built without threads (recipes/openssl_options.sh: no locks, one error queue), so one thread at a time
// is in it. TEngine = that exclusion (taken again by the thread that holds it: the session callback runs inside a
// handshake) + the shared heap. The parallel-handshake capacity of the mbedTLS engine's fixed PSA key slots does not
// exist here: a connection is heap, the heap is 16 MB, and handshakes of several threads take turns.
static TInt gEngLock;
static TUint64 gEngOwner;
static TInt gEngDepth;

class TEngine
	{
public:
	TEngine() : iOuter(EFalse), iOld(NULL)
		{
		TUint64 me = RThread().Id().Id();
		if (gEngDepth > 0 && gEngOwner == me)
			{
			++gEngDepth;
			return;
			}
		SpinLock(gEngLock);
		gEngOwner = me;
		gEngDepth = 1;
		iOuter = ETrue;
		iOld = EnterShared();
		}
	~TEngine()
		{
		if (!iOuter)
			{
			--gEngDepth;
			return;
			}
		if (iOld)
			User::SwitchHeap(iOld);
		gEngOwner = 0;
		gEngDepth = 0;
		SpinUnlock(gEngLock);
		}
private:
	TBool iOuter;
	RHeap* iOld;
	};

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

// The trust anchors: one X509_STORE per process, parsed once on the shared heap and shared (read-only) by every
// connection's SSL_CTX (SSL_CTX_set1_cert_store). The process's own reference is never dropped: it lives as long as the
// process (the next connection must not parse ~140 certificates again).
static X509_STORE* gStore;
static TInt gStoreLock;

// The CA bundle (PEM): read with the file server (no libc stdio in the client's process needed), NUL-terminated.
// A certificate that does not parse is skipped.
static X509_STORE* AcquireTrustAnchorsL()
	{
	SpinLock(gStoreLock);
	X509_STORE* have = gStore;
	SpinUnlock(gStoreLock);
	if (have)
		return have;
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
	// PEM -> X509_STORE
	X509_STORE* fresh = NULL;
	TInt n = 0;
		{
		TEngine engine;
		fresh = X509_STORE_new();
		BIO* in = BIO_new_mem_buf(pem.Ptr(), pem.Length() - 1);
		if (in && fresh)
			{
			X509* cert;
			while ((cert = PEM_read_bio_X509(in, NULL, NULL, NULL)) != NULL)
				{
				if (X509_STORE_add_cert(fresh, cert))
					++n;
				X509_free(cert);
				}
			ERR_clear_error();			// (the end of the file is an "error" to the PEM reader)
			}
		BIO_free(in);
		}
	TLSLOG("[ssl] %d trust anchors", n);
	CleanupStack::PopAndDestroy(3, &fs);
	if (n == 0)
		{
		if (fresh)
			{
			TEngine engine;
			X509_STORE_free(fresh);
			}
		User::Leave(KErrNotFound);
		}
	SpinLock(gStoreLock);
	X509_STORE* dead = NULL;
	if (gStore)							// another thread was faster: use its store
		dead = fresh;
	else
		gStore = fresh;
	have = gStore;
	SpinUnlock(gStoreLock);
	if (dead)
		{
		TEngine engine;
		X509_STORE_free(dead);
		}
	return have;
	}

// The session cache (tls_sesscache.h; the container is the mbedTLS engine's): in memory per process, and a file in the
// process's private data so a restart resumes too. An entry is an i2d_SSL_SESSION image (it carries the server's
// certificate chain, so a resumed connection still has a peer certificate for the UI). Written to a temporary file and
// renamed over the old one (RFs::Replace is atomic); a damaged file is ignored (CRC).
static phsc gSess;
static TInt gSessLock;
static TInt gSessLoaded;
_LIT(KSessFile, "phtls_ossl_sess.dat");		// (not the mbedTLS engine's file: the images are not interchangeable)
_LIT(KSessTmp, "phtls_ossl_sess.tmp");
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
				{ TSharedHeap shared; phsc_deserialize(&gSess, img.Ptr(), (size_t)img.Length(), NowSeconds()); }
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
	size_t need;
	unsigned char* img;
	SpinLock(gSessLock);
		{
		TSharedHeap shared;
		need = phsc_serialize(&gSess, now, NULL, 0);
		img = need ? static_cast<unsigned char*>(malloc(need)) : NULL;
		if (img)
			need = phsc_serialize(&gSess, now, img, need);
		}
	SpinUnlock(gSessLock);
	RFs fs;
	TFileName dir;
	if (!OpenPrivate(fs, dir))
		{
		TSharedHeap shared;
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
	TSharedHeap shared;
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
	static int NewSessionCb(SSL* aSsl, SSL_SESSION* aSess);
	int CacheSession(SSL_SESSION* aSess);		// (inside an engine call)
	TUint SessionPort();
	TUint iPort;					// the remote port, for the session cache (asked outside the engine scope)
	void TryResume();
	void ForgetSession();
	TInt EngErr(int aRc);				// (inside the engine call's TEngine scope) classify aRc; remembers iLastErr, iVerifyRes
	static void Fail(TRequestStatus& aStatus, TInt aErr);
	void StartWrite(const TDesC8& aDesc, TRequestStatus& aStatus, TSockXfrLength* aLen);
	void StartRead(TDes8& aDesc, TRequestStatus& aStatus, TSockXfrLength* aLen, TBool aFill);

	// the engine
	void Progress();
	void Flush();
	void ArmRecv();
	void Complete(TRequestStatus*& aCaller, TInt aCode);
	void FailAll(TInt aErr);
	TInt MapErr(int aSslError);
	TInt MapVerify(TUint32 aVerifyErr);
	TBool PeerCertAccepted(TBool aRemember);
	void StartDialogL(TUint32 aVerifyErr, const TDesC8& aCert);
	void RefusePeerCert(TInt aErr);
	void DrainOut();					// the memory BIO's ciphertext -> iOut
	void FeedIn();						// received ciphertext -> the memory BIO
	TInt PeerDer(RBuf8& aDer);			// the leaf certificate, DER
	TInt TlsCall(int aSslError);		// the ciphertext the call produced -> iOut; returns aSslError

	// the transport: an RSocket (ordinal 1) or a socket-like object (ordinal 3)
	RSocket* iSocket;
	MGenericSecureSocket* iGeneric;

	SSL_CTX* iCtx;
	SSL* iSsl;
	BIO* iRbio;						// ciphertext from the peer (we write, SSL reads)
	BIO* iWbio;						// ciphertext for the peer (SSL writes, we drain into iOut)
	TInt iRecHave;					// record framing of what was fed (for the generic transport's exact-length reads)
	TInt iRecNeed;
	TUint8 iRecHdr[5];
	TBool iConnected;
	TBool iClosed;
	TInt iFatal;					// sticky transport / protocol error
	TDialogMode iDialogMode;
	TBool iVerifyPending;			// the handshake is done but the certificate awaits the user's answer
	TBuf8<256> iHost;				// KSoSSLDomainName (SNI, name check, the dialog)
	phtls_conf iSettings;			// ssl.ini, read when the connection was made
	TBool iSessionOffered;			// a cached session went into the ClientHello
	TBool iSessionDirty;			// a session was cached: the file wants writing
	TBuf8<64> iAlpn;				// KPhSoAlpn, comma separated
	TBuf8<80> iAlpnWire;			// ... length-prefixed, as OpenSSL wants it
	unsigned long iLastErr;			// the OpenSSL error of the last failed call (taken inside its scope)
	TInt iVerifyRes;				// SSL_get_verify_result at that time
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
	// (the shared trust store and the process-wide heap stay for the life of the process: a connection's SSL_CTX holds
	// the store, and freeing it from whichever thread unloads the DLL would be a free on the wrong heap)
	}

// Forget every cached session (memory and file): a client asking for a clean slate.
void CTlsConnection::FlushSessionCache()
	{
	TLSLOG("[ssl] FlushSessionCache");
	SpinLock(gSessLock);
	{ TSharedHeap shared; phsc_clear(&gSess); }
	SpinUnlock(gSessLock);
	if (iSettings.session_persist)
		SessionsSave();			// (an empty cache removes the file)
	}

CTlsConnection::CTlsConnection(RSocket* aSocket, MGenericSecureSocket* aGeneric)
	: iSocket(aSocket), iGeneric(aGeneric), iDialogMode(EDialogModeAttended), iRecvView(NULL, 0)
	{
	phtls_conf_defaults(&iSettings);
	iPort = 443;
	}

void CTlsConnection::ConstructL()
	{
	iOut.CreateL(2048);
	iSending.CreateL(2048);
	iIn.CreateL(16);			// (unused by this engine: the read BIO queues)
	iRecvBuf.CreateL(KRecvScratch);
	iSender = new(ELeave) CTlsIo(*this, ETrue);
	iReceiver = new(ELeave) CTlsIo(*this, EFalse);
	ReadSettings(iSettings);

	// the library: the seed source on the kernel RNG, once per process (repeat calls return at once)
	TInt seeded;
		{
		TEngine engine;
		seeded = phorepoc_openssl_seed_init();
		}
	if (!seeded)
		User::Leave(KErrGeneral);
	TLSLOG("[ssl] %08x seed source ready (tls13 %d, session cache %d), loading trust anchors", this, iSettings.tls13, iSettings.session_cache);
	X509_STORE* store = AcquireTrustAnchorsL();
	TInt err = KErrNone;
		{
		TEngine engine;				// (no Leave inside: a Leave does not run destructors)
		iCtx = SSL_CTX_new(TLS_client_method());
		if (!iCtx)
			err = KErrNoMemory;
		else
			{
			SSL_CTX_set_min_proto_version(iCtx, TLS1_2_VERSION);
			// ssl.ini "tls13 = 0": the kill switch for servers / middleboxes that break TLS 1.3 (default: on)
			SSL_CTX_set_max_proto_version(iCtx, iSettings.tls13 ? TLS1_3_VERSION : TLS1_2_VERSION);
			// forward-secret AEAD suites only (no CBC, no static RSA, SSL Labs: WEAK); TLS 1.3's three are the library default
			SSL_CTX_set_cipher_list(iCtx, "ECDHE+AESGCM:ECDHE+CHACHA20");
			// signature algorithms without SHA-224 (SHA-1 is not in the default list)
			SSL_CTX_set1_sigalgs_list(iCtx, "ed25519:ed448:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:rsa_pss_pss_sha256:rsa_pss_pss_sha384:rsa_pss_pss_sha512:RSA+SHA256:RSA+SHA384:RSA+SHA512");
			// sessions: the process-wide cache (tls_sesscache.h) through the new-session callback, not OpenSSL's own store
			SSL_CTX_set_session_cache_mode(iCtx, iSettings.session_cache ? (SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE) : SSL_SESS_CACHE_OFF);
			SSL_CTX_sess_set_new_cb(iCtx, &CTlsConnection::NewSessionCb);
			SSL_CTX_set_options(iCtx, SSL_OP_NO_RENEGOTIATION | SSL_OP_IGNORE_UNEXPECTED_EOF);
			// OpenSSL, like mbedTLS in OPTIONAL mode: the handshake completes with an untrusted chain and the result is read
			// afterwards (SSL_get_verify_result) -- attended mode then asks the user as the 2010 TLS provider does
			// (Progress), unattended mode refuses it
			SSL_CTX_set_verify(iCtx, SSL_VERIFY_NONE, NULL);
			SSL_CTX_set1_cert_store(iCtx, store);		// (the process-wide trust anchors, +1 reference)
			iSsl = SSL_new(iCtx);
			iRbio = BIO_new(BIO_s_mem());
			iWbio = BIO_new(BIO_s_mem());
			if (!iSsl || !iRbio || !iWbio)
				{
				BIO_free(iRbio);			// (SSL_set_bio takes them over once it has them)
				BIO_free(iWbio);
				iRbio = iWbio = NULL;
				err = KErrNoMemory;
				}
			else
				{
				BIO_set_mem_eof_return(iRbio, -1);	// empty = retry (WANT_READ); iClosed switches it to 0 = EOF
				SSL_set_bio(iSsl, iRbio, iWbio);
				SSL_set_connect_state(iSsl);
				SSL_set_app_data(iSsl, this);		// (the new-session callback finds its connection)
				}
			}
		}
	User::LeaveIfError(err);
	iRecNeed = 5;
	iWant = 5;
	TLSLOG("[ssl] %08x constructed", this);
	}

CTlsConnection::~CTlsConnection()
	{
	TLSLOG("[ssl] %08x destroyed", this);
	delete iDialogAo;
	delete iSender;
	delete iReceiver;
	delete iServerCert;
		{
		TEngine engine;
		SSL_free(iSsl);					// (frees the BIOs it holds)
		SSL_CTX_free(iCtx);
		ERR_clear_error();
		}
	iOut.Close();
	iSending.Close();
	iIn.Close();
	iRecvBuf.Close();
	}

// ---- session resumption -----------------------------------------------------------------------------------------
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

// OpenSSL calls this (inside SSL_do_handshake / SSL_read: a TLS 1.3 ticket arrives after the handshake) for each new
// session; it never takes the reference (return 0).
int CTlsConnection::NewSessionCb(SSL* aSsl, SSL_SESSION* aSess)
	{
	CTlsConnection* self = static_cast<CTlsConnection*>(SSL_get_app_data(aSsl));
	return self ? self->CacheSession(aSess) : 0;
	}

int CTlsConnection::CacheSession(SSL_SESSION* aSess)
	{
	// not a session whose certificate the user had to accept: that one is never resumed silently
	if (!iSettings.session_cache || iHost.Length() == 0 || SSL_get_verify_result(iSsl) != X509_V_OK)
		return 0;
	const int len = i2d_SSL_SESSION(aSess, NULL);
	if (len <= 0 || (unsigned)len > PHSC_MAX_BLOB)
		return 0;
	unsigned char* blob = static_cast<unsigned char*>(malloc((size_t)len));		// (the shared heap: we are inside TEngine)
	if (!blob)
		return 0;
	unsigned char* p = blob;
	if (i2d_SSL_SESSION(aSess, &p) == len)
		{
		TBuf8<256> host(iHost);
		const unsigned char flags = SSL_SESSION_get_protocol_version(aSess) == TLS1_3_VERSION ? PHSC_FLAG_SINGLE_USE : 0;
		SpinLock(gSessLock);
		phsc_put(&gSess, (const char*)host.PtrZ(), iPort, blob, (size_t)len, flags, NowSeconds(),
				 (uint32_t)SSL_SESSION_get_timeout(aSess));
		SpinUnlock(gSessLock);
		iSessionDirty = ETrue;
		TLSLOG("[ssl] %08x session cached (%d bytes)", this, len);
		}
	free(blob);
	return 0;
	}

// Before the handshake: offer the cached session for this host and port, if there is one.
void CTlsConnection::TryResume()
	{
	if (!iSettings.session_cache || iHost.Length() == 0)
		return;
	TBuf8<256> host(iHost);
	const char* name = (const char*)host.PtrZ();
	const TUint port = iPort;
	SessionsLoadOnce(iSettings.session_persist);
	TBool bad = EFalse;
		{
		TEngine engine;
		size_t len = 0;
		unsigned char flags = 0;
		SpinLock(gSessLock);
		unsigned char* blob = phsc_take(&gSess, name, port, NowSeconds(), &len, &flags);
		SpinUnlock(gSessLock);
		if (blob)
			{
			const unsigned char* p = blob;
			SSL_SESSION* sess = d2i_SSL_SESSION(NULL, &p, (long)len);
			if (sess && SSL_set_session(iSsl, sess) == 1)
				iSessionOffered = ETrue;
			else
				bad = ETrue;				// damaged or from another build: do not offer it again
			SSL_SESSION_free(sess);
			free(blob);
			ERR_clear_error();
			}
		}
	if (bad)
		{
		SpinLock(gSessLock);
		{ TSharedHeap shared; phsc_remove(&gSess, name, port); }
		SpinUnlock(gSessLock);
		}
	TLSLOG("[ssl] %08x session %s", this, iSessionOffered ? "offered" : "none");
	}

// A handshake that failed with a cached session in it: drop the entry (a server that now refuses it outright).
void CTlsConnection::ForgetSession()
	{
	if (!iSessionOffered)
		return;
	iSessionOffered = EFalse;
	TBuf8<256> host(iHost);
	SpinLock(gSessLock);
	{ TSharedHeap shared; phsc_remove(&gSess, (const char*)host.PtrZ(), iPort); }
	SpinUnlock(gSessLock);
	}

// ---- memory BIOs: queues, never block ---------------------------------------------------------------------------
// Ciphertext OpenSSL produced -> iOut (the next Flush() hands it to the transport). Only the BIO read is in the engine
// scope: iOut is a thread-heap buffer.
void CTlsConnection::DrainOut()
	{
	char chunk[1024];
	for (;;)
		{
		int n;
			{
			TEngine engine;
			n = BIO_read(iWbio, chunk, sizeof(chunk));
			}
		if (n <= 0)
			break;
		if (iOut.Length() + n > iOut.MaxLength() && iOut.ReAlloc(iOut.Length() + n + 1024) != KErrNone)
			{
			FailAll(KErrNoMemory);
			return;
			}
		iOut.Append(TPtrC8(reinterpret_cast<const TUint8*>(chunk), n));
		}
	}

// Received ciphertext (iRecvBuf) -> the read BIO; tracks the TLS record framing so that the generic transport (which
// has no one-or-more read) asks for exactly the rest of the current record: iWant.
void CTlsConnection::FeedIn()
	{
	const TUint8* p = iRecvBuf.Ptr();
	TInt left = iRecvBuf.Length();
		{
		TEngine engine;
		BIO_write(iRbio, p, left);
		}
	while (left > 0)
		{
		if (iRecHave < 5)
			{
			iRecHdr[iRecHave++] = *p++;
			--left;
			if (iRecHave == 5)
				iRecNeed = 5 + ((iRecHdr[3] << 8) | iRecHdr[4]);
			}
		else
			{
			TInt n = Min(left, iRecNeed - iRecHave);
			iRecHave += n;
			p += n;
			left -= n;
			}
		if (iRecHave >= 5 && iRecHave == iRecNeed)
			iRecHave = 0;
		}
	iWant = iRecHave < 5 ? 5 - iRecHave : iRecNeed - iRecHave;
	}

// What the engine call that returned aRc left: 0 (SSL_ERROR_NONE), SSL_ERROR_WANT_READ, or the SSL_ERROR_* that ended
// it. Call it INSIDE the scope of that call (the error queue is the library's one): it records the OpenSSL error and the
// verify result for MapErr and the log line, and empties the queue.
TInt CTlsConnection::EngErr(int aRc)
	{
	int e = aRc > 0 ? SSL_ERROR_NONE : SSL_get_error(iSsl, aRc);
	iLastErr = (e == SSL_ERROR_SSL || e == SSL_ERROR_SYSCALL) ? ERR_peek_last_error() : 0;
	iVerifyRes = (TInt)SSL_get_verify_result(iSsl);
	ERR_clear_error();
	return e;
	}

// The ciphertext the call produced is moved to iOut (outside the scope); returns the class EngErr gave.
TInt CTlsConnection::TlsCall(int aSslError)
	{
	DrainOut();
	return aSslError;
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

// aSslError: an SSL_ERROR_* (EngErr); iLastErr / iVerifyRes were taken inside the failed call's scope.
TInt CTlsConnection::MapErr(int aSslError)
	{
	switch (aSslError)
		{
	case SSL_ERROR_ZERO_RETURN:
		return KErrEof;				// close_notify
	case SSL_ERROR_SYSCALL:
		return iClosed ? KErrEof : KErrSSLAlertInternalError;	// (EOF without close_notify)
	case SSL_ERROR_SSL:
		{
		unsigned long err = iLastErr;
		const int reason = ERR_GET_REASON(err);
		TLSLOG("[ssl] OpenSSL error 0x%08lx", err);
		if (reason == SSL_R_CERTIFICATE_VERIFY_FAILED)
			return MapVerify((TUint32)iVerifyRes);
		if (reason == ERR_R_MALLOC_FAILURE)
			return KErrNoMemory;
		if (reason >= SSL_AD_REASON_OFFSET && reason < SSL_AD_REASON_OFFSET + 256)
			return KErrSSLAlertHandshakeFailure;	// a fatal alert from the peer (TLS alert number = reason - offset)
		return KErrSSLAlertHandshakeFailure;
		}
	default:
		RDebug::Printf("PH: [ssl] OpenSSL error class %d -> KErrSSLAlertInternalError", aSslError);
		return KErrSSLAlertInternalError;
		}
	}

// As the 2010 TLS provider's unattended mode (CTlsProvider.cpp, EValidateCertificate); aVerifyErr = X509_V_ERR_*.
TInt CTlsConnection::MapVerify(TUint32 aVerifyErr)
	{
	TLSLOG("[ssl] certificate verify failed: x509 error %d", (TInt)aVerifyErr);
	switch (aVerifyErr)
		{
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
	case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
	case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
	case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
		return KErrSSLAlertUnknownCA;
	case X509_V_ERR_CERT_REVOKED:
		return KErrSSLAlertCertificateRevoked;
	case X509_V_ERR_CERT_HAS_EXPIRED:
	case X509_V_ERR_CERT_NOT_YET_VALID:
		return KErrSSLAlertCertificateExpired;
	default:
		return KErrSSLAlertBadCertificate;
		}
	}

// The reason as the S60 dialog reads it (CTSecurityDialogsAO.cpp): EValidatedOK / EDateOutOfRange = a trusted
// certificate with a name or date problem (the dialog tells them apart by comparing the CN with the host),
// EChainHasNoRoot = untrusted (can be accepted), ECertificateRevoked = refused outright.
static TValidationError DialogReason(TUint32 aVerifyErr)
	{
	switch (aVerifyErr)
		{
	case X509_V_ERR_CERT_REVOKED:
		return ECertificateRevoked;
	case X509_V_ERR_CERT_HAS_EXPIRED:
	case X509_V_ERR_CERT_NOT_YET_VALID:
		return EDateOutOfRange;
	case X509_V_ERR_HOSTNAME_MISMATCH:
	case X509_V_ERR_IP_ADDRESS_MISMATCH:
		return EValidatedOK;
	default:
		return EChainHasNoRoot;
		}
	}

// The leaf certificate as DER (empty = none yet). The OpenSSL parts run in the engine scope, the descriptor is made on
// the thread's own heap outside it.
TInt CTlsConnection::PeerDer(RBuf8& aDer)
	{
	X509* x;
	TInt len;
		{
		TEngine engine;
		x = SSL_get1_peer_certificate(iSsl);
		len = x ? i2d_X509(x, NULL) : 0;
		}
	if (!x)
		return KErrNotFound;
	TInt err = len > 0 ? aDer.Create(len) : KErrGeneral;
		{
		TEngine engine;
		if (err == KErrNone)
			{
			unsigned char* p = const_cast<TUint8*>(aDer.Ptr());
			i2d_X509(x, &p);
			aDer.SetLength(len);
			}
		X509_free(x);
		}
	return err;
	}

// Certificates the user accepted, per process (the 2010 provider keeps them in its cache server for the session;
// "accept permanently" goes to the dialog's own trusted-sites store): SHA-256 of the leaf + the host.
const TInt KMaxAccepted = 16;
static TUint8 gAccepted[KMaxAccepted][32];
static TInt gAcceptedCount;
static TInt gAcceptedNext;

TBool CTlsConnection::PeerCertAccepted(TBool aRemember)
	{
	RBuf8 der;
	if (PeerDer(der) != KErrNone)
		return EFalse;
	TUint8 digest[32];
	unsigned int dlen = 0;
	TBool ok;
		{
		TEngine engine;
		EVP_MD_CTX* md = EVP_MD_CTX_new();
		ok = md && EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1
			&& EVP_DigestUpdate(md, der.Ptr(), der.Length()) == 1
			&& EVP_DigestUpdate(md, iHost.Ptr(), iHost.Length()) == 1
			&& EVP_DigestFinal_ex(md, digest, &dlen) == 1;
		EVP_MD_CTX_free(md);
		ERR_clear_error();
		}
	der.Close();
	if (!ok)
		return EFalse;
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

void CTlsConnection::StartDialogL(TUint32 aVerifyErr, const TDesC8& aCert)
	{
	if (!iDialogAo)
		iDialogAo = new(ELeave) CTlsDialogAo(*this);
	iDialogAo->StartL(iHost, DialogReason(aVerifyErr), aCert);
	}

void CTlsConnection::RefusePeerCert(TInt aErr)
	{
	// (OpenSSL has no public call for a bad_certificate alert after the handshake: the close_notify tells the peer
	// we are gone; the mbedTLS engine sends the exact alert)
		{
		TEngine engine;
		SSL_shutdown(iSsl);
		}
	DrainOut();
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
			{
			iClosed = ETrue;			// OpenSSL sees EOF (the read BIO returns 0) -> the read completes with KErrEof
			BIO_set_mem_eof_return(iRbio, 0);
			}
		else if (aResult != KErrNone)
			{
			FailAll(aResult);
			return;
			}
		if (iGeneric)
			iRecvBuf.SetLength(iRecvView.Length());
		if (iRecvBuf.Length())
			FeedIn();
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
		int rc, se;
		TUint32 flags = 0;
			{
			TEngine engine;
			rc = SSL_do_handshake(iSsl);
			se = EngErr(rc);
			if (se == SSL_ERROR_NONE)
				flags = (TUint32)iVerifyRes;
			}
		TlsCall(se);
		if (iSessionDirty && iSettings.session_persist && se == SSL_ERROR_NONE)
			{
			iSessionDirty = EFalse;
			SessionsSave();
			}
		if (se == SSL_ERROR_NONE && flags && !PeerCertAccepted(EFalse))
			{
			if (iDialogMode == EDialogModeUnattended)
				{
				RefusePeerCert(MapVerify(flags));
				return;
				}
			RBuf8 der;
			TLSLOG("[ssl] %08x certificate x509 error %d: asking the user", this, (TInt)flags);
			TInt err = PeerDer(der);
			if (err == KErrNone)
				TRAP(err, StartDialogL(flags, der));
			der.Close();
			if (err != KErrNone)
				{
				RefusePeerCert(MapVerify(flags));	// no dialog available: as unattended
				return;
				}
			iVerifyPending = ETrue;
			Flush();						// (TLS 1.3: our Finished)
			return;
			}
		if (se == SSL_ERROR_NONE)
			{
			iConnected = ETrue;
			TLSLOG("[ssl] handshake done: %s %s%s", SSL_get_version(iSsl), SSL_CIPHER_get_name(SSL_get_current_cipher(iSsl)), SSL_session_reused(iSsl) ? " (resumed)" : "");
			if (iOut.Length() == 0)
				Complete(iHandshake, KErrNone);
			}
		else if (se == SSL_ERROR_WANT_READ || se == SSL_ERROR_WANT_WRITE)
			needRecv = se == SSL_ERROR_WANT_READ;
		else
			{
			RDebug::Printf("PH: [ssl] %08x handshake failed: class %d err 0x%08lx (resumed offer %d)", this, se, iLastErr, iSessionOffered ? 1 : 0);
			ForgetSession();
			Flush();					// the alert, if any
			FailAll(MapErr(se));
			return;
			}
		}

	if (iWrite && iConnected && !iWriteFlushing)
		{
		while (iWriteDone < iWriteData.Length())
			{
			size_t written = 0;
			int rc, se;
				{
				TEngine engine;
				rc = SSL_write_ex(iSsl, iWriteData.Ptr() + iWriteDone, (size_t)(iWriteData.Length() - iWriteDone), &written);
				se = EngErr(rc);
				}
			TlsCall(se);
			if (rc > 0)
				iWriteDone += (TInt)written;
			else if (se == SSL_ERROR_WANT_READ || se == SSL_ERROR_WANT_WRITE)
				break;
			else
				{
				RDebug::Printf("PH: [ssl] %08x write failed: class %d err 0x%08lx", this, se, iLastErr);
				FailAll(MapErr(se));
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
			size_t got = 0;
			int rc, se;
				{
				TEngine engine;
				rc = SSL_read_ex(iSsl, const_cast<TUint8*>(iReadDes->Ptr()) + iReadDes->Length(), (size_t)room, &got);
				se = EngErr(rc);
				}
			TlsCall(se);							// (a TLS 1.3 ticket / key update is consumed inside OpenSSL; the session callback ran in there)
			if (iSessionDirty && iSettings.session_persist)
				{
				iSessionDirty = EFalse;
				SessionsSave();
				}
			if (rc > 0)
				{
				iReadDes->SetLength(iReadDes->Length() + (TInt)got);
				if (!iReadFill)
					break;
				}
			else if (se == SSL_ERROR_WANT_READ || se == SSL_ERROR_WANT_WRITE)
				{
				needRecv = ETrue;
				break;
				}
			else if (se == SSL_ERROR_ZERO_RETURN || (se == SSL_ERROR_SYSCALL && iClosed))
				{
				TLSLOG("[ssl] %08x read eof class=%d have=%d", this, se, iReadDes->Length());
				if (iReadDes->Length() == 0)
					{
					Complete(iRead, KErrEof);
					}
				break;
				}
			else
				{
				RDebug::Printf("PH: [ssl] %08x read failed: class %d err 0x%08lx", this, se, iLastErr);
				FailAll(MapErr(se));
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
	iPort = SessionPort();			// (a socket call: outside the engine scope)
	if (iAlpnWire.Length())
		{
		TEngine engine;
		SSL_set_alpn_protos(iSsl, iAlpnWire.Ptr(), (unsigned)iAlpnWire.Length());
		}
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
	TLSLOG("[ssl] %08x read max=%d fill=%d in=%d avail=%d closed=%d", this, aDesc.MaxLength(), aFill, iIn.Length(), iConnected ? -1, iClosed);
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
			{
			TEngine engine;
			SSL_shutdown(iSsl);			// queues our close_notify
			}
		DrainOut();
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
	RBuf8 der;
	if (PeerDer(der) != KErrNone)
		return NULL;
	TRAPD(err, iServerCert = CX509Certificate::NewL(der));
	TLSLOG("[ssl] %08x ServerCert: %d bytes DER -> x509 err %d", this, der.Length(), err);
	der.Close();
	return err == KErrNone ? iServerCert : NULL;
	}

TInt CTlsConnection::CurrentCipherSuite(TDes8& aCipherSuite)
	{
	TLSLOG("[ssl] %08x CurrentCipherSuite", this);
	if (aCipherSuite.MaxLength() < 2)
		return KErrOverflow;
	const SSL_CIPHER* cipher = iConnected ? SSL_get_current_cipher(iSsl) : NULL;
	int id = cipher ? (int)SSL_CIPHER_get_protocol_id(cipher) : 0;	// the TLS suite number
	aCipherSuite.SetLength(2);
	aCipherSuite[0] = (TUint8)(id >> 8);
	aCipherSuite[1] = (TUint8)id;
	return KErrNone;
	}

// The suites offered ([hi][lo] pairs).
TInt CTlsConnection::AvailableCipherSuites(TDes8& aCiphers)
	{
	TLSLOG("[ssl] %08x AvailableCipherSuites max=%d", this, aCiphers.MaxLength());
	aCiphers.Zero();
	STACK_OF(SSL_CIPHER)* list = SSL_get_ciphers(iSsl);
	for (int i = 0; list && i < sk_SSL_CIPHER_num(list); ++i)
		{
		const TUint32 id = SSL_CIPHER_get_protocol_id(sk_SSL_CIPHER_value(list, i));
		if (aCiphers.Length() + 2 > aCiphers.MaxLength())
			return KErrOverflow;
		aCiphers.Append((TUint8)(id >> 8));
		aCiphers.Append((TUint8)id);
		}
	return KErrNone;
	}

// Callers pick from the 2010 SSL.DLL's (TLS 1.0-era) list: honouring it would switch off every modern suite, so
// the request is accepted and mbedTLS keeps its own (forward-secret AEAD) preference order.
TInt CTlsConnection::SetAvailableCipherSuites(const TDesC8& /*aCiphers*/)
	{
	return KErrNone;
	}

TInt CTlsConnection::GetOpt(TUint aOptionName, TUint aOptionLevel, TInt& aOption)
	{
	TLSLOG("[ssl] %08x GetOpt(int) %x/%x", this, aOptionName, aOptionLevel);
	if (aOptionLevel == KSolInetSSL && aOptionName == KPhSoSessionResumed)
		{
		TEngine engine;
		aOption = (iConnected && SSL_session_reused(iSsl)) ? 1 : 0;
		return KErrNone;
		}
	if (aOptionName == KSOReadBytesPending && aOptionLevel == KSOLSocket)
		{
		TEngine engine;
		aOption = (TInt)SSL_pending(iSsl);
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
		aOption.Zero();
		if (iConnected)
			{
			TEngine engine;
			const unsigned char* proto = NULL;
			unsigned len = 0;
			SSL_get0_alpn_selected(iSsl, &proto, &len);
			if (proto && len)
				aOption.Copy(TPtrC8(proto, (TInt)len).Left(aOption.MaxLength()));
			}
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
		iHost.LowerCase();			// DNS names are case-insensitive: one spelling for the SNI, the name check and the session cache
		TBuf8<256> host(iHost);
		// SNI + the certificate name check (a name mismatch lands in SSL_get_verify_result)
		const char* name = (const char*)host.PtrZ();
		TEngine engine;
		const TBool ok = SSL_set_tlsext_host_name(iSsl, name) == 1 && SSL_set1_host(iSsl, name) == 1;
		ERR_clear_error();
		return ok ? KErrNone : KErrArgument;
		}
	case KSoDialogMode:
		if (aOption.Length() < (TInt)sizeof(TUint))
			return KErrArgument;
		return SetDialogMode((TDialogMode)*(const TUint*)aOption.Ptr());
	case KPhSoAlpn:
		{
		// "h2,http/1.1": at most 8 names, 63 bytes in all; kept as the length-prefixed list OpenSSL wants
		if (iConnected || iHandshake || aOption.Length() >= iAlpn.MaxLength())
			return KErrArgument;
		TBuf8<80> wire;
		TInt lenAt = -1, count = 0;
		for (TInt i = 0; i <= aOption.Length(); ++i)
			{
			const TBool end = i == aOption.Length();
			const TUint8 c = end ? ',' : aOption[i];
			if (c == ',')
				{
				if (lenAt < 0 || wire.Length() - lenAt - 1 == 0)
					{
					if (end && aOption.Length() == 0)
						break;				// "" = offer nothing
					return KErrArgument;	// an empty name
					}
				wire[lenAt] = (TUint8)(wire.Length() - lenAt - 1);
				lenAt = -1;
				continue;
				}
			if (lenAt < 0)
				{
				if (++count > 8)
					return KErrArgument;
				lenAt = wire.Length();
				wire.Append(0);
				}
			wire.Append(c);
			}
		iAlpn.Copy(aOption);
		iAlpnWire.Copy(wire);
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
	if (iConnected ? SSL_version(iSsl) == TLS1_3_VERSION : iSettings.tls13 != 0)
		name.Set(KTls13);
	if (aProtocol.MaxLength() < name.Length())
		return KErrOverflow;
	aProtocol.Copy(name);
	return KErrNone;
	}
