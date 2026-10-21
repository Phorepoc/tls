// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0

// sslresume.exe -- on-device proof that SSL.DLL resumes TLS sessions. It makes three https connections to one host
// through the platform's CSecureSocket (so through whichever SSL.DLL the loader picks), and asks each connection
// whether it resumed (the Phorepoc option KPhSoSessionResumed). The first is a full handshake; the second and third
// must resume. Output: "[sslresume]" lines on the debug port and in C:\data\sslresume.txt.
//
//   sslresume.exe [host [port]]        default: example.com 443
//
// Verdict line: "[sslresume] PASS" (connection 2 and 3 resumed), "[sslresume] FAIL ..." or "[sslresume] SKIP" (the
// installed SSL.DLL is not ours: no such option). To see the TLS 1.3 / TLS 1.2 behaviours, run it with and without
// "tls13 = 0" in \resource\ssl\ssl.ini; to see persistence across processes, run it twice with session_persist on:
// the first connection of the second run must resume as well ("[sslresume] connection 1 ... resumed 1").
#include <e32std.h>
#include <e32base.h>
#include <f32file.h>
#include <es_sock.h>
#include <in_sock.h>
#include <securesocket.h>
#include <ssl_internal.h>

const TUint KPhSoSessionResumed = 0x50480001;	// (SSL.DLL, tlsconnection_mbed.cpp)

static RFile gLog;

static void Out(const TDesC8& aLine)
	{
	TBuf<200> w;
	w.Copy(aLine.Left(200));
	RDebug::Print(_L("PH: %S"), &w);
	TBuf8<220> l(aLine.Left(210));
	l.Append(_L8("\r\n"));
	if (gLog.SubSessionHandle())
		gLog.Write(l);
	}

static void Line(const char* aFmt, TInt a = 0, TInt b = 0, TInt c = 0)
	{
	TBuf8<200> s;
	s.Format(TPtrC8(reinterpret_cast<const TUint8*>(aFmt)), a, b, c);
	Out(s);
	}

// one connection; returns the handshake error, *aResumed = KPhSoSessionResumed (-1: option unknown)
static TInt Connection(RSocketServ& aSs, const TDesC& aHost, TInt aPort, TInt aIndex, TInt* aResumed, TInt* aMs)
	{
	*aResumed = -1;
	const TUint32 t0 = User::NTickCount();
	RHostResolver resolver;
	TInt err = resolver.Open(aSs, KAfInet, KProtocolInetTcp);
	if (err != KErrNone)
		return err;
	TNameEntry entry;
	TRequestStatus st;
	resolver.GetByName(aHost, entry, st);
	User::WaitForRequest(st);
	resolver.Close();
	if (st.Int() != KErrNone)
		return st.Int();
	TInetAddr addr(entry().iAddr);
	addr.SetPort(aPort);

	RSocket sock;
	err = sock.Open(aSs, KAfInet, KSockStream, KProtocolInetTcp);
	if (err != KErrNone)
		return err;
	sock.Connect(addr, st);
	User::WaitForRequest(st);
	if (st.Int() != KErrNone)
		{
		sock.Close();
		return st.Int();
		}
	CSecureSocket* tls = NULL;
	TRAP(err, tls = CSecureSocket::NewL(sock, _L("TLS1.0")));
	if (err != KErrNone)
		{
		sock.Close();
		return err;
		}
	TBuf8<128> host8;
	host8.Copy(aHost.Left(128));
	tls->SetOpt(KSoSSLDomainName, KSolInetSSL, host8);
	tls->SetDialogMode(EDialogModeUnattended);
	tls->StartClientHandshake(st);
	User::WaitForRequest(st);
	err = st.Int();
	if (err == KErrNone)
		{
		TInt resumed = -1;
		if (tls->GetOpt(KPhSoSessionResumed, KSolInetSSL, resumed) == KErrNone)
			*aResumed = resumed;
		TBuf<16> proto;
		tls->Protocol(proto);
		TBuf8<16> p8;
		p8.Copy(proto);
		// some application data, so a TLS 1.3 server's ticket is read (and cached) as well
		TBuf8<256> req;
		req.Format(_L8("GET / HTTP/1.1\r\nHost: %S\r\nConnection: close\r\n\r\n"), &host8);
		tls->Send(req, st);
		User::WaitForRequest(st);
		TBuf8<1024> reply;
		if (st.Int() == KErrNone)
			{
			TSockXfrLength got;
			tls->RecvOneOrMore(reply, st, got);
			User::WaitForRequest(st);
			}
		*aMs = (TInt)(User::NTickCount() - t0);
		TBuf8<80> msg(_L8("[sslresume] connection "));
		msg.AppendNum(aIndex);
		msg.Append(_L8(": "));
		msg.Append(p8);
		msg.Append(_L8(" resumed "));
		msg.AppendNum(*aResumed);
		msg.Append(_L8(", reply "));
		msg.AppendNum(reply.Length());
		msg.Append(_L8(" bytes, "));
		msg.AppendNum(*aMs);
		msg.Append(_L8(" ms"));
		Out(msg);
		}
	tls->Close();
	delete tls;
	sock.Close();
	return err;
	}

static TInt Run()
	{
	TBuf<128> cmd;
	User::CommandLine(cmd);
	TLex lex(cmd);
	TPtrC host = lex.NextToken();
	if (host.Length() == 0)
		host.Set(_L("example.com"));
	TInt port = 443;
	TPtrC p = lex.NextToken();
	if (p.Length())
		{
		TLex pl(p);
		pl.Val(port);
		}
	RFs fs;
	if (fs.Connect() == KErrNone)
		{
		fs.MkDirAll(_L("C:\\data\\"));
		gLog.Replace(fs, _L("C:\\data\\sslresume.txt"), EFileWrite | EFileStreamText);
		}
	RSocketServ ss;
	TInt err = ss.Connect();
	if (err != KErrNone)
		return err;

	TInt resumed[3] = { -1, -1, -1 };
	TInt ms[3] = { 0, 0, 0 };
	TInt fail = KErrNone;
	for (TInt i = 0; i < 3; ++i)
		{
		TInt e = Connection(ss, host, port, i + 1, &resumed[i], &ms[i]);
		if (e != KErrNone)
			{
			Line("[sslresume] connection %d failed: %d", i + 1, e);
			fail = e;
			break;
			}
		}
	ss.Close();
	if (fail != KErrNone)
		Line("[sslresume] FAIL connection error %d", fail);
	else if (resumed[0] < 0)
		Line("[sslresume] SKIP the installed SSL.DLL has no session option (not Phorepoc's)");
	else if (resumed[1] == 1 && resumed[2] == 1)
		Line("[sslresume] PASS connections 2 and 3 resumed (%d ms full, %d ms resumed)", ms[0], ms[1]);
	else
		Line("[sslresume] FAIL resumed flags %d %d %d", resumed[0], resumed[1], resumed[2]);
	gLog.Close();
	fs.Close();
	return fail;
	}

TInt E32Main()
	{
	__UHEAP_MARK;
	CTrapCleanup* cleanup = CTrapCleanup::New();
	TInt err = KErrNoMemory;
	if (cleanup)
		{
		// the secure socket's provider uses active objects: an active scheduler must be installed
		// (without one the first CSecureSocket call panics E32USER-CBase 44)
		CActiveScheduler* sched = new CActiveScheduler;
		CActiveScheduler::Install(sched);
		TInt result = KErrNone;
		TRAP(err, result = Run());
		delete sched;
		if (err == KErrNone)
			err = result;
		delete cleanup;
		}
	__UHEAP_MARKEND;
	return err;
	}
