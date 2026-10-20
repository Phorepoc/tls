// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0

// sslprobe.cpp -- ask the phone's loader for SSL.DLL the way securesocket.dll does (by name, no
// version) and record which file it picked, or the error. Separates "the loader refuses our eclipsing copy"
// from "the client never loads SSL.DLL". Result: C:\data\sslprobe.txt (C:\data needs no capability).
#include <e32std.h>
#include <f32file.h>

static void Log(RFile& aFile, const TDesC& aWhat, TInt aErr, const TDesC& aDetail)
	{
	TBuf8<300> line;
	line.Copy(aWhat);
	line.Append(_L8(" -> "));
	line.AppendNum(aErr);
	line.Append(' ');
	TBuf8<256> detail;
	detail.Copy(aDetail.Left(256));
	line.Append(detail);
	line.Append(_L8("\r\n"));
	aFile.Write(line);
	}

static void Try(RFile& aFile, const TDesC& aName)
	{
	RLibrary lib;
	TInt err = lib.Load(aName);
	if (err != KErrNone)
		{
		Log(aFile, aName, err, KNullDesC);
		return;
		}
	TFileName loaded = lib.FileName();
	TBuf<300> detail(loaded);
	detail.Append(lib.Lookup(1) ? _L(" ord1 ok") : _L(" ord1 NULL"));
	TUidType uids = lib.Type();
	detail.AppendFormat(_L(" uid3 %08x"), uids[2].iUid);
	Log(aFile, aName, err, detail);
	lib.Close();
	}

GLDEF_C TInt E32Main()
	{
	RFs fs;
	if (fs.Connect() != KErrNone)
		return KErrGeneral;
	_LIT(KOut, "C:\\data\\sslprobe.txt");
	RFile file;
	TInt err = file.Replace(fs, KOut, EFileWrite | EFileShareAny);
	if (err == KErrNone)
		{
		Try(file, _L("SSL.DLL"));						// what securesocket.dll does
		Try(file, _L("F:\\sys\\bin\\ssl.dll"));			// our copy only: hash / capability / import errors
		Try(file, _L("Z:\\sys\\bin\\ssl.dll"));			// the ROM one
		file.Close();
		}
	fs.Close();
	return err;
	}
