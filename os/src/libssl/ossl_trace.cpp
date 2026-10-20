// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0

// ossl_trace.cpp -- the libssl.dll drop-in's trace line (C side: ossl_trace() in ossl_ssl.c).
// PHOREPOC_LIBSSL_TRACE: one RDebug line per handshake result / failure, prefixed "[libssl]".
#include <e32std.h>
#include <e32debug.h>
#ifdef PHOREPOC_LIBSSL_FILELOG
#include <f32file.h>
#endif

class TOsslTraceOverflow : public TDes8Overflow
	{
public:
	void Overflow(TDes8& /*aDes*/) {}
	};

extern "C" void ossl_trace(const char* aFmt, ...)
	{
	TBuf8<300> line;
	TOsslTraceOverflow overflow;
	VA_LIST list;
	VA_START(list, aFmt);
	line.AppendFormatList(TPtrC8(reinterpret_cast<const TUint8*>(aFmt)), list, &overflow);
	VA_END(list);
	if (line.Length() == line.MaxLength())
		line.SetLength(line.MaxLength() - 1);		// room for PtrZ's terminator
	RDebug::Printf("[libssl] %s", (const char*)line.PtrZ());
#ifdef PHOREPOC_LIBSSL_FILELOG
	// a phone has no debug port: the same line appended to C:\data\libssl_trace.txt
	RFs fs;
	if (fs.Connect() == KErrNone)
		{
		RFile f;
		_LIT(KLog, "c:\\data\\libssl_trace.txt");
		TInt err = f.Open(fs, KLog, EFileWrite | EFileShareAny);
		if (err == KErrNotFound)
			err = f.Create(fs, KLog, EFileWrite | EFileShareAny);
		if (err == KErrNone)
			{
			TInt pos = 0;
			f.Seek(ESeekEnd, pos);
			f.Write(line);
			f.Write(_L8("\n"));
			f.Close();
			}
		fs.Close();
		}
#endif
	}
