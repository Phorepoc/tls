// Copyright The Phorepoc Authors
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-Phorepoc-Build-Output-Exception-1.0
// Host shim for seed_symbian.cpp: the two euser names it uses, over getrandom().
#pragma once
#include <stddef.h>
#include <sys/random.h>
typedef int TInt;
typedef unsigned char TUint8;
class TDes8
	{
public:
	TDes8(unsigned char* aPtr, int aLen, int aMax) : iPtr(aPtr), iLen(aLen), iMax(aMax) {}
	void SetLength(int aLen) { iLen = aLen; }
	unsigned char* Ptr() { return iPtr; }
	int Length() const { return iLen; }
private:
	unsigned char* iPtr; int iLen; int iMax;
	};
typedef TDes8 TPtr8;
namespace Math
	{
	inline void Random(TDes8& aDes)
		{
		unsigned char* p = aDes.Ptr();
		for (int n = aDes.Length(); n > 0;)
			{
			ssize_t r = getrandom(p, (size_t)n, 0);
			if (r <= 0) continue;
			p += r; n -= (int)r;
			}
		}
	}
