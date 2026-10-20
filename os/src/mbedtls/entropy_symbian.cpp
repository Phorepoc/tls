// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0

// entropy_symbian.cpp -- mbedTLS's entropy source on Symbian
// (MBEDTLS_ENTROPY_HARDWARE_ALT in phorepoc_mbedtls_config.h). euser's Math::Random(TDes8&) = the kernel's random
// number generator -- what what the device build uses too.
// NB: how well the kernel pool is seeded on this board (no hardware entropy source is wired into it yet) is an open
// item; the TLS itself is not weakened by this file, only by a poorly seeded pool.
#include <e32math.h>
#include <stddef.h>

extern "C" int mbedtls_hardware_poll(void* /*aData*/, unsigned char* aOutput, size_t aLen, size_t* aOLen)
	{
	TPtr8 out(aOutput, 0, (TInt)aLen);
	out.SetLength((TInt)aLen);
	Math::Random(out);
	*aOLen = aLen;
	return 0;
	}

// mbedtls_ms_time (TLS 1.3 ticket ages): platform_util.c finds no clock on the ARM (device) build, which is neither
// "unix" nor Windows to it -- MBEDTLS_PLATFORM_MS_TIME_ALT there (emitter/components.py ssl_arm), milliseconds of
// universal time here. (The x32 build uses Open C's clock_gettime.)
#if defined(MBEDTLS_PLATFORM_MS_TIME_ALT)
#include <e32std.h>
extern "C" long long mbedtls_ms_time(void)
	{
	TTime now;
	now.UniversalTime();
	return now.Int64() / 1000;
	}
#endif
