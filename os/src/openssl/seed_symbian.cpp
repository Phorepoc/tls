// Copyright The Phorepoc Authors
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-Phorepoc-Build-Output-Exception-1.0

// seed_symbian.cpp -- OpenSSL's entropy source on Symbian: the kernel's random number generator (euser
// Math::Random), the same source the mbedTLS port uses (os/src/mbedtls/entropy_symbian.cpp).
//
// OpenSSL is built with --with-rand-seed=none (no OS entropy call exists on Symbian), so its seed source finds
// nothing. This file registers a built-in provider "phorepoc-seed" with one RAND algorithm, "PH-SEED", that follows
// the contract of OpenSSL's own SEED-SRC (get_seed / clear_seed), and selects it as the seed source of the default
// library context (RAND_set_seed_source_type) before the first DRBG is used. Public API only; nothing of OpenSSL is
// patched.
// NB: how well the kernel pool is seeded on a board is an open item (no hardware entropy source wired into it yet);
// the TLS is not weakened by this file, only by a poorly seeded pool.
#include <e32math.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

namespace
	{
	struct TSeedCtx
		{
		int iState;
		};

	void* SeedNew(void* /*aProvCtx*/, void* aParent, const OSSL_DISPATCH* /*aParentDispatch*/)
		{
		if (aParent)
			return NULL;			// a seed source has no parent
		TSeedCtx* c = (TSeedCtx*)calloc(1, sizeof(TSeedCtx));
		if (c)
			c->iState = EVP_RAND_STATE_UNINITIALISED;
		return c;
		}

	void SeedFree(void* aCtx) { free(aCtx); }

	int SeedInstantiate(void* aCtx, unsigned int, int, const unsigned char*, size_t, const OSSL_PARAM[])
		{
		((TSeedCtx*)aCtx)->iState = EVP_RAND_STATE_READY;
		return 1;
		}

	int SeedUninstantiate(void* aCtx)
		{
		((TSeedCtx*)aCtx)->iState = EVP_RAND_STATE_UNINITIALISED;
		return 1;
		}

	void Fill(unsigned char* aOut, size_t aLen)
		{
		TPtr8 out(aOut, 0, (TInt)aLen);
		out.SetLength((TInt)aLen);
		Math::Random(out);
		}

	int SeedGenerate(void* aCtx, unsigned char* aOut, size_t aLen, unsigned int, int, const unsigned char*, size_t)
		{
		if (((TSeedCtx*)aCtx)->iState != EVP_RAND_STATE_READY)
			return 0;
		Fill(aOut, aLen);
		return 1;
		}

	int SeedReseed(void* aCtx, int, const unsigned char*, size_t, const unsigned char*, size_t)
		{
		return ((TSeedCtx*)aCtx)->iState == EVP_RAND_STATE_READY;
		}

	int SeedGetCtxParams(void* aCtx, OSSL_PARAM aParams[])
		{
		OSSL_PARAM* p = OSSL_PARAM_locate(aParams, OSSL_RAND_PARAM_STATE);
		if (p && !OSSL_PARAM_set_int(p, ((TSeedCtx*)aCtx)->iState))
			return 0;
		p = OSSL_PARAM_locate(aParams, OSSL_RAND_PARAM_STRENGTH);
		if (p && !OSSL_PARAM_set_int(p, 1024))
			return 0;
		p = OSSL_PARAM_locate(aParams, OSSL_RAND_PARAM_MAX_REQUEST);
		if (p && !OSSL_PARAM_set_size_t(p, 128))
			return 0;
		return 1;
		}

	const OSSL_PARAM* SeedGettable(void*, void*)
		{
		static const OSSL_PARAM known[] = {
			OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, NULL),
			OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
			OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
			OSSL_PARAM_END
		};
		return known;
		}

	int SeedVerifyZeroization(void*) { return 1; }
	int SeedEnableLocking(void*) { return 1; }
	int SeedLock(void*) { return 1; }
	void SeedUnlock(void*) {}

	// what the parent DRBG instantiates / reseeds from: aMinLen..aMaxLen bytes (every byte is a byte of the kernel RNG)
	size_t SeedGetSeed(void*, unsigned char** aOut, int /*aEntropyBits*/, size_t aMinLen, size_t aMaxLen,
					   int, const unsigned char*, size_t)
		{
		size_t len = aMinLen > 32 ? aMinLen : 32;
		if (len > aMaxLen)
			len = aMaxLen;
		if (len < aMinLen)
			return 0;
		unsigned char* buf = (unsigned char*)malloc(len);
		if (!buf)
			return 0;
		Fill(buf, len);
		*aOut = buf;
		return len;
		}

	void SeedClearSeed(void*, unsigned char* aOut, size_t aLen)
		{
		if (aOut)
			{
			memset(aOut, 0, aLen);
			free(aOut);
			}
		}

	const OSSL_DISPATCH KSeedFunctions[] = {
		{ OSSL_FUNC_RAND_NEWCTX, (void (*)(void))SeedNew },
		{ OSSL_FUNC_RAND_FREECTX, (void (*)(void))SeedFree },
		{ OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))SeedInstantiate },
		{ OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void))SeedUninstantiate },
		{ OSSL_FUNC_RAND_GENERATE, (void (*)(void))SeedGenerate },
		{ OSSL_FUNC_RAND_RESEED, (void (*)(void))SeedReseed },
		{ OSSL_FUNC_RAND_ENABLE_LOCKING, (void (*)(void))SeedEnableLocking },
		{ OSSL_FUNC_RAND_LOCK, (void (*)(void))SeedLock },
		{ OSSL_FUNC_RAND_UNLOCK, (void (*)(void))SeedUnlock },
		{ OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void (*)(void))SeedGettable },
		{ OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void))SeedGetCtxParams },
		{ OSSL_FUNC_RAND_VERIFY_ZEROIZATION, (void (*)(void))SeedVerifyZeroization },
		{ OSSL_FUNC_RAND_GET_SEED, (void (*)(void))SeedGetSeed },
		{ OSSL_FUNC_RAND_CLEAR_SEED, (void (*)(void))SeedClearSeed },
		{ 0, NULL }
	};

	const OSSL_ALGORITHM KSeedAlgorithms[] = {
		{ "PH-SEED", "provider=phorepoc-seed", KSeedFunctions, "Phorepoc kernel RNG seed source" },
		{ NULL, NULL, NULL, NULL }
	};

	const OSSL_ALGORITHM* SeedQuery(void*, int aOperation, int* aNoCache)
		{
		*aNoCache = 0;
		return aOperation == OSSL_OP_RAND ? KSeedAlgorithms : NULL;
		}

	const OSSL_DISPATCH KProviderFunctions[] = {
		{ OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))SeedQuery },
		{ 0, NULL }
	};

	int SeedProviderInit(const OSSL_CORE_HANDLE*, const OSSL_DISPATCH*, const OSSL_DISPATCH** aOut, void** aProvCtx)
		{
		*aProvCtx = NULL;
		*aOut = KProviderFunctions;
		return 1;
		}

	int gSeedReady;		// per process (the DLL's writable static data: EPOCALLOWDLLDATA)
	}

// Registers the provider and makes it the seed source; call before the first SSL_CTX is made. Repeat calls return 1
// at once. 0 = the library refused (no memory).
extern "C" int phorepoc_openssl_seed_init(void)
	{
	if (gSeedReady)
		return 1;
	if (!OSSL_PROVIDER_add_builtin(NULL, "phorepoc-seed", SeedProviderInit)
		|| !OSSL_PROVIDER_load(NULL, "phorepoc-seed")
		|| !OSSL_PROVIDER_load(NULL, "default")
		|| !RAND_set_seed_source_type(NULL, "PH-SEED", "provider=phorepoc-seed"))
		return 0;
	gSeedReady = 1;
	return 1;
	}
