// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0

// tls_conf.cpp -- see tls_conf.h.
#include <string.h>

#include "tls_conf.h"

void phtls_conf_defaults(phtls_conf* aConf)
	{
	aConf->tls13 = 1;
	aConf->session_cache = 1;
	aConf->session_persist = 1;
	}

static bool IsSpace(char c) { return c == ' ' || c == '\t' || c == '\r'; }

// "0", "off", "no", "false" / "1", "on", "yes", "true"; anything else leaves aValue alone
static void ParseBool(const char* v, size_t n, int* aValue)
	{
	struct { const char* s; int val; } words[] =
		{ { "0", 0 }, { "off", 0 }, { "no", 0 }, { "false", 0 }, { "1", 1 }, { "on", 1 }, { "yes", 1 }, { "true", 1 } };
	for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); ++i)
		{
		size_t wl = strlen(words[i].s);
		if (wl != n)
			continue;
		size_t k = 0;
		while (k < n && (v[k] | 0x20) == words[i].s[k])
			++k;
		if (k == n)
			{
			*aValue = words[i].val;
			return;
			}
		}
	}

void phtls_conf_parse(phtls_conf* aConf, const char* aText, size_t aLen)
	{
	size_t pos = 0;
	while (pos < aLen)
		{
		size_t end = pos;
		while (end < aLen && aText[end] != '\n')
			++end;
		const char* line = aText + pos;
		size_t n = end - pos;
		pos = end + 1;
		for (size_t i = 0; i < n; ++i)			// a trailing comment
			if (line[i] == '#')
				{
				n = i;
				break;
				}
		const char* eq = (const char*)memchr(line, '=', n);
		if (!eq)
			continue;
		const char* k = line;
		size_t kl = (size_t)(eq - line);
		while (kl && IsSpace(k[0]))
			{ ++k; --kl; }
		while (kl && IsSpace(k[kl - 1]))
			--kl;
		const char* v = eq + 1;
		size_t vl = n - (size_t)(v - line);
		while (vl && IsSpace(v[0]))
			{ ++v; --vl; }
		while (vl && IsSpace(v[vl - 1]))
			--vl;
		int* target = NULL;
		if (kl == 5 && memcmp(k, "tls13", 5) == 0)
			target = &aConf->tls13;
		else if (kl == 13 && memcmp(k, "session_cache", 13) == 0)
			target = &aConf->session_cache;
		else if (kl == 15 && memcmp(k, "session_persist", 15) == 0)
			target = &aConf->session_persist;
		if (target)
			ParseBool(v, vl, target);
		}
	}
