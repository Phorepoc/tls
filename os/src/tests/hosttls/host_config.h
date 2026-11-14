/* Copyright The Phorepoc Authors
 * SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-Phorepoc-Build-Output-Exception-1.0 */
/* host_config.h -- the host test's mbedTLS: exactly the ssl.dll configuration, plus the server side the test needs as
 * its peer (a TLS server with session tickets). */
#ifndef PHOREPOC_HOST_CONFIG_H
#define PHOREPOC_HOST_CONFIG_H
#include "phorepoc_mbedtls_config.h"
#define MBEDTLS_SSL_SRV_C
#define MBEDTLS_SSL_TICKET_C
#endif
