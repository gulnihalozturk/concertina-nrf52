/*
 * SHA-256 and HMAC-SHA-256 (FIPS 180-4, FIPS 198-1).
 *   SHA256_IMPL_UNROLLED - the scalar backend of the original repository with
 *                          the round loop unrolled by eight (variable roles
 *                          rotated instead of moved). Default.
 *   SHA256_IMPL_REF      - the scalar backend of the original, unchanged.
 *   SHA256_IMPL_CC310    - the HASH engine of the CryptoCell-310 (nRF52840)
 *                          computes the compression function; padding and
 *                          HMAC are done here, so that HMAC can start from
 *                          the precomputed ipad/opad states.
 * As for HMAC-SHA3-256, the ipad/opad states are precomputed per key.
 *
 * Build options (memory measurements): SHA256_WITH_SW, SHA256_WITH_REF,
 * SHA256_WITH_CC310 (0 removes the backend).
 */
#pragma once
#include "common.h"

enum { SHA256_IMPL_UNROLLED = 0, SHA256_IMPL_REF = 1, SHA256_IMPL_CC310 = 2 };

#ifndef SHA256_WITH_SW
#define SHA256_WITH_SW 1
#endif
#ifndef SHA256_WITH_REF
#define SHA256_WITH_REF 1
#endif
#ifndef SHA256_WITH_CC310
#define SHA256_WITH_CC310 1
#endif

#define SHA256_BLOCK 64

void sha256(const u8 *msg, size_t len, u8 out[32], int impl);

typedef struct {
	u32 inner[8];
	u32 outer[8];
	int impl;
} hmac_sha256_key;

void hmac_sha256_setkey(hmac_sha256_key *k, const u8 *key, size_t key_len,
			int impl);
void hmac_sha256(const hmac_sha256_key *k, const u8 *a, size_t a_len,
		 const u8 *b, size_t b_len, u8 out[32]);
