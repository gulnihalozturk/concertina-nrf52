/*
 * Keccak-f[1600], SHA3-256 and HMAC-SHA3-256 (FIPS 202, FIPS 198-1) for
 * 32-bit cores.
 *
 * Implementations (selected per key at run time, so both can be tested and
 * benchmarked on the same firmware):
 *   KECCAK_IMPL_BI32  - bit-interleaved 32-bit lanes (the usual technique on
 *                       32-bit CPUs: 64-bit rotations become 32-bit ones).
 *                       Default.
 *   KECCAK_IMPL_REF64 - the 64-bit lane code of the original repository
 *                       (keccak_round.inc), compiled for a 32-bit CPU; kept as
 *                       a reference.
 * HMAC keys are pre-processed once: the states after absorbing K^ipad and
 * K^opad are stored, so that each MAC evaluation only absorbs the message.
 */
#pragma once
#include "common.h"

/* Build option (code-size measurements): 0 removes the reference backend. */
#ifndef KECCAK_WITH_REF64
#define KECCAK_WITH_REF64 1
#endif

#define SHA3_256_RATE 136

enum { KECCAK_IMPL_BI32 = 0, KECCAK_IMPL_REF64 = 1 };

typedef union {
	u64 q[25]; /* KECCAK_IMPL_REF64: lane i = x + 5y */
	u32 w[50]; /* KECCAK_IMPL_BI32: w[2i] even bits, w[2i+1] odd bits */
} keccak_state;

/* The two permutations on their own representation, and the conversion
 * between the representations (used by the self-test). */
void keccak_f1600_ref64(u64 st[25]);
void keccak_f1600_bi32(u32 st[50]);
void keccak_to_bi32(u32 out[50], const u64 in[25]);
void keccak_from_bi32(u64 out[25], const u32 in[50]);

void sha3_256(const u8 *msg, size_t len, u8 out[32], int impl);

typedef struct {
	keccak_state inner;
	keccak_state outer;
	int impl;
} hmac_sha3_256_key;

void hmac_sha3_256_setkey(hmac_sha3_256_key *k, const u8 *key, size_t key_len,
			  int impl);
/* MAC over the concatenation a || b, where b is a short suffix (<= 64 bytes). */
void hmac_sha3_256(const hmac_sha3_256_key *k, const u8 *a, size_t a_len,
		   const u8 *b, size_t b_len, u8 out[32]);
