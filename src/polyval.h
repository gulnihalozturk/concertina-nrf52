/*
 * POLYVAL (RFC 8452) as used by HCTR2, for Cortex-M4, which has no
 * carry-less multiply instruction (and the CryptoCell-310 of the nRF52840
 * has no GHASH/GCM mode), so POLYVAL is always computed in software.
 *
 * Constant-time implementations (integer multiplications on bit-masked
 * operands, the technique of BearSSL's ghash_ctmul*):
 *   POLYVAL_IMPL_CT32   - 32x32->64-bit multiplications (UMULL, a fixed single
 *                         cycle on Cortex-M4); Karatsuba (9 products of 32-bit
 *                         words per block), Montgomery reduction by shifts.
 *   POLYVAL_IMPL_CT64   - the portable constant-time code of the AArch64
 *                         repository, unchanged (64x64->64-bit products, bit
 *                         reversal, reduction by two more products).
 * Table-based implementations (Shoup's method, as in mbed TLS's GCM; table
 * lookups indexed by secret data, so not constant-time):
 *   POLYVAL_IMPL_TABLE4 - 4-bit tables: 256 bytes per key, 32 lookups/block.
 *   POLYVAL_IMPL_TABLE8 - 8-bit tables: 4 KiB per key, 16 lookups/block.
 * The tables compute GHASH with H' = mulX_GHASH(ByteReverse(H)), using
 * POLYVAL(H, X) = ByteReverse(GHASH(H', ByteReverse(X))) (RFC 8452,
 * Appendix A); with the state kept as a little-endian 128-bit integer, the
 * byte reversals vanish, so all implementations share the same state.
 */
#pragma once
#include "common.h"

enum {
	POLYVAL_IMPL_CT32 = 0,
	POLYVAL_IMPL_CT64 = 1,
	POLYVAL_IMPL_TABLE4 = 2,
	POLYVAL_IMPL_TABLE8 = 3
};

/* Build options (memory measurements): 0 removes an implementation. */
#ifndef POLYVAL_WITH_CT32
#define POLYVAL_WITH_CT32 1
#endif
#ifndef POLYVAL_WITH_CT64
#define POLYVAL_WITH_CT64 1
#endif
#ifndef POLYVAL_WITH_TABLE4
#define POLYVAL_WITH_TABLE4 1
#endif
#ifndef POLYVAL_WITH_TABLE8
#define POLYVAL_WITH_TABLE8 1
#endif

typedef struct {
	u32 h[4]; /* H as little-endian words */
	union {
		u32 none;
#if POLYVAL_WITH_CT32
		u32 hm[9][4]; /* CT32: the nine Karatsuba operands of H, masked */
#endif
#if POLYVAL_WITH_TABLE4
		u32 t4[16][4]; /* TABLE4: nibble multiples of H' */
#endif
#if POLYVAL_WITH_TABLE8
		u32 t8[256][4]; /* TABLE8: byte multiples of H' */
#endif
	} u;
	int impl;
} polyval_key;

typedef struct {
	u32 s[4];
} polyval_state;

void polyval_setkey(polyval_key *key, const u8 h[16], int impl);
FORCEINLINE void polyval_init(polyval_state *st) { memset(st, 0, sizeof(*st)); }
void polyval_update(polyval_state *st, const polyval_key *key, const u8 *data,
		    size_t nblocks);
void polyval_emit(const polyval_state *st, u8 out[16]);

/* Self-test support: the GHASH reduction tables (R[b] = top 16 bits of
 * b * x^k for the k = 4 or 8 bits shifted out). */
extern const u16 polyval_r4[16];
extern const u16 polyval_r8[256];
