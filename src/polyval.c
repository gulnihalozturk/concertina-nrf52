#include "platform.h"
#include "polyval.h"

#define M0_32 0x11111111u
#define M1_32 0x22222222u
#define M2_32 0x44444444u
#define M3_32 0x88888888u
#define M0_64 0x1111111111111111ull
#define M1_64 0x2222222222222222ull
#define M2_64 0x4444444444444444ull
#define M3_64 0x8888888888888888ull

/* ---------------- common: Montgomery reduction ---------------- */

/*
 * (h1:h0:l1:l0) * x^-128 mod p(x), p(x) = x^128 + x^127 + x^126 + x^121 + 1,
 * as in the PMULL and portable backends of the AArch64 code. The two
 * carry-less multiplications by the constant 0xc200000000000000 (x^63, x^62,
 * x^57) are done with shifts.
 */
FORCEINLINE void mont_reduce(u64 l0, u64 l1, u64 h0, u64 h1, u64 *r_lo,
			     u64 *r_hi)
{
	u64 t0 = (l0 << 63) ^ (l0 << 62) ^ (l0 << 57);
	u64 t1 = (l0 >> 1) ^ (l0 >> 2) ^ (l0 >> 7);

	t0 ^= l1;
	t1 ^= l0;
	l0 = (t0 << 63) ^ (t0 << 62) ^ (t0 << 57);
	l1 = (t0 >> 1) ^ (t0 >> 2) ^ (t0 >> 7);
	l0 ^= t1;
	l1 ^= t0;
	*r_lo = l0 ^ h0;
	*r_hi = l1 ^ h1;
}

#if POLYVAL_WITH_CT32
/* ---------------- POLYVAL_IMPL_CT32 ---------------- */

/* 64-bit carry-less product of x and y, y given as its four masked parts.
 * Each 32x32->64 product receives at most 8 contributions per bit position,
 * so the sums never carry into the next position of the same class. */
FORCEINLINE u64 bmul32(u32 x, const u32 y[4])
{
	const u32 x0 = x & M0_32, x1 = x & M1_32, x2 = x & M2_32, x3 = x & M3_32;
	const u64 z0 = ((u64)x0 * y[0]) ^ ((u64)x1 * y[3]) ^ ((u64)x2 * y[2]) ^
		       ((u64)x3 * y[1]);
	const u64 z1 = ((u64)x0 * y[1]) ^ ((u64)x1 * y[0]) ^ ((u64)x2 * y[3]) ^
		       ((u64)x3 * y[2]);
	const u64 z2 = ((u64)x0 * y[2]) ^ ((u64)x1 * y[1]) ^ ((u64)x2 * y[0]) ^
		       ((u64)x3 * y[3]);
	const u64 z3 = ((u64)x0 * y[3]) ^ ((u64)x1 * y[2]) ^ ((u64)x2 * y[1]) ^
		       ((u64)x3 * y[0]);

	return (z0 & M0_64) | (z1 & M1_64) | (z2 & M2_64) | (z3 & M3_64);
}

/* 128-bit product of (x1:x0) and the 64-bit operand whose three Karatsuba
 * parts (y0, y1, y0^y1) are given masked in y[0..2]. */
FORCEINLINE void mul64_ct32(u32 x0, u32 x1, const u32 (*y)[4], u64 *lo, u64 *hi)
{
	const u64 l = bmul32(x0, y[0]);
	const u64 h = bmul32(x1, y[1]);
	const u64 m = bmul32(x0 ^ x1, y[2]) ^ l ^ h;

	*lo = l ^ (m << 32);
	*hi = h ^ (m >> 32);
}

static void mask4(u32 out[4], u32 y)
{
	out[0] = y & M0_32;
	out[1] = y & M1_32;
	out[2] = y & M2_32;
	out[3] = y & M3_32;
}

static void mul_ct32(u32 s[4], const polyval_key *key)
{
	u64 pl_lo, pl_hi, ph_lo, ph_hi, pm_lo, pm_hi, r_lo, r_hi;

	mul64_ct32(s[0], s[1], &key->u.hm[0], &pl_lo, &pl_hi);
	mul64_ct32(s[2], s[3], &key->u.hm[3], &ph_lo, &ph_hi);
	mul64_ct32(s[0] ^ s[2], s[1] ^ s[3], &key->u.hm[6], &pm_lo, &pm_hi);
	pm_lo ^= pl_lo ^ ph_lo;
	pm_hi ^= pl_hi ^ ph_hi;
	mont_reduce(pl_lo, pl_hi ^ pm_lo, ph_lo ^ pm_hi, ph_hi, &r_lo, &r_hi);
	s[0] = (u32)r_lo;
	s[1] = (u32)(r_lo >> 32);
	s[2] = (u32)r_hi;
	s[3] = (u32)(r_hi >> 32);
}

#endif /* POLYVAL_WITH_CT32 */

#if POLYVAL_WITH_CT64
/* ---------------- POLYVAL_IMPL_CT64 (AArch64 repository, portable) -------- */

static inline u64 bmul64(u64 x, u64 y)
{
	u64 x0 = x & M0_64, x1 = x & M1_64, x2 = x & M2_64, x3 = x & M3_64;
	u64 y0 = y & M0_64, y1 = y & M1_64, y2 = y & M2_64, y3 = y & M3_64;
	u64 z0 = (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1);
	u64 z1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2);
	u64 z2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3);
	u64 z3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0);

	return (z0 & M0_64) | (z1 & M1_64) | (z2 & M2_64) | (z3 & M3_64);
}

static inline u64 rev64(u64 x)
{
	x = ((x >> 1) & 0x5555555555555555ULL) | ((x & 0x5555555555555555ULL) << 1);
	x = ((x >> 2) & 0x3333333333333333ULL) | ((x & 0x3333333333333333ULL) << 2);
	x = ((x >> 4) & 0x0F0F0F0F0F0F0F0FULL) | ((x & 0x0F0F0F0F0F0F0F0FULL) << 4);
	return __builtin_bswap64(x);
}

static inline void clmul64(u64 x, u64 y, u64 *lo, u64 *hi)
{
	*lo = bmul64(x, y);
	*hi = rev64(bmul64(rev64(x), rev64(y))) >> 1;
}

/* pv_mul_portable() of the AArch64 repository, unchanged: Karatsuba with
 * three clmul64(), and the Montgomery reduction with two more clmul64() by
 * the constant (not by shifts). */
#define POLYVAL_REDUCTION_CONST 0xc200000000000000ULL

static void pv_mul_portable(u64 a_lo, u64 a_hi, u64 b_lo, u64 b_hi, u64 *r_lo,
			    u64 *r_hi)
{
	u64 l0, l1, h0, h1, m0, m1, t0, t1;

	clmul64(a_lo, b_lo, &l0, &l1);
	clmul64(a_hi, b_hi, &h0, &h1);
	clmul64(a_lo ^ a_hi, b_lo ^ b_hi, &m0, &m1);
	m0 ^= l0 ^ h0;
	m1 ^= l1 ^ h1;
	l1 ^= m0;
	h0 ^= m1;
	/* Montgomery reduction, as in the PMULL backend. */
	clmul64(l0, POLYVAL_REDUCTION_CONST, &t0, &t1);
	t0 ^= l1;
	t1 ^= l0;
	clmul64(t0, POLYVAL_REDUCTION_CONST, &l0, &l1);
	l0 ^= t1;
	l1 ^= t0;
	*r_lo = l0 ^ h0;
	*r_hi = l1 ^ h1;
}

static void mul_ct64(u32 s[4], const polyval_key *key)
{
	const u64 b_lo = key->h[0] | ((u64)key->h[1] << 32);
	const u64 b_hi = key->h[2] | ((u64)key->h[3] << 32);
	u64 s_lo = s[0] | ((u64)s[1] << 32), s_hi = s[2] | ((u64)s[3] << 32);

	pv_mul_portable(s_lo, s_hi, b_lo, b_hi, &s_lo, &s_hi);
	s[0] = (u32)s_lo;
	s[1] = (u32)(s_lo >> 32);
	s[2] = (u32)s_hi;
	s[3] = (u32)(s_hi >> 32);
}

#endif /* POLYVAL_WITH_CT64 */

/* ---------------- POLYVAL_IMPL_TABLE4 / TABLE8 (Shoup) ---------------- */

/* GHASH reduction for the k bits shifted out of the low end: R[b] is the
 * top 16 bits of b * x^k (generated by tools/gen_ghash_tables.py; the 4-bit
 * table equals mbed TLS's last4). */
const u16 polyval_r4[16] = {
	0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
	0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0,
};
const u16 polyval_r8[256] = {
	0x0000, 0x01c2, 0x0384, 0x0246, 0x0708, 0x06ca, 0x048c, 0x054e,
	0x0e10, 0x0fd2, 0x0d94, 0x0c56, 0x0918, 0x08da, 0x0a9c, 0x0b5e,
	0x1c20, 0x1de2, 0x1fa4, 0x1e66, 0x1b28, 0x1aea, 0x18ac, 0x196e,
	0x1230, 0x13f2, 0x11b4, 0x1076, 0x1538, 0x14fa, 0x16bc, 0x177e,
	0x3840, 0x3982, 0x3bc4, 0x3a06, 0x3f48, 0x3e8a, 0x3ccc, 0x3d0e,
	0x3650, 0x3792, 0x35d4, 0x3416, 0x3158, 0x309a, 0x32dc, 0x331e,
	0x2460, 0x25a2, 0x27e4, 0x2626, 0x2368, 0x22aa, 0x20ec, 0x212e,
	0x2a70, 0x2bb2, 0x29f4, 0x2836, 0x2d78, 0x2cba, 0x2efc, 0x2f3e,
	0x7080, 0x7142, 0x7304, 0x72c6, 0x7788, 0x764a, 0x740c, 0x75ce,
	0x7e90, 0x7f52, 0x7d14, 0x7cd6, 0x7998, 0x785a, 0x7a1c, 0x7bde,
	0x6ca0, 0x6d62, 0x6f24, 0x6ee6, 0x6ba8, 0x6a6a, 0x682c, 0x69ee,
	0x62b0, 0x6372, 0x6134, 0x60f6, 0x65b8, 0x647a, 0x663c, 0x67fe,
	0x48c0, 0x4902, 0x4b44, 0x4a86, 0x4fc8, 0x4e0a, 0x4c4c, 0x4d8e,
	0x46d0, 0x4712, 0x4554, 0x4496, 0x41d8, 0x401a, 0x425c, 0x439e,
	0x54e0, 0x5522, 0x5764, 0x56a6, 0x53e8, 0x522a, 0x506c, 0x51ae,
	0x5af0, 0x5b32, 0x5974, 0x58b6, 0x5df8, 0x5c3a, 0x5e7c, 0x5fbe,
	0xe100, 0xe0c2, 0xe284, 0xe346, 0xe608, 0xe7ca, 0xe58c, 0xe44e,
	0xef10, 0xeed2, 0xec94, 0xed56, 0xe818, 0xe9da, 0xeb9c, 0xea5e,
	0xfd20, 0xfce2, 0xfea4, 0xff66, 0xfa28, 0xfbea, 0xf9ac, 0xf86e,
	0xf330, 0xf2f2, 0xf0b4, 0xf176, 0xf438, 0xf5fa, 0xf7bc, 0xf67e,
	0xd940, 0xd882, 0xdac4, 0xdb06, 0xde48, 0xdf8a, 0xddcc, 0xdc0e,
	0xd750, 0xd692, 0xd4d4, 0xd516, 0xd058, 0xd19a, 0xd3dc, 0xd21e,
	0xc560, 0xc4a2, 0xc6e4, 0xc726, 0xc268, 0xc3aa, 0xc1ec, 0xc02e,
	0xcb70, 0xcab2, 0xc8f4, 0xc936, 0xcc78, 0xcdba, 0xcffc, 0xce3e,
	0x9180, 0x9042, 0x9204, 0x93c6, 0x9688, 0x974a, 0x950c, 0x94ce,
	0x9f90, 0x9e52, 0x9c14, 0x9dd6, 0x9898, 0x995a, 0x9b1c, 0x9ade,
	0x8da0, 0x8c62, 0x8e24, 0x8fe6, 0x8aa8, 0x8b6a, 0x892c, 0x88ee,
	0x83b0, 0x8272, 0x8034, 0x81f6, 0x84b8, 0x857a, 0x873c, 0x86fe,
	0xa9c0, 0xa802, 0xaa44, 0xab86, 0xaec8, 0xaf0a, 0xad4c, 0xac8e,
	0xa7d0, 0xa612, 0xa454, 0xa596, 0xa0d8, 0xa11a, 0xa35c, 0xa29e,
	0xb5e0, 0xb422, 0xb664, 0xb7a6, 0xb2e8, 0xb32a, 0xb16c, 0xb0ae,
	0xbbf0, 0xba32, 0xb874, 0xb9b6, 0xbcf8, 0xbd3a, 0xbf7c, 0xbebe,
};

#if POLYVAL_WITH_TABLE4 || POLYVAL_WITH_TABLE8
/* v = v * x in GHASH's bit order (right shift), constant-time. */
static void ghash_mulx(u32 v[4])
{
	const u32 m = 0u - (v[0] & 1u);

	v[0] = (v[0] >> 1) | (v[1] << 31);
	v[1] = (v[1] >> 1) | (v[2] << 31);
	v[2] = (v[2] >> 1) | (v[3] << 31);
	v[3] = (v[3] >> 1) ^ (m & 0xE1000000u);
}

/* Multiples of H' = mulX_GHASH(H) for an n-bit window (n = 4 or 8): entry
 * 2^(n-1) is H' (coefficient x^0), entry 2^(n-1-j) is H' x^j, and the other
 * entries are XOR combinations. */
static void ghash_table(u32 (*t)[4], int nbits, const u32 h[4])
{
	const int top = 1 << (nbits - 1);
	int i, j, w;

	memcpy(t[top], h, 16);
	ghash_mulx(t[top]); /* H' */
	for (i = top >> 1; i >= 1; i >>= 1) {
		memcpy(t[i], t[2 * i], 16);
		ghash_mulx(t[i]);
	}
	memset(t[0], 0, 16);
	for (i = 2; i <= top; i <<= 1)
		for (j = 1; j < i; j++)
			for (w = 0; w < 4; w++)
				t[i + j][w] = t[i][w] ^ t[j][w];
}

#endif

#define SHR_ZW(z, k, r)                                                        \
	do {                                                                   \
		z##0 = (z##0 >> (k)) | (z##1 << (32 - (k)));                   \
		z##1 = (z##1 >> (k)) | (z##2 << (32 - (k)));                   \
		z##2 = (z##2 >> (k)) | (z##3 << (32 - (k)));                   \
		z##3 = (z##3 >> (k)) ^ ((u32)(r) << 16);                       \
	} while (0)

#if POLYVAL_WITH_TABLE8
static void update_table8(u32 s[4], const polyval_key *key, const u8 *data,
			  size_t nblocks)
{
	const u32(*t)[4] = key->u.t8;
	u8 v[16];
	int k;

	while (nblocks--) {
		u32 z0, z1, z2, z3, rem;

		for (k = 0; k < 4; k++)
			store_le32(v + 4 * k, s[k] ^ load_le32(data + 4 * k));
		/* Horner from the highest-degree byte (byte 0 of the integer) */
		z0 = t[v[0]][0];
		z1 = t[v[0]][1];
		z2 = t[v[0]][2];
		z3 = t[v[0]][3];
		for (k = 1; k < 16; k++) {
			const u32 *m = t[v[k]];

			rem = z0 & 0xff;
			SHR_ZW(z, 8, polyval_r8[rem]);
			z0 ^= m[0];
			z1 ^= m[1];
			z2 ^= m[2];
			z3 ^= m[3];
		}
		s[0] = z0;
		s[1] = z1;
		s[2] = z2;
		s[3] = z3;
		data += 16;
	}
}
#endif

#if POLYVAL_WITH_TABLE4
static void update_table4(u32 s[4], const polyval_key *key, const u8 *data,
			  size_t nblocks)
{
	const u32(*t)[4] = key->u.t4;
	u8 v[16];
	int k;

	while (nblocks--) {
		u32 z0, z1, z2, z3, rem;

		for (k = 0; k < 4; k++)
			store_le32(v + 4 * k, s[k] ^ load_le32(data + 4 * k));
		/* low nibble of each byte first (higher-degree coefficients) */
		z0 = t[v[0] & 15][0];
		z1 = t[v[0] & 15][1];
		z2 = t[v[0] & 15][2];
		z3 = t[v[0] & 15][3];
		for (k = 1; k < 32; k++) {
			const u32 *m = t[(v[k >> 1] >> (4 * (k & 1))) & 15];

			rem = z0 & 0xf;
			SHR_ZW(z, 4, polyval_r4[rem]);
			z0 ^= m[0];
			z1 ^= m[1];
			z2 ^= m[2];
			z3 ^= m[3];
		}
		s[0] = z0;
		s[1] = z1;
		s[2] = z2;
		s[3] = z3;
		data += 16;
	}
}
#endif

/* ---------------- common ---------------- */

void polyval_setkey(polyval_key *key, const u8 h[16], int impl)
{
	int i;

	key->impl = impl;
	for (i = 0; i < 4; i++)
		key->h[i] = load_le32(h + 4 * i);
	switch (impl) {
#if POLYVAL_WITH_CT32
	case POLYVAL_IMPL_CT32:
		/* Karatsuba operands: low half, high half, and their sum, each
		 * split into (w0, w1, w0^w1). */
		mask4(key->u.hm[0], key->h[0]);
		mask4(key->u.hm[1], key->h[1]);
		mask4(key->u.hm[2], key->h[0] ^ key->h[1]);
		mask4(key->u.hm[3], key->h[2]);
		mask4(key->u.hm[4], key->h[3]);
		mask4(key->u.hm[5], key->h[2] ^ key->h[3]);
		mask4(key->u.hm[6], key->h[0] ^ key->h[2]);
		mask4(key->u.hm[7], key->h[1] ^ key->h[3]);
		mask4(key->u.hm[8], key->h[0] ^ key->h[1] ^ key->h[2] ^ key->h[3]);
		break;
#endif
#if POLYVAL_WITH_CT64
	case POLYVAL_IMPL_CT64:
		break;
#endif
#if POLYVAL_WITH_TABLE4
	case POLYVAL_IMPL_TABLE4:
		ghash_table(key->u.t4, 4, key->h);
		break;
#endif
#if POLYVAL_WITH_TABLE8
	case POLYVAL_IMPL_TABLE8:
		ghash_table(key->u.t8, 8, key->h);
		break;
#endif
	default:
		platform_panic("POLYVAL implementation not built", __FILE__, __LINE__);
	}
}

void polyval_update(polyval_state *st, const polyval_key *key, const u8 *data,
		    size_t nblocks)
{
	u32 s[4];
	int i;

#if POLYVAL_WITH_TABLE8
	if (key->impl == POLYVAL_IMPL_TABLE8) {
		update_table8(st->s, key, data, nblocks);
		return;
	}
#endif
#if POLYVAL_WITH_TABLE4
	if (key->impl == POLYVAL_IMPL_TABLE4) {
		update_table4(st->s, key, data, nblocks);
		return;
	}
#endif
	memcpy(s, st->s, sizeof(s));
	while (nblocks--) {
		for (i = 0; i < 4; i++)
			s[i] ^= load_le32(data + 4 * i);
#if POLYVAL_WITH_CT64
		if (!POLYVAL_WITH_CT32 || key->impl == POLYVAL_IMPL_CT64)
			mul_ct64(s, key);
		else
#endif
#if POLYVAL_WITH_CT32
			mul_ct32(s, key);
#else
			;
#endif
		data += 16;
	}
	memcpy(st->s, s, sizeof(s));
}

void polyval_emit(const polyval_state *st, u8 out[16])
{
	int i;

	for (i = 0; i < 4; i++)
		store_le32(out + 4 * i, st->s[i]);
}
