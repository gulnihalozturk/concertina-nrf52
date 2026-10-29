#include "keccak.h"

/* ---------------- KECCAK_IMPL_REF64: 64-bit lanes ---------------- */

static const u64 RC[24] = {
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
	0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
	0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
	0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
	0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
	0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
	0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
	0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

#define ROL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))
/* Only KECCAK_ROUND_SCALAR is used; the file also defines the ARMv8.2-SHA3
 * macro of the original repository, which is never expanded here. */
#include "keccak_round.inc"

#define DECLARE_LANES(T_)                                                      \
	T_ A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14,    \
		A15, A16, A17, A18, A19, A20, A21, A22, A23, A24;              \
	T_ C0, C1, C2, C3, C4, D0, D1, D2, D3, D4, T, BC

#define LANE_LIST(M)                                                           \
	M(0) M(1) M(2) M(3) M(4) M(5) M(6) M(7) M(8) M(9) M(10) M(11) M(12)    \
	M(13) M(14) M(15) M(16) M(17) M(18) M(19) M(20) M(21) M(22) M(23) M(24)
#define RATE_LIST(M)                                                           \
	M(0) M(1) M(2) M(3) M(4) M(5) M(6) M(7) M(8) M(9) M(10) M(11) M(12)    \
	M(13) M(14) M(15) M(16)

#define S_LOAD(i) A##i = st[i];
#define S_STORE(i) st[i] = A##i;
#define S_XOR_IN(i) A##i ^= load_le64(in + 8 * i);

static void absorb_ref64(u64 st[25], const u8 *in, size_t nblocks,
			 int permute_only)
{
	DECLARE_LANES(u64);
	int r;

	LANE_LIST(S_LOAD)
	do {
		if (!permute_only) {
			RATE_LIST(S_XOR_IN)
			in += SHA3_256_RATE;
		}
		for (r = 0; r < 24; r++)
			KECCAK_ROUND_SCALAR(RC[r]);
	} while (--nblocks);
	LANE_LIST(S_STORE)
}

void keccak_f1600_ref64(u64 st[25]) { absorb_ref64(st, NULL, 1, 1); }

/* ---------------- KECCAK_IMPL_BI32: bit-interleaved 32-bit ---------------- */

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#include "keccak_bi32.inc"

void keccak_f1600_bi32(u32 st[50])
{
	u32 tmp[50];
	int r;

	for (r = 0; r < 24; r += 2) {
		keccak_round_bi32(tmp, st, KECCAK_RC_BI[r][0], KECCAK_RC_BI[r][1]);
		keccak_round_bi32(st, tmp, KECCAK_RC_BI[r + 1][0],
				  KECCAK_RC_BI[r + 1][1]);
	}
}

/* Even bits of x to the low half, odd bits to the high half. */
FORCEINLINE u32 unshuffle(u32 x)
{
	u32 t;

	t = (x ^ (x >> 1)) & 0x22222222u;
	x ^= t ^ (t << 1);
	t = (x ^ (x >> 2)) & 0x0c0c0c0cu;
	x ^= t ^ (t << 2);
	t = (x ^ (x >> 4)) & 0x00f000f0u;
	x ^= t ^ (t << 4);
	t = (x ^ (x >> 8)) & 0x0000ff00u;
	x ^= t ^ (t << 8);
	return x;
}

FORCEINLINE u32 shuffle(u32 x)
{
	u32 t;

	t = (x ^ (x >> 8)) & 0x0000ff00u;
	x ^= t ^ (t << 8);
	t = (x ^ (x >> 4)) & 0x00f000f0u;
	x ^= t ^ (t << 4);
	t = (x ^ (x >> 2)) & 0x0c0c0c0cu;
	x ^= t ^ (t << 2);
	t = (x ^ (x >> 1)) & 0x22222222u;
	x ^= t ^ (t << 1);
	return x;
}

/* Lane (lo = bits 0..31, hi = bits 32..63) to its even and odd words. */
FORCEINLINE void to_bi(u32 lo, u32 hi, u32 *e, u32 *o)
{
	lo = unshuffle(lo);
	hi = unshuffle(hi);
	*e = (lo & 0x0000ffffu) | (hi << 16);
	*o = (lo >> 16) | (hi & 0xffff0000u);
}

FORCEINLINE void from_bi(u32 e, u32 o, u32 *lo, u32 *hi)
{
	*lo = shuffle((e & 0x0000ffffu) | (o << 16));
	*hi = shuffle((e >> 16) | (o & 0xffff0000u));
}

void keccak_to_bi32(u32 out[50], const u64 in[25])
{
	int i;

	for (i = 0; i < 25; i++)
		to_bi((u32)in[i], (u32)(in[i] >> 32), &out[2 * i], &out[2 * i + 1]);
}

void keccak_from_bi32(u64 out[25], const u32 in[50])
{
	int i;

	for (i = 0; i < 25; i++) {
		u32 lo, hi;

		from_bi(in[2 * i], in[2 * i + 1], &lo, &hi);
		out[i] = ((u64)hi << 32) | lo;
	}
}

static void absorb_bi32(u32 st[50], const u8 *in, size_t nblocks)
{
	int i;

	do {
		for (i = 0; i < SHA3_256_RATE / 8; i++) {
			u32 e, o;

			to_bi(load_le32(in + 8 * i), load_le32(in + 8 * i + 4), &e, &o);
			st[2 * i] ^= e;
			st[2 * i + 1] ^= o;
		}
		keccak_f1600_bi32(st);
		in += SHA3_256_RATE;
	} while (--nblocks);
}

/* ---------------- common sponge code ---------------- */

static void absorb(keccak_state *st, const u8 *in, size_t nblocks, int impl)
{
	if (!nblocks)
		return;
	if (KECCAK_WITH_REF64 && impl == KECCAK_IMPL_REF64)
		absorb_ref64(st->q, in, nblocks, 0);
	else
		absorb_bi32(st->w, in, nblocks);
}

static void squeeze32(const keccak_state *st, u8 out[32], int impl)
{
	int i;

	for (i = 0; i < 4; i++) {
		if (KECCAK_WITH_REF64 && impl == KECCAK_IMPL_REF64) {
			store_le64(out + 8 * i, st->q[i]);
		} else {
			u32 lo, hi;

			from_bi(st->w[2 * i], st->w[2 * i + 1], &lo, &hi);
			store_le32(out + 8 * i, lo);
			store_le32(out + 8 * i + 4, hi);
		}
	}
}

/* Absorbs the final (partial) block with the SHA-3 padding 0x06 ... 0x80. */
static void absorb_final(keccak_state *st, const u8 *p, size_t len, int impl)
{
	u8 last[SHA3_256_RATE] = {0};

	memcpy(last, p, len);
	last[len] ^= 0x06;
	last[SHA3_256_RATE - 1] ^= 0x80;
	absorb(st, last, 1, impl);
}

void sha3_256(const u8 *msg, size_t len, u8 out[32], int impl)
{
	keccak_state st;
	const size_t nfull = len / SHA3_256_RATE;

	memset(&st, 0, sizeof(st));
	absorb(&st, msg, nfull, impl);
	absorb_final(&st, msg + nfull * SHA3_256_RATE, len - nfull * SHA3_256_RATE,
		     impl);
	squeeze32(&st, out, impl);
}

void hmac_sha3_256_setkey(hmac_sha3_256_key *k, const u8 *key, size_t key_len,
			  int impl)
{
	u8 kb[SHA3_256_RATE] = {0}, pad[SHA3_256_RATE];
	int i;

	if (key_len > SHA3_256_RATE)
		sha3_256(key, key_len, kb, impl);
	else
		memcpy(kb, key, key_len);
	k->impl = impl;
	memset(&k->inner, 0, sizeof(k->inner));
	memset(&k->outer, 0, sizeof(k->outer));
	for (i = 0; i < SHA3_256_RATE; i++)
		pad[i] = kb[i] ^ 0x36;
	absorb(&k->inner, pad, 1, impl);
	for (i = 0; i < SHA3_256_RATE; i++)
		pad[i] = kb[i] ^ 0x5c;
	absorb(&k->outer, pad, 1, impl);
	wipe(kb, sizeof(kb));
	wipe(pad, sizeof(pad));
}

void hmac_sha3_256(const hmac_sha3_256_key *k, const u8 *a, size_t a_len,
		   const u8 *b, size_t b_len, u8 out[32])
{
	keccak_state st;
	u8 buf[2 * SHA3_256_RATE], ih[32];
	const size_t nfull = a_len / SHA3_256_RATE;
	const size_t rem = a_len - nfull * SHA3_256_RATE;
	size_t n;
	const u8 *p = buf;

	CHECK(b_len <= 64);
	st = k->inner;
	absorb(&st, a, nfull, k->impl);
	memcpy(buf, a + nfull * SHA3_256_RATE, rem);
	if (b_len)
		memcpy(buf + rem, b, b_len);
	n = rem + b_len;
	if (n >= SHA3_256_RATE) {
		absorb(&st, buf, 1, k->impl);
		p += SHA3_256_RATE;
		n -= SHA3_256_RATE;
	}
	absorb_final(&st, p, n, k->impl);
	squeeze32(&st, ih, k->impl);

	st = k->outer;
	absorb_final(&st, ih, 32, k->impl);
	squeeze32(&st, out, k->impl);
}
