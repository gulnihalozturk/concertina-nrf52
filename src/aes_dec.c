/*
 * AES inverse cipher, needed by HCTR2 (one block per decryption) and AES-XTS,
 * not by Concertina. Dispatches to one of three backends (see aes.h):
 *   AES_IMPL_SW    - table implementation below: same column-word layout as
 *                    aes.c, a single 1 KiB table with rotations and the
 *                    inverse S-box, built in RAM on first use;
 *   AES_IMPL_CT    - constant-time bitsliced implementation (aes_ct.c);
 *   AES_IMPL_CC310 - CryptoCell-310 decryption (nRF52840).
 *
 * Td[x] = InvMixColumns((InvS(x), 0, 0, 0)) = 14s | 9s << 8 | 13s << 16 | 11s << 24
 * A byte in row r contributes ROL32(Td[x], 8r); InvShiftRows takes row r of
 * output column j from input column j - r.
 */
#include "aes.h"
#include "platform.h"

#if AES_DEC_TABLE
#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#if AES_TABLES_IN_FLASH
#define AES_TABLES_WANT_TD
#include "aes_tables.inc"
#define td_ready 1
#define build_tables() ((void)0)
#else
static u32 Td[256];
static u8 inv_sbox[256];
static int td_ready;

#define ROTL8(x, s) ((u8)(((x) << (s)) | ((x) >> (8 - (s)))))

static u32 xtime(u32 x) { return ((x << 1) ^ ((x & 0x80) ? 0x1b : 0)) & 0xff; }

/* GF(2^8) product with a small constant (used only to build the table). */
static u32 gmul(u32 x, u32 c)
{
	u32 r = 0;

	while (c) {
		if (c & 1)
			r ^= x;
		x = xtime(x);
		c >>= 1;
	}
	return r;
}

static void build_tables(void)
{
	u8 p = 1, q = 1;
	int i;

	do {
		p = (u8)(p ^ (u8)(p << 1) ^ ((p & 0x80) ? 0x1b : 0));
		q ^= (u8)(q << 1);
		q ^= (u8)(q << 2);
		q ^= (u8)(q << 4);
		if (q & 0x80)
			q ^= 0x09;
		inv_sbox[(u8)(q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^
			      ROTL8(q, 4) ^ 0x63)] = p;
	} while (p != 1);
	inv_sbox[0x63] = 0;
	for (i = 0; i < 256; i++) {
		const u32 s = inv_sbox[i];

		Td[i] = gmul(s, 14) | (gmul(s, 9) << 8) | (gmul(s, 13) << 16) |
			(gmul(s, 11) << 24);
	}
	td_ready = 1;
}
#endif /* AES_TABLES_IN_FLASH */

#define D0(x) Td[(x) & 0xff]
#define D1(x) ROL32(Td[((x) >> 8) & 0xff], 8)
#define D2(x) ROL32(Td[((x) >> 16) & 0xff], 16)
#define D3(x) ROL32(Td[(x) >> 24], 24)

/* InvMixColumns(w) = sum of Td[S(byte)], since Td[y] = InvMixColumns(InvS(y)). */
static u32 inv_mix_column(u32 w)
{
	const u32 s = aes_sub_word(w);

	return D0(s) ^ D1(s) ^ D2(s) ^ D3(s);
}

static int setkey_table(aes_dec_key *k, const u8 *key, size_t key_len)
{
	u32 rk[4 * (AES_MAX_NR + 1)];
	int i, j, nr;

	if (!td_ready)
		build_tables();
	nr = k->nr = aes_expand_key(rk, key, key_len);
	for (j = 0; j < 4; j++) {
		k->dk[j] = rk[4 * nr + j];
		k->dk[4 * nr + j] = rk[j];
	}
	for (i = 1; i < nr; i++)
		for (j = 0; j < 4; j++)
			k->dk[4 * i + j] = inv_mix_column(rk[4 * (nr - i) + j]);
	wipe(rk, sizeof(rk));
	return k->impl = AES_IMPL_SW;
}

static void decrypt_table(const aes_dec_key *k, u8 out[16], const u8 in[16])
{
	const u32 *dk = k->dk;
	u32 s0 = load_le32(in) ^ dk[0], s1 = load_le32(in + 4) ^ dk[1];
	u32 s2 = load_le32(in + 8) ^ dk[2], s3 = load_le32(in + 12) ^ dk[3];
	u32 t0, t1, t2, t3;
	int r;

	for (r = 1; r < k->nr; r++) {
		dk += 4;
		t0 = D0(s0) ^ D1(s3) ^ D2(s2) ^ D3(s1) ^ dk[0];
		t1 = D0(s1) ^ D1(s0) ^ D2(s3) ^ D3(s2) ^ dk[1];
		t2 = D0(s2) ^ D1(s1) ^ D2(s0) ^ D3(s3) ^ dk[2];
		t3 = D0(s3) ^ D1(s2) ^ D2(s1) ^ D3(s0) ^ dk[3];
		s0 = t0;
		s1 = t1;
		s2 = t2;
		s3 = t3;
	}
	dk += 4;
#define LAST(a, b, c, d)                                                       \
	((u32)inv_sbox[(a) & 0xff] | ((u32)inv_sbox[((b) >> 8) & 0xff] << 8) |  \
	 ((u32)inv_sbox[((c) >> 16) & 0xff] << 16) |                           \
	 ((u32)inv_sbox[(d) >> 24] << 24))
	store_le32(out, LAST(s0, s3, s2, s1) ^ dk[0]);
	store_le32(out + 4, LAST(s1, s0, s3, s2) ^ dk[1]);
	store_le32(out + 8, LAST(s2, s1, s0, s3) ^ dk[2]);
	store_le32(out + 12, LAST(s3, s2, s1, s0) ^ dk[3]);
#undef LAST
}
#endif /* AES_DEC_TABLE */

int aes_setkey_dec(aes_dec_key *k, const u8 *key, size_t key_len, int impl)
{
	CHECK(key_len == 16 || key_len == 24 || key_len == 32);
	k->nr = (int)key_len / 4 + 6;
	(void)impl;
#if AES_WITH_CC310
	memset(k->key, 0, sizeof(k->key));
	if (impl == AES_IMPL_CC310 && key_len == 16 && platform_has_cc310()) {
		memcpy(k->key, key, 16);
		return k->impl = AES_IMPL_CC310;
	}
#endif
#if AES_DEC_CT
	if (impl == AES_IMPL_CT || !AES_DEC_TABLE) {
		k->nr = aes_ct_setkey_dec(k->dk, key, key_len);
		return k->impl = AES_IMPL_CT;
	}
#endif
#if AES_DEC_TABLE
	return setkey_table(k, key, key_len);
#else
	platform_panic("no AES decryption backend for this key", __FILE__, __LINE__);
#endif
}

void aes_decrypt(const aes_dec_key *k, u8 out[16], const u8 in[16])
{
#if AES_WITH_CC310
	if (k->impl == AES_IMPL_CC310) {
		platform_cc310_aes_ecb(k->key, 1, in, out, 16);
		return;
	}
#endif
#if AES_DEC_CT
	if (k->impl == AES_IMPL_CT) {
		aes_ct_decrypt(k->dk, k->nr, out, in);
		return;
	}
#endif
#if AES_DEC_TABLE
	decrypt_table(k, out, in);
#else
	(void)k; (void)out; (void)in;
#endif
}
