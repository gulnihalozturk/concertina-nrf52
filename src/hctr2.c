#include "hctr2.h"

static void first_block_state(const hctr2_ctx *c, polyval_state *st,
			      size_t tweak_len, int divisible)
{
	u8 blk[16] = {0};

	store_le64(blk, (u64)tweak_len * 8 * 2 + (divisible ? 2 : 3));
	polyval_init(st);
	polyval_update(st, &c->pv, blk, 1);
}

void hctr2_setkey(hctr2_ctx *c, const u8 *key, size_t key_len,
		  int polyval_impl, int aes_impl, int aes_dec_impl)
{
	u8 h[16] = {0}, one[16] = {0};

	aes_setkey(&c->aes, key, key_len, aes_impl);
	aes_setkey_dec(&c->aes_dec, key, key_len, aes_dec_impl);
	aes_encrypt(&c->aes, h, h);
	one[0] = 0x01;
	aes_encrypt(&c->aes, c->L, one);
	polyval_setkey(&c->pv, h, polyval_impl);
	first_block_state(c, &c->init[0], HCTR2_DEFAULT_TWEAK_LEN, 0);
	first_block_state(c, &c->init[1], HCTR2_DEFAULT_TWEAK_LEN, 1);
	wipe(h, sizeof(h));
}

static void hash_padded(const hctr2_ctx *c, polyval_state *st, const u8 *data,
			size_t len, int one_pad)
{
	const size_t nblocks = len / 16, rem = len % 16;

	polyval_update(st, &c->pv, data, nblocks);
	if (rem) {
		u8 blk[16] = {0};

		memcpy(blk, data + 16 * nblocks, rem);
		if (one_pad)
			blk[rem] = 0x01;
		polyval_update(st, &c->pv, blk, 1);
	}
}

void hctr2_crypt(const hctr2_ctx *c, u8 *dst, const u8 *src, size_t len,
		 const u8 *tweak, size_t tweak_len, int encrypt)
{
	polyval_state st1, st2;
	u8 digest[16], MM[16], UU[16], S[16];
	const size_t n_len = len - 16;
	const int divisible = (n_len % 16) == 0;

	CHECK(len >= 16);
	if (tweak_len == HCTR2_DEFAULT_TWEAK_LEN)
		st1 = c->init[divisible];
	else
		first_block_state(c, &st1, tweak_len, divisible);
	hash_padded(c, &st1, tweak, tweak_len, 0);
	st2 = st1;

	hash_padded(c, &st1, src + 16, n_len, 1);
	polyval_emit(&st1, digest);
	xor_bytes(MM, src, digest, 16);

	if (encrypt)
		aes_encrypt(&c->aes, UU, MM);
	else
		aes_decrypt(&c->aes_dec, UU, MM);

	xor_bytes(S, MM, UU, 16);
	xor_bytes(S, S, c->L, 16);
	aes_xctr_xor(&c->aes, S, src + 16, dst + 16, n_len);

	hash_padded(c, &st2, dst + 16, n_len, 1);
	polyval_emit(&st2, digest);
	xor_bytes(dst, UU, digest, 16);
	wipe(MM, sizeof(MM));
	wipe(UU, sizeof(UU));
	wipe(S, sizeof(S));
}

void hctr2_wipe(hctr2_ctx *c) { wipe(c, sizeof(*c)); }
