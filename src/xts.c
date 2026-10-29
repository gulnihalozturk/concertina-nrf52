#include "platform.h"
#include "xts.h"

void xts_setkey(xts_ctx *c, const u8 *key, size_t key_len, int aes_impl)
{
	aes_setkey(&c->k1, key, key_len / 2, aes_impl);
	aes_setkey(&c->k2, key + key_len / 2, key_len / 2, aes_impl);
	aes_setkey_dec(&c->d1, key, key_len / 2,
		       aes_impl == AES_IMPL_CC310 ? AES_IMPL_CC310 : AES_IMPL_SW);
}

/* Multiplication by alpha in GF(2^128), little-endian (IEEE 1619). */
static void mul_alpha(u8 t[16])
{
	u64 lo = load_le64(t), hi = load_le64(t + 8);
	const u64 carry = hi >> 63;

	hi = (hi << 1) | (lo >> 63);
	lo = (lo << 1) ^ (0x87 & (0 - carry));
	store_le64(t, lo);
	store_le64(t + 8, hi);
}

#if AES_WITH_CC310
/* CryptoCell: the tweaks of up to 16 blocks are computed first, and the
 * blocks go through the engine in one ECB transfer. */
static void xts_crypt_cc310(const xts_ctx *c, u8 *dst, const u8 *src, size_t len,
			    u8 t[16], int encrypt)
{
	static u8 buf[256] __attribute__((aligned(4)));
	u8 tw[256];
	const u8 *key = encrypt ? c->k1.key : c->d1.key;

	while (len) {
		const size_t n = len < sizeof(buf) ? len : sizeof(buf);
		size_t u;

		for (u = 0; u < n; u += 16) {
			memcpy(tw + u, t, 16);
			mul_alpha(t);
		}
		xor_bytes(buf, src, tw, n);
		platform_cc310_aes_ecb(key, !encrypt, buf, buf, n);
		xor_bytes(dst, buf, tw, n);
		src += n;
		dst += n;
		len -= n;
	}
	wipe(buf, sizeof(buf));
	wipe(tw, sizeof(tw));
}
#endif

void xts_crypt(const xts_ctx *c, u8 *dst, const u8 *src, size_t len,
	       const u8 iv[16], int encrypt)
{
	u8 t[16], b[16];

	CHECK(len >= 16 && len % 16 == 0);
	aes_encrypt(&c->k2, t, iv);
#if AES_WITH_CC310
	if (c->k1.impl == AES_IMPL_CC310 && (encrypt || c->d1.impl == AES_IMPL_CC310)) {
		xts_crypt_cc310(c, dst, src, len, t, encrypt);
		wipe(t, sizeof(t));
		return;
	}
#endif
	while (len) {
		xor_bytes(b, src, t, 16);
		if (encrypt)
			aes_encrypt(&c->k1, b, b);
		else
			aes_decrypt(&c->d1, b, b);
		xor_bytes(dst, b, t, 16);
		mul_alpha(t);
		src += 16;
		dst += 16;
		len -= 16;
	}
	wipe(t, sizeof(t));
	wipe(b, sizeof(b));
}

void xts_wipe(xts_ctx *c) { wipe(c, sizeof(*c)); }
