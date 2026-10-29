#include "scheme.h"

enum { ROLE_TWEAK = 0x00, ROLE_CTEXT = 0x01, ROLE_PTEXT = 0x02 };

static void hkey_set(scheme_hkey *k, int hash, const u8 *key, size_t len,
		     int impl)
{
	(void)hash;
#if SCHEME_WITH_SHA3
	if (SCHEME_USE_SHA3(hash)) {
		hmac_sha3_256_setkey(&k->s3, key, len, impl);
		return;
	}
#endif
#if SCHEME_WITH_SHA256
	hmac_sha256_setkey(&k->s2, key, len, impl);
#endif
}

static void mac_raw(int hash, const scheme_hkey *k, const u8 *a, size_t a_len,
		    const u8 *b, size_t b_len, u8 out[32])
{
	(void)hash;
#if SCHEME_WITH_SHA3
	if (SCHEME_USE_SHA3(hash)) {
		hmac_sha3_256(&k->s3, a, a_len, b, b_len, out);
		return;
	}
#endif
#if SCHEME_WITH_SHA256
	hmac_sha256(&k->s2, a, a_len, b, b_len, out);
#endif
}

void scheme_setkey(scheme_ctx *c, const u8 *master_key, size_t key_len,
		   int hash, int hash_impl, int aes_impl)
{
	static const char *const labels[6] = {"1", "2", "3", "4", "ctr", "hash"};
	/* Lengths as constants rather than strlen(), so that the cost of the key
	 * setup does not depend on where the linker places the strings. */
	static const u8 label_len[6] = {1, 1, 1, 1, 3, 4};
	const size_t name_len = sizeof(SCHEME_NAME) - 1;
	scheme_hkey mk;
	u8 msg[64], out[32], keys[6][32];
	int u;

	CHECK(key_len == 16 || key_len == 24 || key_len == 32);
	CHECK((hash == SCHEME_HMAC_SHA3_256 && SCHEME_WITH_SHA3) ||
	      (hash == SCHEME_HMAC_SHA256 && SCHEME_WITH_SHA256));
	c->hash = hash;
	hkey_set(&mk, hash, master_key, key_len, hash_impl);

	for (u = 0; u < 6; u++) {
		size_t n = 0, lab = name_len + 1 + label_len[u];

		CHECK(lab + 9 <= sizeof(msg));
		store_be32(msg, 1);
		n = 4;
		memcpy(msg + n, SCHEME_NAME, name_len);
		n += name_len;
		msg[n++] = '/';
		memcpy(msg + n, labels[u], label_len[u]);
		n += label_len[u];
		msg[n++] = 0x00;
		store_be32(msg + n, (u32)(8 * key_len));
		n += 4;
		mac_raw(hash, &mk, msg, n, NULL, 0, out);
		memcpy(keys[u], out, key_len);
	}
	for (u = 0; u < 4; u++)
		aes_setkey(&c->k[u], keys[u], key_len, aes_impl);
	aes_setkey(&c->kctr, keys[4], key_len, aes_impl);
	hkey_set(&c->hk, hash, keys[5], key_len, hash_impl);
	wipe(keys, sizeof(keys));
	wipe(&mk, sizeof(mk));
	wipe(out, sizeof(out));
}

/* x = H(tail || role || T), 32 bytes (two 128-bit halves). */
static void mask(const scheme_ctx *c, const u8 *tail, size_t tail_len,
		 u8 role, const u8 *tweak, u8 x[32])
{
	u8 suffix[1 + SCHEME_TWEAK_LEN];

	suffix[0] = role;
	memcpy(suffix + 1, tweak, SCHEME_TWEAK_LEN);
	mac_raw(c->hash, &c->hk, tail, tail_len, suffix, sizeof(suffix), x);
}

/* The four Feistel rounds, the counter seed and the CTR layer are shared by
 * encryption and decryption; only the direction of the Feistel differs. */
typedef struct {
	u8 a[32], u1[16], u2[16], r[16], l[16], v1[16], v2[16], t[16], S[16];
} work;

FORCEINLINE void xor16(u8 *d, const u8 *a, const u8 *b) { xor_bytes(d, a, b, 16); }

void scheme_encrypt(const scheme_ctx *c, u8 *dst, const u8 *src, size_t len,
		    const u8 tweak[SCHEME_TWEAK_LEN])
{
	work w;
	const size_t tl = len - 32;

	CHECK(len >= SCHEME_MIN_LEN);
	mask(c, src + 32, tl, ROLE_PTEXT, tweak, w.a);
	xor16(w.u1, src, w.a);
	xor16(w.u2, src + 16, w.a + 16);

	aes_encrypt(&c->k[0], w.t, w.u1);
	xor16(w.r, w.u2, w.t);
	aes_encrypt(&c->k[1], w.t, w.r);
	xor16(w.l, w.u1, w.t);
	aes_encrypt(&c->k[2], w.t, w.l);
	xor16(w.v2, w.r, w.t);
	aes_encrypt(&c->k[3], w.t, w.v2);
	xor16(w.v1, w.l, w.t);

	xor16(w.S, w.u1, w.u2);
	xor16(w.S, w.S, w.v1);
	xor16(w.S, w.S, w.v2);
	aes_ctr_be_xor(&c->kctr, w.S, src + 32, dst + 32, tl);

	mask(c, dst + 32, tl, ROLE_CTEXT, tweak, w.a);
	xor16(dst, w.v1, w.a);
	xor16(dst + 16, w.v2, w.a + 16);
	wipe(&w, sizeof(w));
}

void scheme_decrypt(const scheme_ctx *c, u8 *dst, const u8 *src, size_t len,
		    const u8 tweak[SCHEME_TWEAK_LEN])
{
	work w;
	const size_t tl = len - 32;

	CHECK(len >= SCHEME_MIN_LEN);
	mask(c, src + 32, tl, ROLE_CTEXT, tweak, w.a);
	xor16(w.v1, src, w.a);
	xor16(w.v2, src + 16, w.a + 16);

	aes_encrypt(&c->k[3], w.t, w.v2);
	xor16(w.l, w.v1, w.t);
	aes_encrypt(&c->k[2], w.t, w.l);
	xor16(w.r, w.v2, w.t);
	aes_encrypt(&c->k[1], w.t, w.r);
	xor16(w.u1, w.l, w.t);
	aes_encrypt(&c->k[0], w.t, w.u1);
	xor16(w.u2, w.r, w.t);

	xor16(w.S, w.u1, w.u2);
	xor16(w.S, w.S, w.v1);
	xor16(w.S, w.S, w.v2);
	aes_ctr_be_xor(&c->kctr, w.S, src + 32, dst + 32, tl);

	mask(c, dst + 32, tl, ROLE_PTEXT, tweak, w.a);
	xor16(dst, w.u1, w.a);
	xor16(dst + 16, w.u2, w.a + 16);
	wipe(&w, sizeof(w));
}

void scheme_wipe(scheme_ctx *c) { wipe(c, sizeof(*c)); }
