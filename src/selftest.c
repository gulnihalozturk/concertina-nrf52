/*
 * Self-tests, run on the target before any benchmark. Every backend of the
 * chip is tested through the same functions as the benchmark uses:
 *   AES        - FIPS 197 Appendix C (AES-128/192/256, software); the ECB
 *                peripheral and the CryptoCell against FIPS 197 and the
 *                software AES (single blocks, Concertina's counter, XCTR)
 *   AES^-1     - table, constant-time and CryptoCell inverse ciphers:
 *                FIPS 197 and random round trips
 *   Keccak     - SHA3-256("abc"), SHA3-256(""), bit-interleaved permutation
 *                against the 64-bit reference on random states
 *   SHA-256    - SHA-256("abc"); CryptoCell against software, random lengths
 *   hash, HMAC - 90 known answers from Python hashlib/hmac (kat_generated.h),
 *                at several message split points, every backend
 *   Concertina - 90 known answers from python/scheme_ref.py: every software
 *                hash backend, and the configurations of the two chips
 *                (AES on the ECB peripheral; AES and SHA-256 on the
 *                CryptoCell), out of place and in place
 *   POLYVAL, XCTR, HCTR2 - the official vectors of https://github.com/google/hctr2
 *                (96, 180 and 700): all four POLYVAL implementations, and
 *                the AES configurations of the two chips (encryption and
 *                decryption); the GHASH reduction tables against their
 *                bit-serial definition
 *   AES-XTS    - 14 known answers from Python `cryptography` (kat_generated.h)
 */
#include "selftest.h"
#include "platform.h"
#include "print.h"
#include "arena.h"
#include "hctr2.h"
#include "scheme.h"
#include "testvecs/hctr2_testvecs.h"
#include "testvecs/polyval_testvecs.h"
#include "testvecs/xctr_testvecs.h"
#include "xts.h"

#include "kat_generated.h"

#ifndef SELFTEST_FULL_SPLITS
#define SELFTEST_FULL_SPLITS 0 /* 1: every split point, as on AArch64 */
#endif

static int failures, checks;

#define EXPECT(cond, ...)                                                      \
	do {                                                                   \
		checks++;                                                      \
		if (!(cond)) {                                                 \
			failures++;                                            \
			xprintf("  FAIL: " __VA_ARGS__);                       \
			xprintf("\n");                                         \
		}                                                              \
	} while (0)

static u32 rng_state = 0x2545f491u;

static u32 rnd32(void)
{
	u32 x = rng_state;

	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	return rng_state = x;
}

static void rnd_bytes(u8 *p, size_t n)
{
	while (n--)
		*p++ = (u8)rnd32();
}

static int hexval(char c)
{
	return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10;
}

static int hexeq(const u8 *a, const char *hex, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (a[i] != (u8)(16 * hexval(hex[2 * i]) + hexval(hex[2 * i + 1])))
			return 0;
	return 1;
}

static void report(const char *name, int f0, int c0)
{
	xprintf("  %-44s %s (%d checks)\n", name, failures == f0 ? "ok" : "FAILED",
		checks - c0);
}

static const struct {
	size_t klen;
	const char *ct;
} fips197[] = {{16, "69c4e0d86a7b0430d8cdb78070b4c55a"},
	       {24, "dda97ca4864cdfe06eaf70a0ec0d7191"},
	       {32, "8ea2b7ca516745bfeafc49904b496089"}};

static void unhex(u8 *out, const char *hex, size_t n)
{
	size_t j;

	for (j = 0; j < n; j++)
		out[j] = (u8)(16 * hexval(hex[2 * j]) + hexval(hex[2 * j + 1]));
}

static const char *aes_name(int impl)
{
	static const char *const n[] = {"software", "ECB", "CryptoCell", "constant-time"};

	return n[impl];
}

static void test_aes(void)
{
	u8 *in = arena_a, *o1 = arena_b, *o2 = arena_b + 2048;
	u8 key[32], pt[16], ct[16], back[16];
	size_t i, j;
	aes_key k, kh;
	aes_dec_key kd;
	int f0 = failures, c0 = checks, di, hw;
	static const int dec_impls[3] = {AES_IMPL_SW, AES_IMPL_CT, AES_IMPL_CC310};

	for (j = 0; j < 32; j++)
		key[j] = (u8)j;
	for (j = 0; j < 16; j++)
		pt[j] = (u8)(0x11 * j);
	for (i = 0; i < 3; i++) {
		aes_setkey(&k, key, fips197[i].klen, AES_IMPL_SW);
		aes_encrypt(&k, ct, pt);
		EXPECT(hexeq(ct, fips197[i].ct, 16), "AES-%u (software), FIPS 197",
		       (unsigned)(8 * fips197[i].klen));
	}
	report("AES-128/192/256 software, FIPS 197 App. C", f0, c0);

	/* Inverse cipher: table, constant-time and CryptoCell backends */
	for (di = 0; di < 3; di++) {
		const int impl = dec_impls[di];
		char name[96];

		if (impl == AES_IMPL_CC310 && !platform_has_cc310())
			continue;
		f0 = failures;
		c0 = checks;
		for (j = 0; j < 32; j++)
			key[j] = (u8)j;
		for (i = 0; i < 3; i++) {
			if (impl == AES_IMPL_CC310 && fips197[i].klen != 16)
				continue;
			unhex(ct, fips197[i].ct, 16);
			EXPECT(aes_setkey_dec(&kd, key, fips197[i].klen, impl) == impl,
			       "AES^-1 backend %s selected", aes_name(impl));
			aes_decrypt(&kd, back, ct);
			EXPECT(!memcmp(back, pt, 16), "AES-%u inverse (%s), FIPS 197",
			       (unsigned)(8 * fips197[i].klen), aes_name(impl));
		}
		for (i = 0; i < 96; i++) {
			u8 r[32], x[16], y[16];
			const size_t kl = impl == AES_IMPL_CC310 ? 16 : 16 + 8 * (i % 3);

			rnd_bytes(r, sizeof(r));
			rnd_bytes(x, 16);
			aes_setkey(&k, r, kl, AES_IMPL_SW);
			aes_setkey_dec(&kd, r, kl, impl);
			aes_encrypt(&k, y, x);
			aes_decrypt(&kd, back, y);
			EXPECT(!memcmp(back, x, 16), "AES^-1 (%s) round trip %u", aes_name(impl),
			       (unsigned)i);
		}
		memcpy(name, "AES^-1 ", 7);
		strcpy(name + 7, aes_name(impl));
		strcat(name, impl == AES_IMPL_CC310 ? ": FIPS 197, round trips"
						    : ", 128-256: FIPS 197, round trips");
		report(name, f0, c0);
	}

	/* Forward hardware backends against FIPS 197 and the software AES,
	 * single blocks, Concertina's counter and XCTR */
	for (hw = AES_IMPL_ECB; hw <= AES_IMPL_CC310; hw++) {
		char name[96];

		if ((hw == AES_IMPL_ECB && !platform_has_ecb()) ||
		    (hw == AES_IMPL_CC310 && !platform_has_cc310())) {
			xprintf("  %-44s skipped (not on this chip)\n", aes_name(hw));
			continue;
		}
		f0 = failures;
		c0 = checks;
		for (j = 0; j < 32; j++)
			key[j] = (u8)j;
		for (j = 0; j < 16; j++)
			pt[j] = (u8)(0x11 * j);
		EXPECT(aes_setkey(&kh, key, 16, hw) == hw, "%s backend selected", aes_name(hw));
		aes_encrypt(&kh, ct, pt);
		EXPECT(hexeq(ct, fips197[0].ct, 16), "AES-128 (%s), FIPS 197", aes_name(hw));
		EXPECT(aes_setkey(&kh, key, 32, hw) == AES_IMPL_SW,
		       "AES-256 falls back to software (%s)", aes_name(hw));
		for (i = 0; i < 64; i++) {
			rnd_bytes(key, 16);
			rnd_bytes(pt, 16);
			aes_setkey(&k, key, 16, AES_IMPL_SW);
			aes_setkey(&kh, key, 16, hw);
			aes_encrypt(&k, ct, pt);
			aes_encrypt(&kh, back, pt);
			EXPECT(!memcmp(ct, back, 16), "%s vs software, block %u", aes_name(hw),
			       (unsigned)i);
		}
		for (i = 0; i < 24; i++) {
			const size_t len = rnd32() % 1200;

			rnd_bytes(key, 16);
			rnd_bytes(pt, 16);
			rnd_bytes(in, len);
			aes_setkey(&k, key, 16, AES_IMPL_SW);
			aes_setkey(&kh, key, 16, hw);
			if (i & 1) {
				aes_xctr_xor(&k, pt, in, o1, len);
				aes_xctr_xor(&kh, pt, in, o2, len);
			} else {
				aes_ctr_be_xor(&k, pt, in, o1, len);
				aes_ctr_be_xor(&kh, pt, in, o2, len);
			}
			EXPECT(!memcmp(o1, o2, len), "%s vs software, %s length %u",
			       aes_name(hw), (i & 1) ? "XCTR" : "CTR", (unsigned)len);
		}
		memcpy(name, "AES-128 ", 8);
		strcpy(name + 8, aes_name(hw));
		strcat(name, ": FIPS 197, vs software");
		report(name, f0, c0);
	}
}

static void test_hashes(void)
{
	static const char abc3[] =
		"3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";
	static const char empty3[] =
		"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
	static const char abc2[] =
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
	u64 *a = (u64 *)(void *)arena_a, *b = (u64 *)(void *)(arena_a + 256);
	u32 *w = (u32 *)(void *)(arena_a + 512);
	u8 d[32];
	int i, t, f0 = failures, c0 = checks;

	sha3_256((const u8 *)"abc", 3, d, KECCAK_IMPL_BI32);
	EXPECT(hexeq(d, abc3, 32), "SHA3-256(abc), bit-interleaved");
	sha3_256((const u8 *)"abc", 3, d, KECCAK_IMPL_REF64);
	EXPECT(hexeq(d, abc3, 32), "SHA3-256(abc), 64-bit reference");
	sha3_256((const u8 *)"", 0, d, KECCAK_IMPL_BI32);
	EXPECT(hexeq(d, empty3, 32), "SHA3-256(), bit-interleaved");
	sha3_256((const u8 *)"", 0, d, KECCAK_IMPL_REF64);
	EXPECT(hexeq(d, empty3, 32), "SHA3-256(), 64-bit reference");
	for (t = 0; t < 16; t++) {
		for (i = 0; i < 25; i++)
			a[i] = ((u64)rnd32() << 32) | rnd32();
		keccak_to_bi32(w, a);
		keccak_from_bi32(b, w);
		EXPECT(!memcmp(a, b, 200), "bit interleaving round trip");
		keccak_f1600_ref64(a);
		keccak_f1600_bi32(w);
		keccak_from_bi32(b, w);
		EXPECT(!memcmp(a, b, 200), "Keccak-f bit-interleaved vs reference");
	}
	report("SHA3-256 / Keccak-f[1600] (both backends)", f0, c0);

	f0 = failures;
	c0 = checks;
	sha256((const u8 *)"abc", 3, d, SHA256_IMPL_UNROLLED);
	EXPECT(hexeq(d, abc2, 32), "SHA-256(abc), unrolled");
	sha256((const u8 *)"abc", 3, d, SHA256_IMPL_REF);
	EXPECT(hexeq(d, abc2, 32), "SHA-256(abc), reference");
	if (platform_has_cc310()) {
		sha256((const u8 *)"abc", 3, d, SHA256_IMPL_CC310);
		EXPECT(hexeq(d, abc2, 32), "SHA-256(abc), CryptoCell");
		for (t = 0; t < 24; t++) {
			const size_t len = rnd32() % 1500;
			u8 d2[32];

			rnd_bytes(arena_b, len);
			sha256(arena_b, len, d, SHA256_IMPL_UNROLLED);
			sha256(arena_b, len, d2, SHA256_IMPL_CC310);
			EXPECT(!memcmp(d, d2, 32), "SHA-256 CryptoCell vs software, length %u",
			       (unsigned)len);
		}
	}
	report(platform_has_cc310() ? "SHA-256 (software x2, CryptoCell)"
				    : "SHA-256 (both software backends)", f0, c0);
}

static void hmac_one(const struct kat_mac *v, int impl, size_t split, u8 m[32])
{
	if (v->hash == 0) {
		hmac_sha3_256_key k;

		hmac_sha3_256_setkey(&k, v->key, v->key_len, impl);
		hmac_sha3_256(&k, v->msg, split, v->msg + split, v->len - split, m);
	} else {
		hmac_sha256_key k;

		hmac_sha256_setkey(&k, v->key, v->key_len, impl);
		hmac_sha256(&k, v->msg, split, v->msg + split, v->len - split, m);
	}
}

static void test_mac(void)
{
	size_t i, s;
	int impl, f0 = failures, c0 = checks;

	for (i = 0; i < KAT_MAC_COUNT; i++) {
		const struct kat_mac *v = &kat_mac[i];
		/* SHA3-256: bit-interleaved, reference; SHA-256: unrolled,
		 * reference, CryptoCell */
		const int nimpl = v->hash == 0 ? 2 : (platform_has_cc310() ? 3 : 2);
		/* hmac_*() takes the message as a || b with |b| <= 64. */
		const size_t lo = v->len > 64 ? v->len - 64 : 0;

		for (impl = 0; impl < nimpl; impl++) {
			u8 d[32], m[32];

			if (v->hash == 0)
				sha3_256(v->msg, v->len, d, impl);
			else
				sha256(v->msg, v->len, d, impl);
			EXPECT(!memcmp(d, v->digest, 32), "hash %d impl %d len %u", v->hash,
			       impl, (unsigned)v->len);
#if SELFTEST_FULL_SPLITS
			for (s = lo; s <= v->len; s++) {
				hmac_one(v, impl, s, m);
				EXPECT(!memcmp(m, v->mac, 32), "HMAC hash %d impl %d len %u split %u",
				       v->hash, impl, (unsigned)v->len, (unsigned)s);
			}
#else
			{
				/* lowest split, the suffix length used by Concertina
				 * (17 bytes), one byte, no suffix */
				const size_t sp[4] = {lo, v->len >= 17 ? v->len - 17 : lo,
						      v->len >= 1 ? v->len - 1 : lo, v->len};

				for (s = 0; s < 4; s++) {
					hmac_one(v, impl, sp[s], m);
					EXPECT(!memcmp(m, v->mac, 32),
					       "HMAC hash %d impl %d len %u split %u", v->hash,
					       impl, (unsigned)v->len, (unsigned)sp[s]);
				}
			}
#endif
		}
	}
	report(platform_has_cc310() ? "Hashes, HMAC: 90 known answers (+CryptoCell)"
				    : "SHA3-256, SHA-256, HMAC: 90 known answers", f0, c0);
}

/* Configurations under test: hash backend, AES backend. */
static void scheme_check(const struct kat_scheme *v, int hash_impl, int aes_impl)
{
	scheme_ctx *c = &arena_ctx.s;
	u8 *buf = arena_a, *out = arena_b;

	scheme_setkey(c, v->key, v->key_len, v->hash, hash_impl, aes_impl);
	scheme_encrypt(c, out, v->pt, v->len, v->tweak);
	EXPECT(!memcmp(out, v->ct, v->len), "enc: hash %d/%d, aes %d, key %u, len %u",
	       v->hash, hash_impl, aes_impl, (unsigned)v->key_len, (unsigned)v->len);
	scheme_decrypt(c, buf, v->ct, v->len, v->tweak);
	EXPECT(!memcmp(buf, v->pt, v->len), "dec: hash %d/%d, aes %d, key %u, len %u",
	       v->hash, hash_impl, aes_impl, (unsigned)v->key_len, (unsigned)v->len);
	memcpy(buf, v->pt, v->len);
	scheme_encrypt(c, buf, buf, v->len, v->tweak);
	EXPECT(!memcmp(buf, v->ct, v->len), "in-place enc, len %u", (unsigned)v->len);
	scheme_decrypt(c, buf, buf, v->len, v->tweak);
	EXPECT(!memcmp(buf, v->pt, v->len), "in-place dec, len %u", (unsigned)v->len);
}

static void test_scheme(void)
{
	size_t i;
	int hi, f0 = failures, c0 = checks, n_ecb = 0, n_cc = 0;

	for (i = 0; i < KAT_SCHEME_COUNT; i++) {
		const struct kat_scheme *v = &kat_scheme[i];
		const int sha3 = v->hash == SCHEME_HMAC_SHA3_256;

		CHECK(v->len <= ARENA_LEN);
		/* every software hash backend, software AES */
		for (hi = 0; hi < 2; hi++)
			scheme_check(v, hi, AES_IMPL_SW);
		if (v->key_len != 16)
			continue;
		/* nRF52832 configuration: AES on the ECB peripheral */
		if (platform_has_ecb()) {
			scheme_check(v, 0, AES_IMPL_ECB);
			n_ecb++;
		}
		/* nRF52840 configuration: AES and SHA-256 on the CryptoCell */
		if (platform_has_cc310()) {
			scheme_check(v, sha3 ? KECCAK_IMPL_BI32 : SHA256_IMPL_CC310,
				     AES_IMPL_CC310);
			n_cc++;
		}
	}
	scheme_wipe(&arena_ctx.s);
	report("Concertina: 90 known answers (all backends)", f0, c0);
	xprintf("  %-44s %d with ECB, %d with CryptoCell AES (+SHA-256)\n", "", n_ecb, n_cc);
}

static void test_polyval(void)
{
	size_t i;
	int impl, f0 = failures, c0 = checks;
	polyval_key *k = &arena_ctx.h.pv;

	/* reduction tables, bit-serial definition */
	for (i = 0; i < 256; i++) {
		u32 t[4] = {(u32)i, 0, 0, 0};
		int b;

		for (b = 0; b < 8; b++) {
			const u32 m = 0u - (t[0] & 1u);

			t[0] = (t[0] >> 1) | (t[1] << 31);
			t[1] = (t[1] >> 1) | (t[2] << 31);
			t[2] = (t[2] >> 1) | (t[3] << 31);
			t[3] = (t[3] >> 1) ^ (m & 0xE1000000u);
			if (b == 3 && i < 16)
				EXPECT((u32)polyval_r4[i] == (t[3] >> 16),
				       "GHASH 4-bit reduction %u", (unsigned)i);
		}
		EXPECT((u32)polyval_r8[i] == (t[3] >> 16), "GHASH 8-bit reduction %u",
		       (unsigned)i);
	}
	for (i = 0; i < polyval_tv_count; i++) {
		const struct polyval_testvec *v = &polyval_tv[i];

		CHECK(v->message.len % 16 == 0);
		for (impl = 0; impl < 4; impl++) {
			polyval_state st;
			u8 out[16];

			polyval_setkey(k, v->key.data, impl);
			polyval_init(&st);
			polyval_update(&st, k, v->message.data, v->message.len / 16);
			polyval_emit(&st, out);
			EXPECT(!memcmp(out, v->hash.data, 16), "POLYVAL vector %u (impl %d)",
			       (unsigned)i, impl);
		}
	}
	report("POLYVAL: 96 vectors (ct32, ct64, table4, table8)", f0, c0);
}

static void test_xctr_set(const struct xctr_testvec *tv, size_t n, size_t klen)
{
	u8 *out = arena_a;
	size_t i;
	int ai;

	for (i = 0; i < n; i++) {
		const struct xctr_testvec *v = &tv[i];

		CHECK(v->plaintext.len <= ARENA_LEN && v->key.len == klen);
		for (ai = AES_IMPL_SW; ai <= AES_IMPL_CC310; ai++) {
			aes_key k;

			if (ai != AES_IMPL_SW &&
			    (klen != 16 || (ai == AES_IMPL_ECB && !platform_has_ecb()) ||
			     (ai == AES_IMPL_CC310 && !platform_has_cc310())))
				continue;
			aes_setkey(&k, v->key.data, klen, ai);
			aes_xctr_xor(&k, v->nonce.data, v->plaintext.data, out, v->plaintext.len);
			EXPECT(!memcmp(out, v->ciphertext.data, v->plaintext.len),
			       "XCTR-AES-%u vector %u (aes %s)", (unsigned)(8 * klen),
			       (unsigned)i, aes_name(ai));
		}
	}
}

struct hctr2_cfg {
	int pv, aes, dec;
};

static void test_hctr2_set(const struct hctr2_testvec *tv, size_t n, size_t klen)
{
	/* POLYVAL backends with software AES, then every configuration of the
	 * benchmark with the AES hardware of the two chips (forward / inverse) */
	static const struct hctr2_cfg cfg[] = {
		{POLYVAL_IMPL_CT32, AES_IMPL_SW, AES_IMPL_SW},
		{POLYVAL_IMPL_CT64, AES_IMPL_SW, AES_IMPL_SW},
		{POLYVAL_IMPL_TABLE4, AES_IMPL_SW, AES_IMPL_SW},
		{POLYVAL_IMPL_TABLE8, AES_IMPL_SW, AES_IMPL_SW},
		{POLYVAL_IMPL_CT32, AES_IMPL_SW, AES_IMPL_CT},
		{POLYVAL_IMPL_CT32, AES_IMPL_ECB, AES_IMPL_SW},
		{POLYVAL_IMPL_CT32, AES_IMPL_ECB, AES_IMPL_CT},
		{POLYVAL_IMPL_TABLE4, AES_IMPL_ECB, AES_IMPL_SW},
		{POLYVAL_IMPL_TABLE8, AES_IMPL_ECB, AES_IMPL_SW},
		{POLYVAL_IMPL_CT32, AES_IMPL_CC310, AES_IMPL_CC310},
		{POLYVAL_IMPL_TABLE4, AES_IMPL_CC310, AES_IMPL_CC310},
		{POLYVAL_IMPL_TABLE8, AES_IMPL_CC310, AES_IMPL_CC310},
	};
	hctr2_ctx *c = &arena_ctx.h;
	u8 *ct = arena_a, *pt = arena_b;
	size_t i, j;

	for (i = 0; i < n; i++) {
		const struct hctr2_testvec *v = &tv[i];
		const size_t len = v->plaintext.len;

		CHECK(len <= ARENA_LEN && v->key.len == klen);
		for (j = 0; j < sizeof(cfg) / sizeof(cfg[0]); j++) {
			const struct hctr2_cfg *f = &cfg[j];

			if ((f->aes != AES_IMPL_SW || f->dec == AES_IMPL_CC310) && klen != 16)
				continue;
			if ((f->aes == AES_IMPL_ECB && !platform_has_ecb()) ||
			    (f->aes == AES_IMPL_CC310 && !platform_has_cc310()))
				continue;
			hctr2_setkey(c, v->key.data, klen, f->pv, f->aes, f->dec);
			hctr2_crypt(c, ct, v->plaintext.data, len, v->tweak.data, v->tweak.len, 1);
			EXPECT(!memcmp(ct, v->ciphertext.data, len),
			       "HCTR2-AES-%u enc vector %u (cfg %u)", (unsigned)(8 * klen),
			       (unsigned)i, (unsigned)j);
			hctr2_crypt(c, pt, ct, len, v->tweak.data, v->tweak.len, 0);
			EXPECT(!memcmp(pt, v->plaintext.data, len),
			       "HCTR2-AES-%u dec vector %u (cfg %u)", (unsigned)(8 * klen),
			       (unsigned)i, (unsigned)j);
		}
	}
	hctr2_wipe(c);
}

static void test_hctr2(void)
{
	int f0 = failures, c0 = checks;

	test_xctr_set(xctr_aes128_tv, xctr_aes128_tv_count, 16);
	test_xctr_set(xctr_aes192_tv, xctr_aes192_tv_count, 24);
	test_xctr_set(xctr_aes256_tv, xctr_aes256_tv_count, 32);
	report("XCTR: 180 official vectors (all AES backends)", f0, c0);
	f0 = failures;
	c0 = checks;
	test_hctr2_set(hctr2_aes128_tv, hctr2_aes128_tv_count, 16);
	test_hctr2_set(hctr2_aes192_tv, hctr2_aes192_tv_count, 24);
	test_hctr2_set(hctr2_aes256_tv, hctr2_aes256_tv_count, 32);
	report("HCTR2: 700 official vectors (all backends)", f0, c0);
}

static void test_xts(void)
{
	xts_ctx *c = &arena_ctx.x;
	u8 *ct = arena_a, *pt = arena_b;
	size_t i;
	int ai, f0 = failures, c0 = checks;

	for (i = 0; i < KAT_XTS_COUNT; i++) {
		const struct kat_xts *v = &kat_xts[i];

		CHECK(v->len <= ARENA_LEN);
		for (ai = AES_IMPL_SW; ai <= AES_IMPL_CC310; ai++) {
			if (ai != AES_IMPL_SW &&
			    (v->key_len != 32 || (ai == AES_IMPL_ECB && !platform_has_ecb()) ||
			     (ai == AES_IMPL_CC310 && !platform_has_cc310())))
				continue;
			xts_setkey(c, v->key, v->key_len, ai);
			xts_crypt(c, ct, v->pt, v->len, v->iv, 1);
			EXPECT(!memcmp(ct, v->ct, v->len), "XTS enc vector %u (aes %s)",
			       (unsigned)i, aes_name(ai));
			xts_crypt(c, pt, ct, v->len, v->iv, 0);
			EXPECT(!memcmp(pt, v->pt, v->len), "XTS dec vector %u (aes %s)",
			       (unsigned)i, aes_name(ai));
		}
	}
	xts_wipe(c);
	report("AES-XTS: 14 known answers (all AES backends)", f0, c0);
}

int run_selftests(void)
{
	failures = checks = 0;
	xprintf("Self-tests%s:\n", SELFTEST_FULL_SPLITS ? " (all HMAC split points)" : "");
	test_aes();
	test_hashes();
	test_mac();
	test_scheme();
	test_polyval();
	test_hctr2();
	test_xts();
	xprintf("Self-tests: %s (%d checks, %d failures)\n",
		failures ? "FAILED" : "all passed", checks, failures);
	return failures;
}
