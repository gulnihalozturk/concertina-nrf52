/* AES-XTS (IEEE 1619, NIST SP 800-38E) as a narrow-block reference point, on
 * the shared AES code. Only lengths that are multiples of 16 bytes are
 * supported (no ciphertext stealing), which covers all benchmarked sizes.
 * aes_impl selects the forward backend (encryption, tweak); decryption uses
 * the CryptoCell with AES_IMPL_CC310 and the software table inverse cipher
 * otherwise (the ECB peripheral only encrypts). */
#pragma once
#include "aes.h"

typedef struct {
	aes_key k1, k2;
	aes_dec_key d1;
} xts_ctx;

void xts_setkey(xts_ctx *c, const u8 *key, size_t key_len, int aes_impl); /* key_len = 2k */
void xts_crypt(const xts_ctx *c, u8 *dst, const u8 *src, size_t len,
	       const u8 iv[16], int encrypt);
void xts_wipe(xts_ctx *c);
