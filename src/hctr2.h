/*
 * HCTR2 (Crowley, Huckleberry, Biggers, ePrint 2021/1441), re-implemented on
 * the shared AES code of this benchmark (as in the AArch64 repository) and
 * validated against the official test vectors of the reference repository
 * https://github.com/google/hctr2 (src/testvecs/, identical to
 * test_vectors/converted/cstruct/ at commit 0b0b537).
 *
 * Encryption uses the forward cipher (one block, XCTR); decryption needs the
 * inverse cipher for one block. aes_impl selects the backend of the forward
 * cipher (software, ECB peripheral or CryptoCell), aes_dec_impl that of the
 * inverse cipher (software table, constant-time software or CryptoCell).
 */
#pragma once
#include "aes.h"
#include "polyval.h"

#define HCTR2_DEFAULT_TWEAK_LEN 16

typedef struct {
	aes_key aes;
	aes_dec_key aes_dec;
	polyval_key pv;
	u8 L[16];
	polyval_state init[2]; /* precomputed first hash block, tweak length 16 */
} hctr2_ctx;

void hctr2_setkey(hctr2_ctx *c, const u8 *key, size_t key_len,
		  int polyval_impl, int aes_impl, int aes_dec_impl);
/* len >= 16; dst may equal src. */
void hctr2_crypt(const hctr2_ctx *c, u8 *dst, const u8 *src, size_t len,
		 const u8 *tweak, size_t tweak_len, int encrypt);
void hctr2_wipe(hctr2_ctx *c);
