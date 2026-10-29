/*
 * AES for the benchmark: one implementation per backend, shared by every
 * mode, so that the measured differences come from the modes themselves.
 *
 * Forward direction (aes.c), used by all modes:
 *   AES_IMPL_SW    - 32-bit table implementation with a single 1 KiB table
 *                    and rotations, built in RAM at start-up (the nRF52 chips
 *                    have no data cache). AES-128/192/256.
 *   AES_IMPL_ECB   - the ECB peripheral of the nRF52832 / nRF52840 (AES-128,
 *                    encryption only), one block per operation.
 *   AES_IMPL_CC310 - the CryptoCell-310 of the nRF52840 (AES-128), several
 *                    blocks per DMA transfer (counter blocks are prepared by
 *                    the CPU: neither counter of Concertina nor XCTR is the
 *                    CryptoCell's CTR mode).
 * Selecting a hardware backend for a 192/256-bit key, or on a chip without
 * it, falls back to AES_IMPL_SW.
 *
 * Inverse direction (aes_dec.c, aes_ct.c), used by HCTR2 and AES-XTS only:
 *   AES_IMPL_SW    - table implementation (second 1 KiB table, inverse S-box,
 *                    equivalent inverse key schedule); not constant-time
 *   AES_IMPL_CT    - constant-time bitsliced implementation (BearSSL aes_ct)
 *   AES_IMPL_CC310 - CryptoCell-310 decryption
 *
 * Build options (for the memory measurements; each configuration is built
 * with only what it uses):
 *   AES_MAX_NR      14 (AES-256, default) or 10 (AES-128 only)
 *   AES_WITH_ECB    ECB peripheral backend (default 1)
 *   AES_WITH_CC310  CryptoCell backend (default 1)
 *   AES_FWD_SW      software forward cipher (default 1)
 *   AES_DEC_TABLE   table inverse cipher (default 1)
 *   AES_DEC_CT      constant-time inverse cipher (default 1)
 *   AES_ECB_ONLY    = forward cipher on the ECB peripheral only
 *   AES_CC310_ONLY  = both directions on the CryptoCell only
 *   AES_TABLES_IN_FLASH  constant tables in flash instead of tables built in
 *                   RAM at first use (default 0: flash data reads are slower)
 */
#pragma once
#include "common.h"

enum { AES_IMPL_SW = 0, AES_IMPL_ECB = 1, AES_IMPL_CC310 = 2, AES_IMPL_CT = 3 };

#ifndef AES_MAX_NR
#define AES_MAX_NR 14
#endif
#ifndef AES_ECB_ONLY
#define AES_ECB_ONLY 0
#endif
#ifndef AES_CC310_ONLY
#define AES_CC310_ONLY 0
#endif
#if AES_ECB_ONLY
#define AES_FWD_SW 0
#define AES_WITH_CC310 0
#endif
#if AES_CC310_ONLY
#define AES_FWD_SW 0
#define AES_WITH_ECB 0
#define AES_DEC_TABLE 0
#define AES_DEC_CT 0
#endif
#ifndef AES_FWD_SW
#define AES_FWD_SW 1
#endif
#ifndef AES_WITH_ECB
#define AES_WITH_ECB 1
#endif
#ifndef AES_WITH_CC310
#define AES_WITH_CC310 1
#endif
#ifndef AES_DEC_TABLE
#define AES_DEC_TABLE 1
#endif
#ifndef AES_DEC_CT
#define AES_DEC_CT 1
#endif
#ifndef AES_TABLES_IN_FLASH
#define AES_TABLES_IN_FLASH 0
#endif

typedef struct {
#if AES_FWD_SW
	u32 rk[4 * (AES_MAX_NR + 1)]; /* round keys, little-endian column words */
#endif
	u8 key[16]; /* raw key for the hardware backends (AES-128 only) */
	int nr;     /* 10, 12 or 14 */
	int impl;   /* AES_IMPL_SW, AES_IMPL_ECB or AES_IMPL_CC310 */
} aes_key;

#if AES_DEC_CT
#define AES_DEC_WORDS (8 * (AES_MAX_NR + 1)) /* bitsliced round keys */
#elif AES_DEC_TABLE
#define AES_DEC_WORDS (4 * (AES_MAX_NR + 1))
#else
#define AES_DEC_WORDS 0
#endif

typedef struct {
#if AES_DEC_WORDS
	u32 dk[AES_DEC_WORDS]; /* inverse-cipher (table) or bitsliced round keys */
#endif
#if AES_WITH_CC310
	u8 key[16];            /* raw key for the CryptoCell */
#endif
	int nr;
	int impl; /* AES_IMPL_SW, AES_IMPL_CT or AES_IMPL_CC310 */
} aes_dec_key;

/* Returns the backend actually selected. */
int aes_setkey(aes_key *k, const u8 *key, size_t key_len, int impl);
void aes_encrypt(const aes_key *k, u8 out[16], const u8 in[16]);

/* Counter-mode keystream XOR: block i (i = 0, 1, ...) is E_K(S xor <i>_128)
 * with <i>_128 the 128-bit big-endian encoding of i (Concertina). in may
 * equal out. */
void aes_ctr_be_xor(const aes_key *k, const u8 S[16], const u8 *in, u8 *out,
		    size_t len);

/* XCTR (HCTR2): block i (i = 1, 2, ...) is E_K(S xor (le64(i) || 0^64)). */
void aes_xctr_xor(const aes_key *k, const u8 S[16], const u8 *in, u8 *out,
		  size_t len);

/* Inverse cipher; returns the backend actually selected. */
int aes_setkey_dec(aes_dec_key *k, const u8 *key, size_t key_len, int impl);
void aes_decrypt(const aes_dec_key *k, u8 out[16], const u8 in[16]);

void aes_wipe(aes_key *k);

/* Internal, shared with aes_dec.c / aes_ct.c: SubWord and the forward key
 * expansion (returns the number of rounds). */
u32 aes_sub_word(u32 w);
int aes_expand_key(u32 *rk, const u8 *key, size_t key_len);

/* aes_ct.c (constant-time, bitsliced; BearSSL aes_ct). */
int aes_ct_setkey_dec(u32 *skey, const u8 *key, size_t key_len);
void aes_ct_decrypt(const u32 *skey, int nr, u8 out[16], const u8 in[16]);
