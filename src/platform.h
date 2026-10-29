/*
 * Platform layer: everything that is specific to the board. Implemented by
 * board/platform_nrf52.c (nRF52840 / nRF52832) and board/platform_host.c (host tests).
 */
#pragma once
#include "common.h"

void platform_init(void);
const char *platform_name(void);

/* Console output (blocking). */
void platform_write(const char *s, size_t n);

/* Free-running cycle counter (DWT->CYCCNT on Cortex-M4) and its frequency. */
u32 platform_cycles(void);
u32 platform_cycles_hz(void);

/* Hardware AES-128 (nRF52840 ECB peripheral). The bytes are in the order of
 * FIPS 197 (key[0] and in[0] first). platform_has_ecb() returns 0 when there
 * is no such peripheral; platform_ecb_encrypt() must then not be called. */
int platform_has_ecb(void);
void platform_ecb_encrypt(const u8 key[16], const u8 in[16], u8 out[16]);

/* CryptoCell-310 (nRF52840): AES-128 ECB encryption or decryption of len
 * bytes (a multiple of 16; out may equal in), and the SHA-256 compression
 * function applied to nblocks 64-byte blocks, starting from and updating
 * the chaining value st[0..7] (H0..H7). platform_has_cc310() returns 0 when
 * there is no CryptoCell; the other two must then not be called. */
int platform_has_cc310(void);
void platform_cc310_aes_ecb(const u8 key[16], int decrypt, const u8 *in, u8 *out,
			    size_t len);
void platform_cc310_sha256_blocks(u32 st[8], const u8 *in, size_t nblocks);

/* Status LEDs (no-op where there are none). */
void platform_led(int idx, int on);

/* End of the program; status 0 = success. Never returns. */
void platform_halt(int status) __attribute__((noreturn));
