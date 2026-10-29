/*
 * Host platform (Linux/macOS) for testing the portable code natively:
 *   make host && ./build/host/concertina-host
 * The "cycle" counter is a nanosecond clock; there is no ECB peripheral.
 */
#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "platform.h"

void platform_init(void) {}
const char *platform_name(void) { return "host (portable C, test build)"; }

void platform_write(const char *s, size_t n)
{
	fwrite(s, 1, n, stdout);
	fflush(stdout);
}

u32 platform_cycles(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (u32)((u64)ts.tv_sec * 1000000000ull + (u64)ts.tv_nsec);
}

u32 platform_cycles_hz(void) { return 1000000000u; }
int platform_has_ecb(void) { return 0; }

/* The host has no CryptoCell: report none (the CryptoCell backends are tested
 * in the emulator, against its model of the hardware). */
int platform_has_cc310(void) { return 0; }
void platform_cc310_aes_ecb(const u8 key[16], int decrypt, const u8 *in, u8 *out,
			    size_t len)
{
	(void)key; (void)decrypt; (void)in; (void)out; (void)len;
	platform_panic("no CryptoCell on the host", __FILE__, __LINE__);
}
void platform_cc310_sha256_blocks(u32 st[8], const u8 *in, size_t nblocks)
{
	(void)st; (void)in; (void)nblocks;
	platform_panic("no CryptoCell on the host", __FILE__, __LINE__);
}

void platform_ecb_encrypt(const u8 key[16], const u8 in[16], u8 out[16])
{
	(void)key;
	(void)in;
	(void)out;
	platform_panic("no ECB peripheral on the host", __FILE__, __LINE__);
}

void platform_led(int idx, int on)
{
	(void)idx;
	(void)on;
}

void platform_halt(int status) { exit(status); }

void platform_panic(const char *what, const char *file, int line)
{
	fprintf(stderr, "Check failed: %s (%s:%d)\n", what, file, line);
	abort();
}
