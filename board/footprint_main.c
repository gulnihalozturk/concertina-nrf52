/*
 * Minimal firmware for the memory measurements (tools/footprint.py): links
 * exactly one mode (key setup, encryption and decryption), with only the
 * backend under test compiled in, and nothing else from the benchmark.
 * FP_MODE = 0 builds the baseline (start-up, platform, console and this
 * measuring code), which tools/footprint.py subtracts.
 *
 * When run (on a board or in the emulator) it prints one line:
 *   FP ctx=<bytes> stack_setup=<bytes> stack_enc=<bytes> stack_dec=<bytes>
 *      setup=<cycles> roundtrip=ok
 * with the peak stack depths measured by painting the stack, and the cost of
 * the key setup of this configuration (counter-read overhead subtracted).
 */
#include "platform.h"
#include "print.h"

#if FP_MODE == 1
#include "xts.h"
typedef xts_ctx ctx_t;
#elif FP_MODE == 2
#include "hctr2.h"
typedef hctr2_ctx ctx_t;
#elif FP_MODE == 3
#include "scheme.h"
typedef scheme_ctx ctx_t;
#else
typedef int ctx_t;
#endif

#ifndef FP_AES
#define FP_AES 0     /* forward AES backend (AES_IMPL_*) */
#endif
#ifndef FP_AES_DEC
#define FP_AES_DEC 0 /* inverse AES backend of HCTR2 (AES_IMPL_*) */
#endif
#ifndef FP_HASH_IMPL
#define FP_HASH_IMPL 0 /* hash backend of Concertina (KECCAK_ / SHA256_IMPL_*) */
#endif
#define LEN 4096

/* External, and used in every build (also the baseline), so that they are
 * part of the subtracted baseline. */
u8 key[32], tweak[16], buf[LEN];
ctx_t ctx;
void (*volatile keep_panic)(const char *, const char *, int) = platform_panic;
void *volatile keep_data[] = {key, tweak, buf, &ctx};

static NOINLINE void op(int what)
{
#if FP_MODE == 1
	if (what == 0)
		xts_setkey(&ctx, key, 32, FP_AES);
	else
		xts_crypt(&ctx, buf, buf, LEN, tweak, what == 1);
#elif FP_MODE == 2
	if (what == 0)
		hctr2_setkey(&ctx, key, 16, FP_POLYVAL, FP_AES, FP_AES_DEC);
	else
		hctr2_crypt(&ctx, buf, buf, LEN, tweak, sizeof(tweak), what == 1);
#elif FP_MODE == 3
	if (what == 0)
		scheme_setkey(&ctx, key, 16, FP_HASH, FP_HASH_IMPL, FP_AES);
	else if (what == 1)
		scheme_encrypt(&ctx, buf, buf, LEN, tweak);
	else
		scheme_decrypt(&ctx, buf, buf, LEN, tweak);
#else
	(void)what;
#endif
}

#define STACK_PAINT 8192u
#define STACK_PATTERN 0xa5c3f00du

static NOINLINE u32 stack_depth(int what)
{
	u32 sp, *p, *lo;

	__asm volatile("mov %0, sp" : "=r"(sp));
	lo = (u32 *)(uintptr_t)(sp - STACK_PAINT);
	for (p = lo; p < (u32 *)(uintptr_t)(sp - 8); p++)
		*(volatile u32 *)p = STACK_PATTERN;
	op(what);
	for (p = lo; p < (u32 *)(uintptr_t)(sp - 8) && *(volatile u32 *)p == STACK_PATTERN; p++)
		;
	return sp - (u32)(uintptr_t)p;
}

int main(void)
{
	u32 s0, s1, s2, setup = ~0u, overhead = ~0u;
	int i;

	platform_init();
	(void)keep_data[0]; /* keeps the data above in every build */
	(void)keep_panic;
	for (i = 0; i < LEN; i++)
		buf[i] = (u8)i;
	s0 = stack_depth(0);
	s1 = stack_depth(1);
	s2 = stack_depth(2);
	for (i = 0; i < 16; i++) {
		const u32 t0 = platform_cycles(), d = platform_cycles() - t0;

		if (d < overhead)
			overhead = d;
	}
	for (i = 0; i < 3; i++) {
		const u32 t0 = platform_cycles();
		u32 d;

		op(0);
		d = platform_cycles() - t0 - overhead;
		if (d < setup)
			setup = d;
	}
	for (i = 0; i < LEN && buf[i] == (u8)i; i++)
		;
	xprintf("FP ctx=%u stack_setup=%u stack_enc=%u stack_dec=%u setup=%u roundtrip=%s\n",
		(unsigned)(FP_MODE ? sizeof(ctx_t) : 0), (unsigned)s0, (unsigned)s1,
		(unsigned)s2, (unsigned)setup, i == LEN ? "ok" : "FAIL");
	platform_halt(i != LEN);
}
