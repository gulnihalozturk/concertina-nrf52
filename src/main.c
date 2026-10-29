/*
 * Concertina and HCTR2 on the nRF52840: self-tests, a short usage example,
 * then the benchmark (Concertina, HCTR2, AES-XTS). Output goes to the
 * console (UARTE0, 115200 8N1 on the nRF52840 DK's J-Link virtual COM port).
 */
#include "bench.h"
#include "platform.h"
#include "print.h"
#include "scheme.h"
#include "selftest.h"

#ifndef RUN_BENCHMARKS
#define RUN_BENCHMARKS 1
#endif

static void example(void)
{
	static scheme_ctx c;
	static const u8 key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				   0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	static const char msg[] = "Concertina on nRF52840: 64-byte wide-block example!";
	u8 pt[64], ct[64], back[64], tweak[16] = {0};
	u32 t0, te, td;

	memset(pt, 0, sizeof(pt));
	memcpy(pt, msg, sizeof(msg) - 1);
	tweak[15] = 7; /* e.g. a sector or record number */
	scheme_setkey(&c, key, sizeof(key), SCHEME_HMAC_SHA3_256, KECCAK_IMPL_BI32,
		      AES_IMPL_SW);
	t0 = platform_cycles();
	scheme_encrypt(&c, ct, pt, sizeof(pt), tweak);
	te = platform_cycles() - t0;
	t0 = platform_cycles();
	scheme_decrypt(&c, back, ct, sizeof(ct), tweak);
	td = platform_cycles() - t0;
	xprintf("\nExample (HMAC-SHA3-256, AES-128, 64 bytes, tweak ...07):\n");
	xprintf("  plaintext : %s\n", msg);
	xprintf("  ciphertext: ");
	xprint_hex(ct, 32);
	xprintf("\n              ");
	xprint_hex(ct + 32, 32);
	xprintf("\n  decrypted : %s (%u + %u cycles)\n",
		memcmp(back, pt, sizeof(pt)) ? "MISMATCH" : "matches", (unsigned)te,
		(unsigned)td);
	/* Wide-block property: one flipped plaintext bit changes every
	 * ciphertext block. */
	pt[63] ^= 1;
	scheme_encrypt(&c, back, pt, sizeof(pt), tweak);
	{
		int i, changed = 0;

		for (i = 0; i < 4; i++)
			changed += memcmp(back + 16 * i, ct + 16 * i, 16) != 0;
		xprintf("  last plaintext bit flipped: %d of 4 ciphertext blocks "
			"changed\n", changed);
	}
	scheme_wipe(&c);
}

int main(void)
{
	int failures;

	platform_init();
	platform_led(0, 1);
	xprintf("\n=== Concertina and HCTR2 (tweakable wide-block modes) on %s ===\n",
		platform_name());
	xprintf("build %s %s, gcc %s\n", __DATE__, __TIME__, __VERSION__);

	failures = run_selftests();
	if (!failures) {
		example();
#if RUN_BENCHMARKS
		run_benchmarks();
#endif
	} else {
		xprintf("Self-tests failed: benchmark skipped.\n");
	}
	xprintf("\nDONE: %s\n", failures ? "FAIL" : "PASS");
	platform_led(0, 0);
	platform_led(failures ? 3 : 1, 1);
	platform_halt(failures != 0);
}
