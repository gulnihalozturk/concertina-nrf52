/*
 * Benchmark on the target, under the conditions of the AArch64 measurement:
 * AES-128, a 16-byte tweak (IV for AES-XTS), message lengths 32, 64, 256,
 * 512, 1024 and 4096 bytes, best of BENCH_NTRIES runs.
 *
 * Modes are measured in three groups:
 *   software   - everything in software (identical on both chips)
 *   ECB        - forward AES on the ECB peripheral (nRF52832 and nRF52840),
 *                inverse AES in software (table or constant-time)
 *   CryptoCell - AES (both directions) and SHA-256 on the CryptoCell-310
 *                (nRF52840 only); Keccak-f and POLYVAL in software
 * A group whose hardware is missing is skipped.
 *
 * For every mode: encryption and decryption cycles, key setup cycles, the
 * size of the context, and the peak stack depth of key setup, encryption and
 * decryption (measured by painting the stack). Cycles come from the platform
 * counter (DWT->CYCCNT) minus the overhead of reading it. Interrupts are not
 * used.
 *
 * Machine-readable lines (parsed by tools/make_tables.py):
 *   CSV,<mode>,<len>,<enc_cycles>,<dec_cycles>
 *   CSV,<mode>,setup,<cycles>,0
 *   CSV,<mode>,ctx,<bytes>,0
 *   CSV,<mode>,stack,<setup_bytes>,<crypt_bytes>
 *   CSV,prim-<primitive>,<bytes>,<cycles>,0
 */
#include "arena.h"
#include "bench.h"
#include "hctr2.h"
#include "platform.h"
#include "print.h"
#include "scheme.h"
#include "xts.h"

#ifndef BENCH_NTRIES
#define BENCH_NTRIES 15
#endif
#define MAX_LEN ARENA_LEN

static const size_t sizes[] = {32, 64, 256, 512, 1024, 4096};
#define NSIZES (sizeof(sizes) / sizeof(sizes[0]))

enum { KIND_XTS, KIND_HCTR2, KIND_CONCERTINA };
enum { NEED_NONE, NEED_ECB, NEED_CC310 };

struct mode {
	const char *id, *label;
	int kind;
	int p1, p2; /* Concertina: hash, hash_impl; HCTR2: polyval_impl */
	int aes_impl, aes_dec_impl;
	int needs;
};

#define SHA3 SCHEME_HMAC_SHA3_256
#define SHA2 SCHEME_HMAC_SHA256
#define CT32 POLYVAL_IMPL_CT32
#define CT64 POLYVAL_IMPL_CT64
#define T4 POLYVAL_IMPL_TABLE4
#define T8 POLYVAL_IMPL_TABLE8
#define SW AES_IMPL_SW
#define ECB AES_IMPL_ECB
#define CC AES_IMPL_CC310
#define CT AES_IMPL_CT

static const struct mode modes[] = {
	/* software */
	{"xts", "AES-XTS", KIND_XTS, 0, 0, SW, SW, NEED_NONE},
	{"hctr2", "HCTR2, POLYVAL ct32", KIND_HCTR2, CT32, 0, SW, SW, NEED_NONE},
	{"hctr2-t4", "HCTR2, POLYVAL table4", KIND_HCTR2, T4, 0, SW, SW, NEED_NONE},
	{"hctr2-t8", "HCTR2, POLYVAL table8", KIND_HCTR2, T8, 0, SW, SW, NEED_NONE},
	{"hctr2-ct64", "HCTR2, POLYVAL ct64 (AArch64 code)", KIND_HCTR2, CT64, 0, SW, SW,
	 NEED_NONE},
	{"concertina-sha3", "Concertina, HMAC-SHA3-256", KIND_CONCERTINA, SHA3,
	 KECCAK_IMPL_BI32, SW, SW, NEED_NONE},
	{"concertina-sha256", "Concertina, HMAC-SHA-256", KIND_CONCERTINA, SHA2,
	 SHA256_IMPL_UNROLLED, SW, SW, NEED_NONE},
	{"concertina-sha3-ref64", "Concertina, SHA3, 64-bit Keccak (AArch64)",
	 KIND_CONCERTINA, SHA3, KECCAK_IMPL_REF64, SW, SW, NEED_NONE},
	{"concertina-sha256-ref", "Concertina, SHA-256, rolled loop (AArch64)",
	 KIND_CONCERTINA, SHA2, SHA256_IMPL_REF, SW, SW, NEED_NONE},
	/* ECB peripheral: forward AES-128 in hardware */
	{"xts-ecb", "AES-XTS, ECB (dec: table)", KIND_XTS, 0, 0, ECB, SW, NEED_ECB},
	{"hctr2-ecb", "HCTR2 ct32, ECB, dec: table", KIND_HCTR2, CT32, 0, ECB, SW, NEED_ECB},
	{"hctr2-ecb-ctdec", "HCTR2 ct32, ECB, dec: constant-time", KIND_HCTR2, CT32, 0,
	 ECB, CT, NEED_ECB},
	{"hctr2-t4-ecb", "HCTR2 table4, ECB, dec: table", KIND_HCTR2, T4, 0, ECB, SW,
	 NEED_ECB},
	{"hctr2-t8-ecb", "HCTR2 table8, ECB, dec: table", KIND_HCTR2, T8, 0, ECB, SW,
	 NEED_ECB},
	{"concertina-sha3-ecb", "Concertina, SHA3 (sw), ECB", KIND_CONCERTINA, SHA3,
	 KECCAK_IMPL_BI32, ECB, SW, NEED_ECB},
	{"concertina-sha256-ecb", "Concertina, SHA-256 (sw), ECB", KIND_CONCERTINA, SHA2,
	 SHA256_IMPL_UNROLLED, ECB, SW, NEED_ECB},
	/* CryptoCell-310: AES both directions and SHA-256 in hardware */
	{"xts-cc", "AES-XTS, CryptoCell", KIND_XTS, 0, 0, CC, CC, NEED_CC310},
	{"hctr2-cc", "HCTR2 ct32, CryptoCell AES", KIND_HCTR2, CT32, 0, CC, CC, NEED_CC310},
	{"hctr2-t4-cc", "HCTR2 table4, CryptoCell AES", KIND_HCTR2, T4, 0, CC, CC,
	 NEED_CC310},
	{"hctr2-t8-cc", "HCTR2 table8, CryptoCell AES", KIND_HCTR2, T8, 0, CC, CC,
	 NEED_CC310},
	{"concertina-sha3-cc", "Concertina, SHA3 (sw), CryptoCell AES", KIND_CONCERTINA,
	 SHA3, KECCAK_IMPL_BI32, CC, CC, NEED_CC310},
	{"concertina-sha256-cc", "Concertina, SHA-256+AES CryptoCell", KIND_CONCERTINA,
	 SHA2, SHA256_IMPL_CC310, CC, CC, NEED_CC310},
};
#define NMODES (sizeof(modes) / sizeof(modes[0]))

static u8 *const buf_in = arena_a, *const buf_out = arena_b;
static u8 key[32], tweak[16];
static u32 overhead;

/* ---------------- the modes behind one interface ---------------- */

static int available(const struct mode *m)
{
	return m->needs == NEED_NONE || (m->needs == NEED_ECB && platform_has_ecb()) ||
	       (m->needs == NEED_CC310 && platform_has_cc310());
}

static size_t key_len(const struct mode *m) { return m->kind == KIND_XTS ? 32 : 16; }

static size_t ctx_size(const struct mode *m)
{
	switch (m->kind) {
	case KIND_XTS:
		return sizeof(xts_ctx);
	case KIND_HCTR2:
		return sizeof(hctr2_ctx);
	default:
		return sizeof(scheme_ctx);
	}
}

static void mode_setkey(const struct mode *m)
{
	switch (m->kind) {
	case KIND_XTS:
		xts_setkey(&arena_ctx.x, key, key_len(m), m->aes_impl);
		break;
	case KIND_HCTR2:
		hctr2_setkey(&arena_ctx.h, key, key_len(m), m->p1, m->aes_impl,
			     m->aes_dec_impl);
		break;
	default:
		scheme_setkey(&arena_ctx.s, key, key_len(m), m->p1, m->p2, m->aes_impl);
		break;
	}
}

static void mode_crypt(const struct mode *m, u8 *dst, const u8 *src, size_t len,
		       int enc)
{
	switch (m->kind) {
	case KIND_XTS:
		xts_crypt(&arena_ctx.x, dst, src, len, tweak, enc);
		break;
	case KIND_HCTR2:
		hctr2_crypt(&arena_ctx.h, dst, src, len, tweak, sizeof(tweak), enc);
		break;
	default:
		if (enc)
			scheme_encrypt(&arena_ctx.s, dst, src, len, tweak);
		else
			scheme_decrypt(&arena_ctx.s, dst, src, len, tweak);
		break;
	}
}

/* The backends actually selected, to detect a silent fallback. */
static int mode_backends_ok(const struct mode *m)
{
	switch (m->kind) {
	case KIND_XTS:
		return arena_ctx.x.k1.impl == m->aes_impl &&
		       arena_ctx.x.d1.impl == (m->aes_impl == CC ? CC : SW);
	case KIND_HCTR2:
		return arena_ctx.h.aes.impl == m->aes_impl &&
		       arena_ctx.h.aes_dec.impl == m->aes_dec_impl &&
		       arena_ctx.h.pv.impl == m->p1;
	default:
		return arena_ctx.s.kctr.impl == m->aes_impl &&
		       arena_ctx.s.k[0].impl == m->aes_impl &&
		       (m->p1 == SHA3 ? arena_ctx.s.hk.s3.impl : arena_ctx.s.hk.s2.impl) ==
			       m->p2;
	}
}

/* ---------------- measurement helpers ---------------- */

static u32 elapsed(u32 t0)
{
	const u32 d = platform_cycles() - t0;

	return d > overhead ? d - overhead : 0;
}

static void calibrate(void)
{
	int i;

	for (i = 0, overhead = ~0u; i < 16; i++) {
		const u32 t0 = platform_cycles();
		const u32 d = platform_cycles() - t0;

		if (d < overhead)
			overhead = d;
	}
}

#define MIN_OVER_TRIES(var, stmt)                                              \
	do {                                                                   \
		int t_;                                                        \
		var = ~0u;                                                     \
		for (t_ = 0; t_ < BENCH_NTRIES; t_++) {                        \
			const u32 t0_ = platform_cycles();                     \
			stmt;                                                  \
			{                                                      \
				const u32 d_ = elapsed(t0_);                   \
				if (d_ < var)                                  \
					var = d_;                              \
			}                                                      \
		}                                                              \
	} while (0)

/* Peak stack depth of a call, by painting the unused stack below the
 * current stack pointer (no interrupts run in this firmware). */
#define STACK_PAINT 8192u
#define STACK_PATTERN 0xa5c3f00du

struct job {
	const struct mode *m;
	int what; /* 0 setkey, 1 encrypt, 2 decrypt (MAX_LEN bytes) */
};

static NOINLINE void run_job(const struct job *j)
{
	if (j->what == 0)
		mode_setkey(j->m);
	else if (j->what == 1)
		mode_crypt(j->m, buf_out, buf_in, MAX_LEN, 1);
	else
		mode_crypt(j->m, buf_in, buf_out, MAX_LEN, 0);
}

static NOINLINE u32 stack_depth(const struct job *j)
{
#if defined(__arm__)
	u32 sp, *p, *lo;

	__asm volatile("mov %0, sp" : "=r"(sp));
	lo = (u32 *)(uintptr_t)(sp - STACK_PAINT);
	for (p = lo; p < (u32 *)(uintptr_t)(sp - 8); p++)
		*(volatile u32 *)p = STACK_PATTERN;
	run_job(j);
	for (p = lo; p < (u32 *)(uintptr_t)(sp - 8) && *(volatile u32 *)p == STACK_PATTERN; p++)
		;
	return sp - (u32)(uintptr_t)p;
#else
	run_job(j);
	return 0;
#endif
}

/* Prints v / len with one decimal, right-aligned in width. */
static void print_ratio(u32 v, size_t len, int width)
{
	const u64 x10 = ((u64)v * 10 + len / 2) / len;
	char s[24], tmp[16];
	int n = 0, m = 0;
	u64 ip = x10 / 10;

	do {
		tmp[m++] = (char)('0' + ip % 10);
		ip /= 10;
	} while (ip);
	while (m)
		s[n++] = tmp[--m];
	s[n++] = '.';
	s[n++] = (char)('0' + x10 % 10);
	s[n] = 0;
	xprintf("%*s", width, s);
}

/* ---------------- primitives ---------------- */

static void bench_primitives(void)
{
	u64 *st64 = (u64 *)(void *)buf_out;
	u32 *st32 = (u32 *)(void *)(buf_out + 256);
	aes_key k;
	aes_dec_key kd;
	polyval_key *pk = &arena_ctx.h.pv;
	polyval_state ps;
	u8 blk[16];
	u32 c, st[8] = {0};

	memset(blk, 0x5a, sizeof(blk));
	memset(buf_out, 0, 1024);
	xprintf("\nPrimitives (AES-128)                              cycles\n");
#define PRIM(name, csv, bytes, div, stmt)                                      \
	do {                                                                   \
		MIN_OVER_TRIES(c, stmt);                                       \
		xprintf("  %-44s %8u\n", name, (unsigned)(c / (div)));         \
		xprintf("CSV,prim-%s,%u,%u,0\n", csv, (unsigned)(bytes),        \
			(unsigned)(c / (div)));                                \
	} while (0)

	PRIM("AES key expansion (encryption)", "aes-setkey", 16, 1,
	     aes_setkey(&k, key, 16, AES_IMPL_SW));
	PRIM("AES block encryption, software", "aes-enc", 16, 1, aes_encrypt(&k, blk, blk));
	PRIM("AES key expansion (inverse, table)", "aes-setkey-dec", 16, 1,
	     aes_setkey_dec(&kd, key, 16, AES_IMPL_SW));
	PRIM("AES block decryption, table", "aes-dec", 16, 1, aes_decrypt(&kd, blk, blk));
	PRIM("AES key expansion (inverse, constant-time)", "aes-setkey-dec-ct", 16, 1,
	     aes_setkey_dec(&kd, key, 16, AES_IMPL_CT));
	PRIM("AES block decryption, constant-time", "aes-dec-ct", 16, 1,
	     aes_decrypt(&kd, blk, blk));
	if (aes_setkey(&k, key, 16, AES_IMPL_ECB) == AES_IMPL_ECB)
		PRIM("AES block encryption, ECB peripheral", "aes-ecb", 16, 1,
		     aes_encrypt(&k, blk, blk));
	if (platform_has_cc310()) {
		aes_setkey(&k, key, 16, AES_IMPL_CC310);
		PRIM("AES block encryption, CryptoCell (1 block)", "aes-cc", 16, 1,
		     aes_encrypt(&k, blk, blk));
		PRIM("AES CTR, CryptoCell, per block (16 per DMA)", "aes-cc-ctr16", 16, 16,
		     aes_ctr_be_xor(&k, blk, buf_in, buf_in, 256));
		aes_setkey_dec(&kd, key, 16, AES_IMPL_CC310);
		PRIM("AES block decryption, CryptoCell", "aes-dec-cc", 16, 1,
		     aes_decrypt(&kd, blk, blk));
		PRIM("SHA-256 compression, CryptoCell (1 block)", "sha256-cc-block", 64, 1,
		     platform_cc310_sha256_blocks(st, buf_in, 1));
		PRIM("SHA-256 compression, CryptoCell (per block of 16)", "sha256-cc-block16",
		     64, 16, platform_cc310_sha256_blocks(st, buf_in, 16));
	}
	aes_wipe(&k);
	PRIM("Keccak-f[1600], bit-interleaved 32-bit", "keccak-bi32", 200, 1,
	     keccak_f1600_bi32(st32));
	PRIM("Keccak-f[1600], 64-bit reference", "keccak-ref64", 200, 1,
	     keccak_f1600_ref64(st64));
	PRIM("SHA-256 compression, unrolled (per block)", "sha256-block", 64, 16,
	     sha256(buf_in, 1024 - 9, buf_out, SHA256_IMPL_UNROLLED));
	PRIM("SHA-256 compression, reference (per block)", "sha256-ref-block", 64, 16,
	     sha256(buf_in, 1024 - 9, buf_out, SHA256_IMPL_REF));
	polyval_init(&ps);
	polyval_setkey(pk, key, POLYVAL_IMPL_CT32);
	PRIM("POLYVAL ct32 (per 16-byte block)", "polyval-ct32", 16, 16,
	     polyval_update(&ps, pk, buf_in, 16));
	polyval_setkey(pk, key, POLYVAL_IMPL_CT64);
	PRIM("POLYVAL ct64 (per 16-byte block)", "polyval-ct64", 16, 16,
	     polyval_update(&ps, pk, buf_in, 16));
	PRIM("POLYVAL table4 key setup", "polyval-t4-setkey", 16, 1,
	     polyval_setkey(pk, key, POLYVAL_IMPL_TABLE4));
	PRIM("POLYVAL table4 (per 16-byte block)", "polyval-t4", 16, 16,
	     polyval_update(&ps, pk, buf_in, 16));
	PRIM("POLYVAL table8 key setup", "polyval-t8-setkey", 16, 1,
	     polyval_setkey(pk, key, POLYVAL_IMPL_TABLE8));
	PRIM("POLYVAL table8 (per 16-byte block)", "polyval-t8", 16, 16,
	     polyval_update(&ps, pk, buf_in, 16));
#undef PRIM
}

/* ---------------- modes ---------------- */

struct result {
	int valid;
	u32 setup, enc[NSIZES], dec[NSIZES], st_setup, st_crypt;
};

static struct result results[NMODES];

static void bench_mode(const struct mode *m, struct result *r)
{
	struct job j = {m, 0};
	size_t i;

	r->valid = 0;
	if (!available(m))
		return;
	mode_setkey(m);
	if (!mode_backends_ok(m)) {
		xprintf("ERROR: %s: a backend was not available\n", m->id);
		return;
	}
	MIN_OVER_TRIES(r->setup, mode_setkey(m));
	for (i = 0; i < MAX_LEN; i++)
		buf_in[i] = (u8)(i * 31 + 7);
	for (i = 0; i < NSIZES; i++) {
		const size_t len = sizes[i];

		MIN_OVER_TRIES(r->enc[i], mode_crypt(m, buf_out, buf_in, len, 1));
		MIN_OVER_TRIES(r->dec[i], mode_crypt(m, buf_in, buf_out, len, 0));
	}
	for (i = 0; i < MAX_LEN; i++) {
		if (buf_in[i] != (u8)(i * 31 + 7)) {
			xprintf("ERROR: %s: decryption did not restore the plaintext\n", m->id);
			return;
		}
	}
	r->st_setup = stack_depth(&j);
	j.what = 1;
	r->st_crypt = stack_depth(&j);
	j.what = 2;
	{
		const u32 d = stack_depth(&j);

		if (d > r->st_crypt)
			r->st_crypt = d;
	}
	r->valid = 1;
}

static void print_table(int dec)
{
	size_t i, k;

	xprintf("\n%s, cycles per byte (AES-128)\n", dec ? "Decryption" : "Encryption");
	xprintf("  %-40s", "mode");
	for (k = 0; k < NSIZES; k++)
		xprintf(" %7u", (unsigned)sizes[k]);
	xprintf("\n");
	for (i = 0; i < NMODES; i++) {
		if (!results[i].valid)
			continue;
		xprintf("  %-40s", modes[i].label);
		for (k = 0; k < NSIZES; k++)
			print_ratio(dec ? results[i].dec[k] : results[i].enc[k], sizes[k], 8);
		xprintf("\n");
	}
}

void run_benchmarks(void)
{
	size_t i, k;

	for (i = 0; i < MAX_LEN; i++)
		buf_in[i] = (u8)(i * 31 + 7);
	for (i = 0; i < sizeof(key); i++)
		key[i] = (u8)(7 * i + 3);
	for (i = 0; i < sizeof(tweak); i++)
		tweak[i] = (u8)(5 * i);
	calibrate();
	xprintf("\nBenchmark: AES-128, 16-byte tweak, minimum of %d runs, counter at %u Hz "
		"(read overhead %u cycles subtracted)\n",
		BENCH_NTRIES, (unsigned)platform_cycles_hz(), (unsigned)overhead);
	xprintf("Hardware: ECB peripheral %s, CryptoCell-310 %s\n",
		platform_has_ecb() ? "yes" : "no", platform_has_cc310() ? "yes" : "no");
	bench_primitives();
	for (i = 0; i < NMODES; i++)
		bench_mode(&modes[i], &results[i]);

	print_table(0);
	print_table(1);
	xprintf("\nKey setup and memory\n");
	xprintf("  %-40s %10s %8s %8s %8s\n", "mode", "setup cyc", "ctx B", "stk set",
		"stk enc");
	for (i = 0; i < NMODES; i++) {
		const struct result *r = &results[i];

		if (!r->valid)
			continue;
		xprintf("  %-40s %10u %8u %8u %8u\n", modes[i].label, (unsigned)r->setup,
			(unsigned)ctx_size(&modes[i]), (unsigned)r->st_setup,
			(unsigned)r->st_crypt);
	}
	for (i = 0; i < NMODES; i++) {
		const struct result *r = &results[i];

		if (!r->valid)
			continue;
		for (k = 0; k < NSIZES; k++)
			xprintf("CSV,%s,%u,%u,%u\n", modes[i].id, (unsigned)sizes[k],
				(unsigned)r->enc[k], (unsigned)r->dec[k]);
		xprintf("CSV,%s,setup,%u,0\n", modes[i].id, (unsigned)r->setup);
		xprintf("CSV,%s,ctx,%u,0\n", modes[i].id, (unsigned)ctx_size(&modes[i]));
		xprintf("CSV,%s,stack,%u,%u\n", modes[i].id, (unsigned)r->st_setup,
			(unsigned)r->st_crypt);
	}
}
