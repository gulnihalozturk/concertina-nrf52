/*
 * Bare-metal driver for the Arm CryptoCell-310 of the nRF52840: AES-128 in
 * ECB mode (encryption and decryption, several blocks per DMA transfer) and
 * the SHA-256 compression function from a given chaining state.
 *
 * Register addresses and fields: Nordic's nrf52840.svd (nrfx). Programming
 * sequences: the AES and HASH examples of the nRF52840 Product
 * Specification (CRYPTOCELL chapter). Where the PS leaves a detail open, the
 * driver does what Arm's own CryptoCell drivers do (the CC312 runtime and the
 * cc3xx driver shipped with TF-M v2.0.0, which program the same registers at
 * the same offsets):
 *   - AES key words are written in ascending order, word i loaded
 *     little-endian from key bytes 4i..4i+3 (TF-M cc3xx_aes.c, set_key()).
 *   - The SHA-256 chaining value H0..H7 goes to HASH_H[0..7] (HASH_H[i] = Hi
 *     as a number), written in descending order and read back after the
 *     transfer (CC312 runtime hash_driver.c, which loads HASH_H0 with
 *     0x6a09e667). HASH_PAD = 1 and HASH_PAD_AUTO = 0, as that driver does for
 *     every update that is not the last one: the hardware then hashes whole
 *     blocks without padding. The caller pads in software, so that a hash
 *     can be continued from any saved state (HMAC with precomputed ipad/opad
 *     states). HASH_ENDIANNESS is set to 1 (big-endian message words, its reset
 *     value) and HASH_PAD_FORCE to 0 explicitly, rather than relying on the
 *     state another driver may have left.
 * The DMA reads and writes SRAM only; data elsewhere (flash) goes through a
 * bounce buffer. One DMA transfer is limited to 2^16 - 1 bytes.
 *
 * This driver follows the documented register interface. Nordic documents
 * the registers "for reference" and recommends its SDK library; the driver
 * has been run on the emulator's model of the CryptoCell, not on silicon.
 */
#include "nrf52_regs.h"
#include "platform.h"

#define RAM_START 0x20000000u
#define RAM_END   0x20040000u
#define BOUNCE    256u /* bytes; multiple of 64 */

static u8 bounce[BOUNCE] __attribute__((aligned(4)));
static int cc_ready;

static int in_ram(const void *p, size_t n)
{
	const u32 a = (u32)(uintptr_t)p;

	return a >= RAM_START && a + n <= RAM_END;
}

static void cc310_init(void)
{
	CC_ENABLE = 1; /* the subsystem registers are accessible once enabled */
	if (CC_HOST_SIGNATURE != CC_HOST_SIGNATURE_VAL)
		platform_panic("CryptoCell-310 not found", __FILE__, __LINE__);
	CC_MISC_AES_CLK = 1;
	CC_MISC_HASH_CLK = 1;
	CC_MISC_DMA_CLK = 1;
	CC_ICR = 0xFFFFFFFFu;
	cc_ready = 1;
}

/* One DMA transfer through the AES engine (in, out in SRAM). */
static void aes_dma(const u8 key[16], int decrypt, const u8 *in, u8 *out, u32 n)
{
	int i;

	while (CC_CRYPTO_BUSY)
		;
	CC_CRYPTO_CTL = CC_CRYPTO_CTL_AES;
	CC_AES_CONTROL = (decrypt ? CC_AES_CONTROL_DECRYPT : 0) | CC_AES_CONTROL_ECB |
			 CC_AES_CONTROL_NK128;
	for (i = 0; i < 4; i++) /* ascending order */
		CC_AES_KEY_0(i) = load_le32(key + 4 * i);
	CC_AES_REMAINING_BYTES = n;
	CC_ICR = CC_IRR_MEM_TO_DIN | CC_IRR_DOUT_TO_MEM;
	CC_DOUT_DST_MEM_ADDR = (u32)(uintptr_t)out;
	CC_DOUT_DST_MEM_SIZE = n;
	CC_DIN_SRC_MEM_ADDR = (u32)(uintptr_t)in;
	__asm volatile("dsb" ::: "memory");
	CC_DIN_SRC_MEM_SIZE = n; /* starts the transfer */
	while (!(CC_IRR & CC_IRR_DOUT_TO_MEM))
		;
	if (CC_IRR & CC_IRR_AHB_ERR)
		platform_panic("CryptoCell DMA error", __FILE__, __LINE__);
	__asm volatile("dsb" ::: "memory");
}

void cc310_aes_ecb(const u8 key[16], int decrypt, const u8 *in, u8 *out,
		   size_t len)
{
	if (!cc_ready)
		cc310_init();
	CHECK(len % 16 == 0);
	if (!in_ram(out, len))
		platform_panic("CryptoCell output not in SRAM", __FILE__, __LINE__);
	while (len) {
		u32 n;

		if (in_ram(in, len)) {
			n = len > (CC_DMA_MAX & ~15u) ? (CC_DMA_MAX & ~15u) : (u32)len;
			aes_dma(key, decrypt, in, out, n);
		} else {
			n = len > BOUNCE ? BOUNCE : (u32)len;
			memcpy(bounce, in, n);
			aes_dma(key, decrypt, bounce, out, n);
		}
		in += n;
		out += n;
		len -= n;
	}
}

/* One DMA transfer through the HASH engine (in SRAM, n multiple of 64). */
static void hash_dma(u32 st[8], const u8 *in, u32 n)
{
	int i;

	while (CC_HASH_BUSY)
		;
	CC_CRYPTO_CTL = CC_CRYPTO_CTL_HASH;
	CC_HASH_CONTROL = CC_HASH_CONTROL_SHA256;
	CC_HASH_PAD = 1;       /* as Arm's driver for a non-final update; */
	CC_HASH_PAD_AUTO = 0;  /* no padding: the caller pads in software */
	CC_HASH_PAD_FORCE = 0; /* in case another driver left it set */
	CC_HASH_ENDIANNESS = 1; /* big-endian message words (its reset value) */
	for (i = 7; i >= 0; i--) /* descending order */
		CC_HASH_H(i) = st[i];
	CC_ICR = CC_IRR_MEM_TO_DIN;
	CC_DIN_SRC_MEM_ADDR = (u32)(uintptr_t)in;
	__asm volatile("dsb" ::: "memory");
	CC_DIN_SRC_MEM_SIZE = n; /* starts the transfer */
	while (!(CC_IRR & CC_IRR_MEM_TO_DIN))
		;
	while (CC_HASH_BUSY)
		;
	if (CC_IRR & CC_IRR_AHB_ERR)
		platform_panic("CryptoCell DMA error", __FILE__, __LINE__);
	for (i = 0; i < 8; i++)
		st[i] = CC_HASH_H(i);
}

void cc310_sha256_blocks(u32 st[8], const u8 *in, size_t nblocks)
{
	const u32 max = CC_DMA_MAX & ~63u;

	if (!cc_ready)
		cc310_init();
	while (nblocks) {
		u32 n = nblocks * 64 > max ? max : (u32)(nblocks * 64);

		if (in_ram(in, n)) {
			hash_dma(st, in, n);
		} else {
			n = n > BOUNCE ? BOUNCE : n;
			memcpy(bounce, in, n);
			hash_dma(st, bounce, n);
		}
		in += n;
		nblocks -= n / 64;
	}
}
