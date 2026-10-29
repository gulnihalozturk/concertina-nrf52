/*
 * nRF52840 / nRF52832 platform layer (bare metal, no SDK required). Select
 * the chip with -DCHIP_NRF52840 (default) or -DCHIP_NRF52832.
 *
 *   console: UARTE0, TX only, 115200 8N1. Default pin P0.06, the J-Link
 *            virtual COM port of both DKs (nRF52840 DK PCA10056, nRF52 DK
 *            PCA10040). Override with -DUART_TX_PIN=<n> (on the nRF52840,
 *            pin numbers >= 32 are P1.(n-32)).
 *   cycles:  DWT->CYCCNT (CPU clock, 64 MHz)
 *   AES:     ECB peripheral (AES-128, encryption only), polled
 *   nRF52840 only: CryptoCell-310 (AES-128 encryption and decryption,
 *            SHA-256), board/cc310_nrf52840.c, enabled on first use (so
 *            that images which do not use it do not contain the driver)
 *   LEDs:    LED1..LED4 of the DK, active low: P0.13..P0.16 (nRF52840 DK),
 *            P0.17..P0.20 (nRF52 DK)
 */
#include "nrf52_regs.h"
#include "platform.h"
#include "print.h"

#if defined(CHIP_NRF52832)
static const u8 led_pins[4] = {17, 18, 19, 20};
#else
#define CHIP_NRF52840 1
static const u8 led_pins[4] = {13, 14, 15, 16};
#endif

#ifndef UART_TX_PIN
#define UART_TX_PIN 6
#endif
#ifndef LED_ACTIVE_LOW
#define LED_ACTIVE_LOW 1
#endif

/* EasyDMA can only read and write RAM. */
/* 64-byte chunks: within the 8-bit TXD.MAXCNT of the nRF52832 as well. */
static u8 tx_buf[64] __attribute__((aligned(4)));
static struct {
	u8 key[16], cleartext[16], ciphertext[16];
} ecb_data __attribute__((aligned(4)));
static int uart_ready;

#define BARRIER() __asm volatile("dsb" ::: "memory")

#if defined(CHIP_NRF52840)
void cc310_aes_ecb(const u8 key[16], int decrypt, const u8 *in, u8 *out, size_t len);
void cc310_sha256_blocks(u32 st[8], const u8 *in, size_t nblocks);

int platform_has_cc310(void) { return 1; }
void platform_cc310_aes_ecb(const u8 key[16], int decrypt, const u8 *in, u8 *out,
			    size_t len)
{
	cc310_aes_ecb(key, decrypt, in, out, len);
}
void platform_cc310_sha256_blocks(u32 st[8], const u8 *in, size_t nblocks)
{
	cc310_sha256_blocks(st, in, nblocks);
}
#else
int platform_has_cc310(void) { return 0; }
void platform_cc310_aes_ecb(const u8 key[16], int decrypt, const u8 *in, u8 *out,
			    size_t len)
{
	(void)key; (void)decrypt; (void)in; (void)out; (void)len;
	platform_panic("no CryptoCell on this chip", __FILE__, __LINE__);
}
void platform_cc310_sha256_blocks(u32 st[8], const u8 *in, size_t nblocks)
{
	(void)st; (void)in; (void)nblocks;
	platform_panic("no CryptoCell on this chip", __FILE__, __LINE__);
}
#endif

static void gpio_out(u32 pin, int high)
{
	if (pin >= 32)
		return; /* P1 pins are only used for the UART, see below */
	if (high)
		P0_OUTSET = 1u << pin;
	else
		P0_OUTCLR = 1u << pin;
	P0_DIRSET = 1u << pin;
}

void platform_init(void)
{
	u32 i;

	const u32 var1 = FICR_HW_VAR1, var2 = FICR_HW_VAR2;
	int new_approtect;

	/* Keep the debug port open on chips whose UICR says so, as nrfx's
	 * SystemInit does (nrf52_handle_approtect()): on build codes with the
	 * APPROTECT peripheral (nrf52_configuration_249()), copy UICR.APPROTECT
	 * into APPROTECT.DISABLE. */
#if defined(CHIP_NRF52832)
	new_approtect = var1 == 0x06u && !(var2 >= 0x03u && var2 <= 0x06u);
#else
	new_approtect = var1 == 0x08u && var2 > 0x04u;
#endif
	if (new_approtect)
		APPROTECT_DISABLE = UICR_APPROTECT;
#if defined(CHIP_NRF52832)
	{
		/* Errata workarounds of nrfx's SystemInit on the nRF52832, with
		 * nrfx's revision detection: 16 and 37 read the revision from
		 * the ROM table (0xF0000FE0/0xF0000FE8) and apply to the first
		 * revision only; 108 reads FICR, falling back to the ROM table
		 * when the FICR words are blank, and applies to all revisions. */
		const u32 rv1 = REG32(0xF0000FE0u) & 0xFFu;
		const u32 rv2 = (REG32(0xF0000FE8u) & 0xF0u) >> 4;
		const u32 v1 = var1 == 0xFFFFFFFFu ? rv1 : var1;

		if (rv1 == 0x06u && rv2 == 0x03u) {
			REG32(0x4007C074u) = 3131961357u; /* 16: RAM on wakeup from CPU IDLE */
			REG32(0x400005A0u) = 0x3u;        /* 37: encryption engine slow */
		}
		if (v1 == 0x06u)                      /* 108: RAM retention */
			REG32(0x40000EE4u) = REG32(0x10000258u) & 0x0000004Fu;
	}
#endif

	NVMC_ICACHECNF = NVMC_ICACHECNF_CACHEEN;

	/* 32 MHz crystal, for an accurate baud rate (bounded wait). */
	CLOCK_EVENTS_HFCLKSTARTED = 0;
	CLOCK_TASKS_HFCLKSTART = 1;
	for (i = 0; i < 2000000u && !CLOCK_EVENTS_HFCLKSTARTED; i++)
		;

	DEMCR |= DEMCR_TRCENA;
	DWT_CYCCNT = 0;
	DWT_CTRL |= DWT_CTRL_CYCCNTENA;

	for (i = 0; i < 4; i++)
		gpio_out(led_pins[i], LED_ACTIVE_LOW);

	gpio_out(UART_TX_PIN, 1);
	UARTE0_PSEL_TXD = UART_TX_PIN < 32 ? UART_TX_PIN : (1u << 5) | (UART_TX_PIN - 32);
	UARTE0_PSEL_RXD = PSEL_DISCONNECTED;
	UARTE0_PSEL_RTS = PSEL_DISCONNECTED;
	UARTE0_PSEL_CTS = PSEL_DISCONNECTED;
	UARTE0_BAUDRATE = UARTE_BAUDRATE_115200;
	UARTE0_CONFIG = 0; /* no parity, no flow control, one stop bit */
	UARTE0_ENABLE = UARTE_ENABLE_ENABLED;
	uart_ready = 1;
}

const char *platform_name(void)
{
	static char name[48];
	const u32 part = FICR_INFO_PART, var = FICR_INFO_VARIANT;
	const char hex[] = "0123456789ABCDEF";
	int n = 0, sh;

	/* e.g. "nRF52840-AAD0, Cortex-M4F @ 64 MHz" (FICR part and variant) */
#if defined(CHIP_NRF52832)
	if (part != 0x52832u)
		xprintf("WARNING: built for the nRF52832, FICR INFO.PART = %x\n", (unsigned)part);
#else
	if (part != 0x52840u)
		xprintf("WARNING: built for the nRF52840, FICR INFO.PART = %x\n", (unsigned)part);
#endif
	memcpy(name, "nRF", 3);
	n = 3;
	for (sh = 16; sh >= 0; sh -= 4)
		name[n++] = hex[(part >> sh) & 0xf];
	name[n++] = '-';
	for (sh = 24; sh >= 0; sh -= 8) {
		const char c = (char)(var >> sh);

		name[n++] = (c >= '0' && c <= 'Z') ? c : '?';
	}
	memcpy(name + n, ", Cortex-M4F @ 64 MHz", 22);
	return name;
}

void platform_write(const char *s, size_t n)
{
	if (!uart_ready)
		return;
	while (n) {
		const size_t k = n < sizeof(tx_buf) ? n : sizeof(tx_buf);

		memcpy(tx_buf, s, k);
		BARRIER();
		UARTE0_TXD_PTR = (u32)(uintptr_t)tx_buf;
		UARTE0_TXD_MAXCNT = k;
		UARTE0_EVENTS_ENDTX = 0;
		UARTE0_TASKS_STARTTX = 1;
		while (!UARTE0_EVENTS_ENDTX)
			;
		s += k;
		n -= k;
	}
}

u32 platform_cycles(void) { return DWT_CYCCNT; }
u32 platform_cycles_hz(void) { return 64000000u; }
int platform_has_ecb(void) { return 1; }

void platform_ecb_encrypt(const u8 key[16], const u8 in[16], u8 out[16])
{
	memcpy(ecb_data.key, key, 16);
	memcpy(ecb_data.cleartext, in, 16);
	ECB_INTENCLR = 0xFFFFFFFFu;
	do {
		ECB_EVENTS_ENDECB = 0;
		ECB_EVENTS_ERRORECB = 0;
		ECB_ECBDATAPTR = (u32)(uintptr_t)&ecb_data;
		BARRIER();
		ECB_TASKS_STARTECB = 1;
		while (!ECB_EVENTS_ENDECB && !ECB_EVENTS_ERRORECB)
			;
		/* ERRORECB: aborted by a higher-priority user (CCM/AAR); retry. */
	} while (ECB_EVENTS_ERRORECB);
	BARRIER();
	memcpy(out, ecb_data.ciphertext, 16);
}

void platform_led(int idx, int on)
{
	if (idx < 0 || idx > 3)
		return;
	gpio_out(led_pins[idx], LED_ACTIVE_LOW ? !on : on);
}

void platform_halt(int status)
{
	(void)status;
	for (;;)
		__asm volatile("wfe");
}

void platform_panic(const char *what, const char *file, int line)
{
	xprintf("\nPANIC: check failed: %s (%s:%d)\n", what, file, line);
	platform_led(3, 1);
	platform_halt(2);
}

/* Called from the HardFault handler with the stacked exception frame. */
void platform_fault(const u32 *frame, u32 exc_return)
{
	xprintf("\nHARD FAULT: pc=%08x lr=%08x xpsr=%08x exc_return=%08x\n",
		(unsigned)frame[6], (unsigned)frame[5], (unsigned)frame[7],
		(unsigned)exc_return);
	platform_led(3, 1);
	platform_halt(3);
}
