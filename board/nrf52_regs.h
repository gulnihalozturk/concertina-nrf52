/*
 * The few nRF52840 / nRF52832 and Cortex-M4 registers used by this firmware.
 * All addresses are identical on the two chips (checked against Nordic's
 * nrf52840.svd and nrf52.svd in nrfx). Kept minimal so that the project
 * builds with nothing but arm-none-eabi-gcc; in an nRF Connect SDK / nrfx
 * project use the MDK headers instead.
 */
#pragma once
#include <stdint.h>

#define REG32(addr) (*(volatile uint32_t *)(uintptr_t)(addr))

/* FICR / UICR; FICR words 0x130/0x134 identify the build code (as used by
 * nrfx's nrf52_erratas.h) */
#define FICR_HW_VAR1        REG32(0x10000130u)
#define FICR_HW_VAR2        REG32(0x10000134u)
#define FICR_INFO_PART      REG32(0x10000100u)
#define FICR_INFO_VARIANT   REG32(0x10000104u)
#define FICR_INFO_RAM       REG32(0x1000010Cu) /* kB */
#define FICR_INFO_FLASH     REG32(0x10000110u) /* kB */
#define UICR_APPROTECT      REG32(0x10001208u)

/* CLOCK (0x40000000) */
#define CLOCK_TASKS_HFCLKSTART   REG32(0x40000000u)
#define CLOCK_EVENTS_HFCLKSTARTED REG32(0x40000100u)
/* APPROTECT (0x40000000), on build codes that support it (rev. 3 and later) */
#define APPROTECT_DISABLE        REG32(0x40000558u)
#define APPROTECT_SWDISABLE      0x5Au
#define UICR_APPROTECT_HWDISABLED 0x5Au

/* UARTE0 (0x40002000) */
#define UARTE0_BASE 0x40002000u
#define UARTE0_TASKS_STARTTX  REG32(UARTE0_BASE + 0x008u)
#define UARTE0_TASKS_STOPTX   REG32(UARTE0_BASE + 0x00Cu)
#define UARTE0_EVENTS_ENDTX   REG32(UARTE0_BASE + 0x120u)
#define UARTE0_EVENTS_TXSTOPPED REG32(UARTE0_BASE + 0x158u)
#define UARTE0_ENABLE         REG32(UARTE0_BASE + 0x500u)
#define UARTE0_PSEL_RTS       REG32(UARTE0_BASE + 0x508u)
#define UARTE0_PSEL_TXD       REG32(UARTE0_BASE + 0x50Cu)
#define UARTE0_PSEL_CTS       REG32(UARTE0_BASE + 0x510u)
#define UARTE0_PSEL_RXD       REG32(UARTE0_BASE + 0x514u)
#define UARTE0_BAUDRATE       REG32(UARTE0_BASE + 0x524u)
#define UARTE0_TXD_PTR        REG32(UARTE0_BASE + 0x544u)
#define UARTE0_TXD_MAXCNT     REG32(UARTE0_BASE + 0x548u)
#define UARTE0_TXD_AMOUNT     REG32(UARTE0_BASE + 0x54Cu)
#define UARTE0_CONFIG         REG32(UARTE0_BASE + 0x56Cu)
#define UARTE_ENABLE_ENABLED  8u
#define UARTE_BAUDRATE_115200 0x01D60000u
#define PSEL_DISCONNECTED     0xFFFFFFFFu

/* ECB (0x4000E000): AES-128 in ECB mode with EasyDMA */
#define ECB_BASE 0x4000E000u
#define ECB_TASKS_STARTECB   REG32(ECB_BASE + 0x000u)
#define ECB_TASKS_STOPECB    REG32(ECB_BASE + 0x004u)
#define ECB_EVENTS_ENDECB    REG32(ECB_BASE + 0x100u)
#define ECB_EVENTS_ERRORECB  REG32(ECB_BASE + 0x104u)
#define ECB_INTENCLR         REG32(ECB_BASE + 0x308u)
#define ECB_ECBDATAPTR       REG32(ECB_BASE + 0x504u)

/* NVMC (0x4001E000): instruction cache */
#define NVMC_ICACHECNF       REG32(0x4001E540u)
#define NVMC_ICACHECNF_CACHEEN 1u

/* GPIO P0 (0x50000000) */
#define P0_OUTSET  REG32(0x50000508u)
#define P0_OUTCLR  REG32(0x5000050Cu)
#define P0_DIRSET  REG32(0x50000518u)
#define P0_PIN_CNF(n) REG32(0x50000700u + 4u * (n))

/* Cortex-M4 debug and system control */
#define DWT_CTRL    REG32(0xE0001000u)
#define DWT_CYCCNT  REG32(0xE0001004u)
#define DWT_CTRL_CYCCNTENA 1u
#define DEMCR       REG32(0xE000EDFCu)
#define DEMCR_TRCENA (1u << 24)
#define SCB_CPACR   REG32(0xE000ED88u)
#define SCB_VTOR    REG32(0xE000ED08u)

/* ------------------------------------------------------------------------
 * nRF52840 only: Arm CryptoCell-310 (addresses and fields from Nordic's
 * nrf52840.svd in nrfx; programming sequences after the examples of the
 * nRF52840 Product Specification, CRYPTOCELL chapter).
 * ------------------------------------------------------------------------ */
#define CC_ENABLE              REG32(0x5002A500u)  /* CRYPTOCELL.ENABLE */
/* CC_AES */
#define CC_AES_KEY_0(i)        REG32(0x5002B400u + 4u * (i))
#define CC_AES_BUSY            REG32(0x5002B470u)
#define CC_AES_REMAINING_BYTES REG32(0x5002B4BCu)
#define CC_AES_CONTROL         REG32(0x5002B4C0u)
#define CC_AES_CONTROL_DECRYPT 1u            /* DEC_KEY0 */
#define CC_AES_CONTROL_ECB     (0u << 2)     /* MODE_KEY0 */
#define CC_AES_CONTROL_NK128   (0u << 12)    /* NK_KEY0 */
/* CC_HASH */
#define CC_HASH_H(i)           REG32(0x5002B640u + 4u * (i))
#define CC_HASH_PAD_AUTO       REG32(0x5002B684u)
#define CC_HASH_CONTROL        REG32(0x5002B7C0u)
#define CC_HASH_CONTROL_SHA256 2u
#define CC_HASH_PAD            REG32(0x5002B7C4u)
#define CC_HASH_PAD_FORCE      REG32(0x5002B7C8u)
#define CC_HASH_ENDIANNESS     REG32(0x5002B7E8u)
/* CC_CTL */
#define CC_CRYPTO_CTL          REG32(0x5002B900u)
#define CC_CRYPTO_CTL_AES      0x01u
#define CC_CRYPTO_CTL_HASH     0x07u
#define CC_CRYPTO_BUSY         REG32(0x5002B910u)
#define CC_HASH_BUSY           REG32(0x5002B91Cu)
/* CC_DIN / CC_DOUT (DMA; memory side reads and writes SRAM only) */
#define CC_DIN_SRC_MEM_ADDR    REG32(0x5002BC28u)
#define CC_DIN_SRC_MEM_SIZE    REG32(0x5002BC2Cu)  /* writing starts the DMA */
#define CC_DOUT_DST_MEM_ADDR   REG32(0x5002BD28u)
#define CC_DOUT_DST_MEM_SIZE   REG32(0x5002BD2Cu)
#define CC_DMA_MAX             65535u              /* 2^16 - 1 bytes per DMA */
/* CC_HOST_RGF */
#define CC_IRR                 REG32(0x5002BA00u)
#define CC_IMR                 REG32(0x5002BA04u)
#define CC_ICR                 REG32(0x5002BA08u)
#define CC_IRR_MEM_TO_DIN      (1u << 6)
#define CC_IRR_DOUT_TO_MEM     (1u << 7)
#define CC_IRR_AHB_ERR         (1u << 8)
#define CC_HOST_SIGNATURE      REG32(0x5002BA24u)  /* reads 0x20E00000 */
#define CC_HOST_SIGNATURE_VAL  0x20E00000u
/* CC_MISC */
#define CC_MISC_AES_CLK        REG32(0x5002B810u)
#define CC_MISC_HASH_CLK       REG32(0x5002B818u)
#define CC_MISC_DMA_CLK        REG32(0x5002B820u)
