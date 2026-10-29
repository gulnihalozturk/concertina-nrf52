/*
 * Common definitions for the portable (32-bit) Concertina implementation.
 *
 * Target: ARM Cortex-M4 (nRF52840). The code is plain C99 with no SIMD or
 * crypto-extension intrinsics, so it also builds on a host for testing.
 * Little-endian is assumed (Cortex-M4 on nRF52840 is little-endian).
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "A little-endian target is assumed."
#endif

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define FORCEINLINE static inline __attribute__((always_inline))
#define NOINLINE __attribute__((noinline))

/* Provided by the platform layer (board/). Never returns. */
void platform_panic(const char *what, const char *file, int line)
	__attribute__((noreturn));

#define CHECK(cond)                                                            \
	do {                                                                   \
		if (!(cond))                                                   \
			platform_panic(#cond, __FILE__, __LINE__);             \
	} while (0)

FORCEINLINE u32 load_le32(const u8 *p)
{
	u32 v;
	memcpy(&v, p, 4);
	return v;
}

FORCEINLINE void store_le32(u8 *p, u32 v) { memcpy(p, &v, 4); }

FORCEINLINE u64 load_le64(const u8 *p)
{
	u64 v;
	memcpy(&v, p, 8);
	return v;
}

FORCEINLINE void store_le64(u8 *p, u64 v) { memcpy(p, &v, 8); }

FORCEINLINE u32 load_be32(const u8 *p)
{
	return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) |
	       (u32)p[3];
}

FORCEINLINE void store_be32(u8 *p, u32 v)
{
	p[0] = (u8)(v >> 24);
	p[1] = (u8)(v >> 16);
	p[2] = (u8)(v >> 8);
	p[3] = (u8)v;
}

FORCEINLINE void store_be64(u8 *p, u64 v)
{
	store_be32(p, (u32)(v >> 32));
	store_be32(p + 4, (u32)v);
}

/* dst = a ^ b (n bytes); dst may alias a or b. */
static inline void xor_bytes(u8 *dst, const u8 *a, const u8 *b, size_t n)
{
	while (n >= 4) {
		store_le32(dst, load_le32(a) ^ load_le32(b));
		dst += 4;
		a += 4;
		b += 4;
		n -= 4;
	}
	while (n--)
		*dst++ = *a++ ^ *b++;
}

/* Zeroises key material; the volatile pointer keeps the compiler from
 * removing the stores as dead. */
static inline void wipe(void *p, size_t n)
{
	volatile u8 *v = (volatile u8 *)p;

	while (n--)
		*v++ = 0;
}
