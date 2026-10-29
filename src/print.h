/*
 * Minimal formatted output (no newlib printf, no heap). Supports
 * %s %c %d %i %u %x %X %%, the flags '-' and '0', a field width, and the
 * length modifiers l, ll and z.
 */
#pragma once
#include <stdarg.h>
#include "common.h"

void xprintf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void xvprintf(const char *fmt, va_list ap);
void xputs(const char *s);
/* Prints n bytes as hex. */
void xprint_hex(const u8 *p, size_t n);
