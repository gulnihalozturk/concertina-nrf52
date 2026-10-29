#include "print.h"
#include "platform.h"

static char obuf[128];
static size_t olen;

static void flush(void)
{
	if (olen) {
		platform_write(obuf, olen);
		olen = 0;
	}
}

static void put(char c)
{
	/* Translate "\n" to "\r\n" for serial terminals. */
	if (c == '\n') {
		if (olen + 2 > sizeof(obuf))
			flush();
		obuf[olen++] = '\r';
	} else if (olen + 1 > sizeof(obuf)) {
		flush();
	}
	obuf[olen++] = c;
	if (olen == sizeof(obuf))
		flush();
}

static void pad(int n, char c)
{
	while (n-- > 0)
		put(c);
}

static void put_str(const char *s, int width, int left)
{
	int n = (int)strlen(s);

	if (!left)
		pad(width - n, ' ');
	while (*s)
		put(*s++);
	if (left)
		pad(width - n, ' ');
}

static void put_num(unsigned long long v, int neg, unsigned base, int upper,
		    int width, int left, int zero)
{
	char tmp[24];
	const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
	int n = 0, len;

	do {
		tmp[n++] = digits[v % base];
		v /= base;
	} while (v);
	len = n + (neg ? 1 : 0);
	if (left) {
		if (neg)
			put('-');
		while (n)
			put(tmp[--n]);
		pad(width - len, ' ');
		return;
	}
	if (zero) {
		if (neg)
			put('-');
		pad(width - len, '0');
	} else {
		pad(width - len, ' ');
		if (neg)
			put('-');
	}
	while (n)
		put(tmp[--n]);
}

void xvprintf(const char *fmt, va_list ap)
{
	for (; *fmt; fmt++) {
		int left = 0, zero = 0, width = 0, lng = 0, sz = 0;

		if (*fmt != '%') {
			put(*fmt);
			continue;
		}
		fmt++;
		for (;; fmt++) {
			if (*fmt == '-')
				left = 1;
			else if (*fmt == '0')
				zero = 1;
			else
				break;
		}
		if (*fmt == '*') {
			width = va_arg(ap, int);
			if (width < 0) {
				left = 1;
				width = -width;
			}
			fmt++;
		}
		while (*fmt >= '0' && *fmt <= '9')
			width = 10 * width + (*fmt++ - '0');
		for (;; fmt++) {
			if (*fmt == 'l')
				lng++;
			else if (*fmt == 'z')
				sz = 1;
			else
				break;
		}
		switch (*fmt) {
		case 's': {
			const char *s = va_arg(ap, const char *);

			put_str(s ? s : "(null)", width, left);
			break;
		}
		case 'c':
			put((char)va_arg(ap, int));
			break;
		case 'd':
		case 'i': {
			long long v;

			if (lng >= 2)
				v = va_arg(ap, long long);
			else if (lng == 1)
				v = va_arg(ap, long);
			else if (sz)
				v = (long long)va_arg(ap, size_t);
			else
				v = va_arg(ap, int);
			put_num(v < 0 ? 0ull - (unsigned long long)v : (unsigned long long)v,
				v < 0, 10, 0, width, left, zero);
			break;
		}
		case 'u':
		case 'x':
		case 'X': {
			unsigned long long v;

			if (lng >= 2)
				v = va_arg(ap, unsigned long long);
			else if (lng == 1)
				v = va_arg(ap, unsigned long);
			else if (sz)
				v = va_arg(ap, size_t);
			else
				v = va_arg(ap, unsigned);
			put_num(v, 0, *fmt == 'u' ? 10 : 16, *fmt == 'X', width, left, zero);
			break;
		}
		case '%':
			put('%');
			break;
		case '\0':
			flush();
			return;
		default:
			put('%');
			put(*fmt);
			break;
		}
	}
	flush();
}

void xprintf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	xvprintf(fmt, ap);
	va_end(ap);
}

void xputs(const char *s) { xprintf("%s\n", s); }

void xprint_hex(const u8 *p, size_t n)
{
	while (n--)
		xprintf("%02x", *p++);
}
