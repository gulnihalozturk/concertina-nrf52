#!/usr/bin/env python3
"""Prints the GHASH reduction tables used by the table-based POLYVAL
(src/polyval.c): R[b] = top 16 bits of b * x^k in GHASH's bit order, for the
k = 4 or 8 bits shifted out of the low end of the 128-bit state. The 4-bit
table must equal mbed TLS's last4 (checked)."""


def red(b, nbits):
    t = b
    for _ in range(nbits):
        lsb = t & 1
        t >>= 1
        if lsb:
            t ^= 0xE1 << 120
    assert t & ((1 << 112) - 1) == 0
    return t >> 112


def main():
    r4 = [red(b, 4) for b in range(16)]
    assert r4 == [0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
                  0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0]
    for name, tab in (("polyval_r4", r4), ("polyval_r8", [red(b, 8) for b in range(256)])):
        print(f"const u16 {name}[{len(tab)}] = {{")
        for i in range(0, len(tab), 8):
            print("\t" + ", ".join(f"0x{v:04x}" for v in tab[i:i + 8]) + ",")
        print("};")


if __name__ == "__main__":
    main()
