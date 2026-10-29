#!/usr/bin/env python3
"""Unit tests of the CryptoCell-310 model (emu/cryptocell.py), independent of
the firmware: correct register sequences give FIPS 197 / FIPS 180-4 results,
and the documented restrictions are enforced.

    python3 emu/test_cryptocell.py
"""
import hashlib
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cryptocell as cc  # noqa: E402
from unicorn import UC_ARCH_ARM, UC_MODE_MCLASS, UC_MODE_THUMB, UC_PROT_ALL, Uc  # noqa: E402

RAM, RAM_SIZE, FLASH = 0x20000000, 0x40000, 0x00000000


def make():
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    uc.mem_map(FLASH, 0x10000, UC_PROT_ALL)
    uc.mem_map(RAM, RAM_SIZE, UC_PROT_ALL)
    lat = []
    m = cc.CryptoCell310(uc, RAM, RAM_SIZE, dict(aes_op=1, aes_blk=2, hash_op=3, hash_blk=4),
                         lat.append)
    return uc, m, lat


def w(m, addr, v):
    m.write(None, addr - cc.CC_BASE, 4, v, None)


def r(m, addr):
    return m.read(None, addr - cc.CC_BASE, 4, None)


def enable(m):
    w(m, cc.ENABLE, 1)
    for a in (cc.MISC_AES_CLK, cc.MISC_HASH_CLK, cc.MISC_DMA_CLK):
        w(m, a, 1)


def aes(m, key, decrypt, src, dst, n, key_order=range(4)):
    w(m, cc.CRYPTO_CTL, 1)
    w(m, cc.AES_CONTROL, 1 if decrypt else 0)
    for i in key_order:
        w(m, cc.AES_KEY_0 + 4 * i, struct.unpack_from("<I", key, 4 * i)[0])
    w(m, cc.AES_REMAINING_BYTES, n)
    w(m, cc.ICR, 0xFFFFFFFF)
    w(m, cc.DOUT_DST_MEM_ADDR, dst)
    w(m, cc.DOUT_DST_MEM_SIZE, n)
    w(m, cc.DIN_SRC_MEM_ADDR, src)
    w(m, cc.DIN_SRC_MEM_SIZE, n)


def sha(m, h, src, n):
    w(m, cc.CRYPTO_CTL, 7)
    w(m, cc.HASH_CONTROL, 2)
    w(m, cc.HASH_PAD, 1)
    w(m, cc.HASH_PAD_AUTO, 0)
    for i in range(7, -1, -1):
        w(m, cc.HASH_H + 4 * i, h[i])
    w(m, cc.ICR, 0xFFFFFFFF)
    w(m, cc.DIN_SRC_MEM_ADDR, src)
    w(m, cc.DIN_SRC_MEM_SIZE, n)
    return [r(m, cc.HASH_H + 4 * i) for i in range(8)]


fails = 0


def check(name, ok):
    global fails
    print(f"  {'ok  ' if ok else 'FAIL'} {name}")
    fails += not ok


def main():
    # FIPS 197 Appendix C.1
    key = bytes(range(16))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

    uc, m, lat = make()
    check("reset values: HOST_SIGNATURE, AES_HW_FLAGS, HASH_HW_FLAGS, HASH_ENDIANNESS",
          (m.regs[cc.HOST_SIGNATURE], m.regs[cc.AES_HW_FLAGS], m.regs[cc.HASH_HW_FLAGS],
           m.regs[cc.HASH_ENDIANNESS]) == (0x20E00000, 0x108, 0x12001, 1))
    r(m, cc.HOST_SIGNATURE)
    check("register access while ENABLE = 0 is reported", any("ENABLE = 0" in e for e in m.errors))

    uc, m, lat = make()
    enable(m)
    uc.mem_write(RAM, pt * 3)
    aes(m, key, 0, RAM, RAM + 0x100, 48)
    check("AES-128 encryption, 3 blocks (FIPS 197 C.1)",
          bytes(uc.mem_read(RAM + 0x100, 48)) == ct * 3 and not m.errors)
    check("IRR: MEM_TO_DIN and DOUT_TO_MEM set", r(m, cc.IRR) & 0xC0 == 0xC0)
    check("latency charged: op + 3 blocks", lat == [1 + 2 * 3])
    aes(m, key, 1, RAM + 0x100, RAM + 0x200, 48)
    check("AES-128 decryption", bytes(uc.mem_read(RAM + 0x200, 48)) == pt * 3 and not m.errors)

    uc, m, lat = make()
    enable(m)
    aes(m, key, 0, RAM, RAM + 0x100, 16, key_order=(0, 2, 1, 3))
    check("key words out of ascending order are reported",
          any("ascending" in e for e in m.errors))

    uc, m, lat = make()
    enable(m)
    uc.mem_write(FLASH + 0x100, pt)
    aes(m, key, 0, FLASH + 0x100, RAM, 16)
    check("DMA from flash: AHB error reported and IRR.AHB_ERR set",
          any("outside SRAM" in e for e in m.errors) and r(m, cc.IRR) & cc.IRR_AHB_ERR)

    uc, m, lat = make()
    enable(m)
    w(m, cc.MISC_AES_CLK, 0)
    aes(m, key, 0, RAM, RAM + 0x100, 16)
    check("AES with its clock disabled is reported", any("clock" in e for e in m.errors))

    uc, m, lat = make()
    enable(m)
    w(m, cc.CRYPTO_CTL, 1)
    w(m, cc.AES_CONTROL, 1 << 2)   # CBC
    w(m, cc.DOUT_DST_MEM_SIZE, 16)
    w(m, cc.DIN_SRC_MEM_SIZE, 16)
    check("unmodelled AES mode (CBC) is reported, not guessed",
          any("only ECB" in e for e in m.errors))

    # SHA-256: "abc" padded by hand, and a 2-block message, against hashlib
    uc, m, lat = make()
    enable(m)
    for msg in (b"abc", bytes(range(100))):
        n = len(msg)
        padded = msg + b"\x80" + b"\0" * ((55 - n) % 64) + struct.pack(">Q", 8 * n)
        uc.mem_write(RAM, padded)
        h = sha(m, cc._IV, RAM, len(padded))
        check(f"SHA-256 compression, {len(padded) // 64} block(s), HASH_H[i] = Hi",
              struct.pack(">8I", *h) == hashlib.sha256(msg).digest() and not m.errors)
    uc, m, lat = make()
    enable(m)
    w(m, cc.CRYPTO_CTL, 7)
    w(m, cc.HASH_CONTROL, 2)
    w(m, cc.HASH_PAD_AUTO, 1)
    for i in range(7, -1, -1):
        w(m, cc.HASH_H + 4 * i, 0)
    w(m, cc.DIN_SRC_MEM_ADDR, RAM)
    w(m, cc.DIN_SRC_MEM_SIZE, 64)
    check("hardware padding (not modelled) is reported", any("padding" in e for e in m.errors))
    uc, m, lat = make()
    enable(m)
    w(m, cc.HASH_H, 0)
    check("HASH_H written out of descending order is reported",
          any("descending" in e for e in m.errors))
    uc, m, lat = make()
    enable(m)
    sha(m, cc._IV, RAM, 70)
    check("SHA-256 transfer that is not whole blocks is reported",
          any("whole blocks" in e for e in m.errors))
    uc, m, lat = make()
    enable(m)
    aes(m, key, 0, RAM, RAM + 0x10000, 0x10000)
    check("DMA size above 2^16 - 1 is reported", any("outside 1..65535" in e for e in m.errors))

    print("CryptoCell model tests:", "all passed" if not fails else f"{fails} FAILED")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
