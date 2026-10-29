"""Model of the nRF52840 CRYPTOCELL (Arm CryptoCell-310) for nrf52_emu.py.

Only the parts the firmware's driver (board/cc310_nrf52840.c) uses are
modelled; anything else is reported as an error instead of being guessed:

  AES engine   CRYPTO_CTL = AES, AES_CONTROL = ECB with a 128-bit key
               (encrypt or decrypt), one DMA transfer from DIN_SRC_MEM to
               DOUT_DST_MEM of a multiple of 16 bytes
  HASH engine  CRYPTO_CTL = HASH, HASH_CONTROL = SHA-256, HASH_PAD_AUTO = 0
               (no hardware padding), whole 64-byte blocks from DIN_SRC_MEM;
               the chaining value is taken from and returned in HASH_H[0..7]

Register addresses and reset values: Nordic's nrf52840.svd. Semantics that
the SVD leaves open follow Arm's drivers for the CryptoCell-312 (its runtime
and the TF-M v2.0.0 cc3xx driver), whose registers have the same offsets: key word i of AES_KEY_0 =
little-endian word of key bytes 4i..4i+3; HASH_H[i] = Hi as a number; message
words big-endian (HASH_ENDIANNESS reset value 1). The model checks the
documented constraints: subsystem and engine clocks enabled, DMA addresses in
SRAM (else AHB error), transfer size at most 2^16 - 1 bytes, key registers
written in ascending order and HASH_H in descending order (the AES and
HASH programming examples of the nRF52840 PS, CRYPTOCELL chapter, which also
gives the 2^16 - 1 byte limit of a DMA transaction).

Results are computed with the `cryptography` package (AES) and with a
SHA-256 compression function written here from FIPS 180-4 and checked
against hashlib at import; neither shares code with the firmware.

Timing: the engines complete instantly; the caller adds the latency of each
transfer (op + blocks * per-block cost) to the cycle counter.
"""
import hashlib
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CC_BASE, CC_SIZE = 0x5002A000, 0x2000

ENABLE = 0x5002A500
AES_KEY_0 = 0x5002B400            # [0..7]
AES_BUSY = 0x5002B470
AES_REMAINING_BYTES = 0x5002B4BC
AES_CONTROL = 0x5002B4C0
AES_HW_FLAGS = 0x5002B4C8
HASH_H = 0x5002B640               # [0..7]
HASH_PAD_AUTO = 0x5002B684
HASH_CONTROL = 0x5002B7C0
HASH_PAD = 0x5002B7C4
HASH_PAD_FORCE = 0x5002B7C8
HASH_HW_FLAGS = 0x5002B7DC
HASH_ENDIANNESS = 0x5002B7E8
MISC_AES_CLK = 0x5002B810
MISC_HASH_CLK = 0x5002B818
MISC_DMA_CLK = 0x5002B820
CLK_STATUS = 0x5002B824
CRYPTO_CTL = 0x5002B900
CRYPTO_BUSY = 0x5002B910
HASH_BUSY = 0x5002B91C
IRR = 0x5002BA00
IMR = 0x5002BA04
ICR = 0x5002BA08
HOST_SIGNATURE = 0x5002BA24
DIN_SRC_MEM_ADDR = 0x5002BC28
DIN_SRC_MEM_SIZE = 0x5002BC2C
DOUT_DST_MEM_ADDR = 0x5002BD28
DOUT_DST_MEM_SIZE = 0x5002BD2C

IRR_MEM_TO_DIN, IRR_DOUT_TO_MEM, IRR_AHB_ERR = 1 << 6, 1 << 7, 1 << 8
DMA_MAX = 0xFFFF

RESET = {
    AES_HW_FLAGS: 0x108,          # USE_5_SBOXES, CTR_EXIST; no 192/256-bit keys
    HASH_HW_FLAGS: 0x12001,       # SHA_256_EXISTS, PAD_EXISTS, CW = 1
    HASH_PAD: 1,
    HASH_ENDIANNESS: 1,
    CLK_STATUS: 0x100,
    HOST_SIGNATURE: 0x20E00000,
}
READ_ONLY = {AES_BUSY, AES_HW_FLAGS, HASH_HW_FLAGS, CLK_STATUS, CRYPTO_BUSY, HASH_BUSY,
             IRR, HOST_SIGNATURE}

# --------------------------------------------------------------- SHA-256
_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2]
_IV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
       0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
_M = 0xFFFFFFFF


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & _M


def sha256_compress(h, block):
    """FIPS 180-4, 6.2.2: one compression of a 64-byte block."""
    w = list(struct.unpack(">16I", block))
    for t in range(16, 64):
        s0 = _rotr(w[t - 15], 7) ^ _rotr(w[t - 15], 18) ^ (w[t - 15] >> 3)
        s1 = _rotr(w[t - 2], 17) ^ _rotr(w[t - 2], 19) ^ (w[t - 2] >> 10)
        w.append((w[t - 16] + s0 + w[t - 7] + s1) & _M)
    a, b, c, d, e, f, g, hh = h
    for t in range(64):
        t1 = (hh + (_rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)) + ((e & f) ^ (~e & g))
              + _K[t] + w[t]) & _M
        t2 = ((_rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) & _M
        a, b, c, d, e, f, g, hh = (t1 + t2) & _M, a, b, c, (d + t1) & _M, e, f, g
    return [(x + y) & _M for x, y in zip(h, (a, b, c, d, e, f, g, hh))]


def _self_check():
    for msg in (b"", b"abc", bytes(range(200))):
        n = len(msg)
        padded = msg + b"\x80" + b"\0" * ((55 - n) % 64) + struct.pack(">Q", 8 * n)
        h = _IV
        for i in range(0, len(padded), 64):
            h = sha256_compress(h, padded[i:i + 64])
        if struct.pack(">8I", *h) != hashlib.sha256(msg).digest():
            raise SystemExit("cryptocell.py: SHA-256 model self-check failed")


_self_check()


class CryptoCell310:
    def __init__(self, uc, ram_base, ram_size, profile, add_latency):
        self.uc = uc
        self.ram = (ram_base, ram_base + ram_size)
        self.prof = profile
        self.add_latency = add_latency       # callback(cycles)
        self.regs = dict(RESET)
        self.errors = []
        self.key_next = 0
        self.hash_prev = None
        self.aes_ops = self.aes_blocks = self.hash_ops = self.hash_blocks = 0
        self.aes_dec_ops = 0

    def _err(self, msg):
        if len(self.errors) < 20:
            self.errors.append("CryptoCell: " + msg)

    # ------------------------------------------------------------ MMIO
    def read(self, uc, offset, size, _):
        addr = CC_BASE + offset
        if addr != ENABLE and not self.regs.get(ENABLE, 0) & 1:
            self._err(f"read of {addr:#010x} while CRYPTOCELL.ENABLE = 0")
        return self.regs.get(addr, 0)

    def write(self, uc, offset, size, value, _):
        addr = CC_BASE + offset
        if addr != ENABLE and not self.regs.get(ENABLE, 0) & 1:
            self._err(f"write to {addr:#010x} while CRYPTOCELL.ENABLE = 0")
            return
        if addr in READ_ONLY:
            self._err(f"write to read-only register {addr:#010x}")
            return
        if addr == ICR:
            self.regs[IRR] = self.regs.get(IRR, 0) & ~value
            return
        if AES_KEY_0 <= addr < AES_KEY_0 + 32:
            i = (addr - AES_KEY_0) // 4
            if i not in (0, self.key_next):
                self._err(f"AES_KEY_0[{i}] written out of ascending order")
            self.key_next = i + 1
        if HASH_H <= addr < HASH_H + 32:
            i = (addr - HASH_H) // 4
            if i != 7 and i != (self.hash_prev - 1 if self.hash_prev else None):
                self._err(f"HASH_H[{i}] written out of descending order")
            self.hash_prev = i
        self.regs[addr] = value & 0xFFFFFFFF
        if addr == DIN_SRC_MEM_SIZE:
            self._start(value)

    # ------------------------------------------------------------- DMA
    def _in_ram(self, ptr, n):
        return self.ram[0] <= ptr and ptr + n <= self.ram[1]

    def _start(self, n):
        r = self.regs
        mode = r.get(CRYPTO_CTL, 0)
        src = r.get(DIN_SRC_MEM_ADDR, 0)
        if not r.get(MISC_DMA_CLK, 0) & 1:
            self._err("DMA started with the DMA clock disabled")
        if not 0 < n <= DMA_MAX:
            self._err(f"DMA size {n} outside 1..65535")
            return
        if mode == 1:
            self._aes(src, n)
        elif mode == 7:
            self._hash(src, n)
        else:
            self._err(f"CRYPTO_CTL = {mode}: flow not modelled")

    def _aes(self, src, n):
        r = self.regs
        ctl = r.get(AES_CONTROL, 0)
        dst, dn = r.get(DOUT_DST_MEM_ADDR, 0), r.get(DOUT_DST_MEM_SIZE, 0)
        if not r.get(MISC_AES_CLK, 0) & 1:
            self._err("AES transfer with the AES clock disabled")
        if ctl & ~1:
            self._err(f"AES_CONTROL = {ctl:#x}: only ECB with a 128-bit key is modelled")
            return
        if self.key_next != 4:
            self._err("AES key not loaded (AES_KEY_0[0..3])")
        if n % 16 or dn != n:
            self._err(f"AES transfer of {n} bytes to a {dn}-byte destination")
            return
        if not (self._in_ram(src, n) and self._in_ram(dst, n)):
            self._err(f"AES DMA address outside SRAM ({src:#010x} -> {dst:#010x})")
            r[IRR] = r.get(IRR, 0) | IRR_AHB_ERR | IRR_MEM_TO_DIN | IRR_DOUT_TO_MEM
            return
        key = struct.pack("<4I", *(r.get(AES_KEY_0 + 4 * i, 0) for i in range(4)))
        c = Cipher(algorithms.AES(key), modes.ECB())
        op = c.decryptor() if ctl & 1 else c.encryptor()
        data = bytes(self.uc.mem_read(src, n))
        self.uc.mem_write(dst, op.update(data) + op.finalize())
        self.aes_ops += 1
        self.aes_dec_ops += ctl & 1
        self.aes_blocks += n // 16
        self.add_latency(self.prof["aes_op"] + self.prof["aes_blk"] * (n // 16))
        r[IRR] = r.get(IRR, 0) | IRR_MEM_TO_DIN | IRR_DOUT_TO_MEM

    def _hash(self, src, n):
        r = self.regs
        if not r.get(MISC_HASH_CLK, 0) & 1:
            self._err("HASH transfer with the HASH clock disabled")
        if r.get(HASH_CONTROL, 0) != 2:
            self._err(f"HASH_CONTROL = {r.get(HASH_CONTROL, 0)}: only SHA-256 is modelled")
            return
        if r.get(HASH_PAD_AUTO, 0) & 1 or r.get(HASH_PAD, 0) != 1:
            self._err("hardware padding configuration not modelled "
                      "(expected HASH_PAD = 1, HASH_PAD_AUTO = 0)")
            return
        if r.get(HASH_PAD_FORCE, 0):
            self._err("HASH_PAD_FORCE set: forced padding not modelled")
            return
        if r.get(HASH_ENDIANNESS, 1) != 1:
            self._err("little-endian HASH data not modelled")
            return
        if self.hash_prev != 0:
            self._err("HASH_H not loaded (HASH_H[7..0])")
        if n % 64:
            self._err(f"HASH transfer of {n} bytes: not whole blocks without padding")
            return
        if not self._in_ram(src, n):
            self._err(f"HASH DMA address outside SRAM ({src:#010x})")
            r[IRR] = r.get(IRR, 0) | IRR_AHB_ERR | IRR_MEM_TO_DIN
            return
        h = [r.get(HASH_H + 4 * i, 0) for i in range(8)]
        data = bytes(self.uc.mem_read(src, n))
        for i in range(0, n, 64):
            h = sha256_compress(h, data[i:i + 64])
        for i, v in enumerate(h):
            r[HASH_H + 4 * i] = v
        self.hash_prev = None
        self.hash_ops += 1
        self.hash_blocks += n // 64
        self.add_latency(self.prof["hash_op"] + self.prof["hash_blk"] * (n // 64))
        r[IRR] = r.get(IRR, 0) | IRR_MEM_TO_DIN
