#!/usr/bin/env python3
"""Runs the nRF52840 or nRF52832 firmware image (build/<chip>/concertina.elf)
in an emulated Cortex-M4 with a small model of the peripherals it uses.

CPU: Unicorn 2 (QEMU's ARM core) in M-profile/Thumb-2 mode, Cortex-M4 model.
Memory map of the chip (--chip):
  nrf52840: 1 MiB flash at 0x0, 256 KiB RAM at 0x20000000
  nrf52832: 512 KiB flash, 64 KiB RAM (nRF52832-QFAA)
FICR at 0x10000000 (INFO.PART = 0x52840 / 0x52832, INFO.VARIANT = "EMU0"),
UICR at 0x10001000. The peripheral registers used here have the same
addresses on both chips.

Peripherals modelled (only what the firmware touches):
  CLOCK   0x40000000  TASKS_HFCLKSTART -> EVENTS_HFCLKSTARTED
  UARTE0  0x40002000  EasyDMA TX: TXD.PTR / TXD.MAXCNT -> console, ENDTX
                      (MAXCNT is 16 bits wide on the nRF52840, 8 on the
                      nRF52832)
  ECB     0x4000E000  AES-128 on the 48-byte ECBDATAPTR structure
                      (computed with the `cryptography` package, an
                      implementation independent of the firmware's)
  CRYPTOCELL 0x5002A000-0x5002BFFF (nRF52840 only; see CryptoCell310 below)
                      AES-128 ECB encryption/decryption and the SHA-256
                      compression function through the DMA interface
  NVMC    0x4001E000  ICACHECNF (accepted, no effect)
  GPIO P0 0x50000000  OUTSET/OUTCLR/DIRSET; the DK LEDs are reported
                      (P0.13..16 on the nRF52840 DK, P0.17..20 on the nRF52 DK)
  DWT     0xE0001000  CYCCNT = number of executed instructions, plus
                      --ecb-cycles per ECB operation, since the emulated
                      peripheral itself completes instantly. Default: the
                      t_ECB of the product specification at 64 MHz, 461 cycles
                      on the nRF52840 (7.2 us, maximum) and 384 on the
                      nRF52832 (6 us, typical). Likewise, each CryptoCell DMA
                      transfer adds the latency of the selected timing
                      profile (--cc-profile; see CC_PROFILES)
  SCS     0xE000E000  DEMCR, CPACR, ... (accepted)
EasyDMA pointers are checked to lie in RAM, as the hardware requires.

The emulator is functional, not cycle-accurate: by default CYCCNT counts
instructions, so the benchmark prints instruction counts. With
--cycle-model P, CYCCNT instead accumulates an estimate of Cortex-M4 cycles
(emu/m4_timing.py; P = taken-branch refill, 1..3). Real cycle counts must be
taken on a board (the same firmware prints DWT cycles there).

    python3 emu/nrf52_emu.py [--chip nrf52832] build/<chip>/concertina.elf
                             [--csv out.csv] [--cycle-model 2]
"""
import argparse
import struct
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from m4_timing import block_cost  # noqa: E402
from cryptocell import CC_BASE, CC_SIZE, CryptoCell310  # noqa: E402
from capstone import CS_ARCH_ARM, CS_MODE_MCLASS, CS_MODE_THUMB, Cs
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from unicorn import (UC_ARCH_ARM, UC_HOOK_BLOCK, UC_HOOK_CODE, UC_MODE_MCLASS,
                     UC_MODE_THUMB, UC_PROT_ALL, UC_PROT_READ, UC_PROT_EXEC, Uc,
                     UcError)
from unicorn.arm_const import (UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0,
                               UC_ARM_REG_SP, UC_CPU_ARM_CORTEX_M4)

CHIPS = {
    # flash, RAM, FICR INFO.PART, LED pins (active low), t_ECB in cycles,
    # TXD.MAXCNT mask
    "nrf52840": dict(flash=0x100000, ram=0x40000, part=0x52840, leds=(13, 14, 15, 16),
                     ecb=461, maxcnt=0xFFFF, cryptocell=True),
    "nrf52832": dict(flash=0x80000, ram=0x10000, part=0x52832, leds=(17, 18, 19, 20),
                     ecb=384, maxcnt=0xFF, cryptocell=False),
}
# CryptoCell-310 timing profiles, in 64 MHz cycles: a fixed cost per DMA
# transfer (start, pipeline fill, completion) and a cost per 16-byte AES block
# and per 64-byte SHA-256 block. These are estimates, not measurements:
#   fast    AES: 10 rounds x 4 cycles (AES_HW_FLAGS.USE_5_SBOXES: "each AES
#           round takes 4 cycles", nRF52840 PS); SHA-256: one round per cycle
#           (assumed); 16 cycles per transfer (assumed)
#   central AES 56 and SHA-256 151 cycles per block: the AES-128-CBC
#           (17.341 MB/s) and SHA-256 (25.903 MB/s) throughputs that wolfSSL
#           reports for the CryptoCell on an nRF52840 DK (IDE/CRYPTOCELL/
#           README.md; MB = 2^20 bytes, 64 MHz); 64 cycles per transfer
#           (assumed)
#   slow    twice the central costs, 256 cycles per transfer
# The software around each transfer (driver register writes, polling) is
# executed by the CPU model and counted separately.
CC_PROFILES = {
    "fast":    dict(aes_op=16,  aes_blk=40,  hash_op=16,  hash_blk=64),
    "central": dict(aes_op=64,  aes_blk=56,  hash_op=64,  hash_blk=151),
    "slow":    dict(aes_op=256, aes_blk=112, hash_op=256, hash_blk=302),
}

FLASH_BASE, RAM_BASE = 0x00000000, 0x20000000
FLASH_SIZE, RAM_SIZE = CHIPS["nrf52840"]["flash"], CHIPS["nrf52840"]["ram"]
FICR_BASE, UICR_BASE = 0x10000000, 0x10001000
APB_BASE, APB_SIZE = 0x40000000, 0x30000
GPIO_BASE, GPIO_SIZE = 0x50000000, 0x1000
PPB_BASE, PPB_SIZE = 0xE0000000, 0x100000

LED_PINS = {13: "LED1", 14: "LED2", 15: "LED3", 16: "LED4"}


def select_chip(name):
    global FLASH_SIZE, RAM_SIZE, LED_PINS
    c = CHIPS[name]
    FLASH_SIZE, RAM_SIZE = c["flash"], c["ram"]
    LED_PINS = {p: f"LED{i + 1}" for i, p in enumerate(c["leds"])}
    return c


class Nrf52:
    def __init__(self, elf_path, max_instructions, ecb_cycles=461, quiet_leds=False,
                 cycle_model=None, chip="nrf52840", cc_profile=None):
        self.chip = select_chip(chip)
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        self.uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_M4)
        self.cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
        self.cs.detail = cycle_model is not None
        self.model_p = cycle_model
        self.ccount = 0
        self.prev_ct = False
        self.prev_end = None
        self.max_instructions = max_instructions
        self.ecb_cycles = ecb_cycles
        self.quiet_leds = quiet_leds
        self.icount = 0
        self.block_len = {}
        self.regs = {}           # APB/GPIO register file
        self.ppb = {}            # system control space
        self.cyc_base = 0
        self.cyc_frozen = 0
        self.gpio_out = 0
        self.gpio_dir = 0
        self.console = bytearray()
        self.status = None
        self.dma_errors = []
        self.ecb_ops = 0
        self.uart_bytes = 0

        uc = self.uc
        uc.mem_map(FLASH_BASE, FLASH_SIZE, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_map(RAM_BASE, RAM_SIZE, UC_PROT_ALL)
        uc.mem_map(FICR_BASE, 0x2000, UC_PROT_READ)
        uc.mem_write(FICR_BASE, b"\xff" * 0x2000)
        uc.mem_write(FICR_BASE + 0x100, struct.pack("<I", self.chip["part"]))  # INFO.PART
        uc.mem_write(FICR_BASE + 0x104, struct.pack("<I", 0x454D5530))    # "EMU0"
        uc.mem_write(FICR_BASE + 0x10C, struct.pack("<I", RAM_SIZE // 1024))    # RAM kB
        uc.mem_write(FICR_BASE + 0x110, struct.pack("<I", FLASH_SIZE // 1024))  # flash kB
        # ROM table (CoreSight): read by the nRF52832 errata detection; the
        # zero identification registers select no errata workaround
        uc.mem_map(0xF0000000, 0x1000, UC_PROT_READ)
        uc.mmio_map(APB_BASE, APB_SIZE, self._apb_read, None, self._apb_write, None)
        uc.mmio_map(GPIO_BASE, GPIO_SIZE, self._gpio_read, None, self._gpio_write, None)
        uc.mmio_map(PPB_BASE, PPB_SIZE, self._ppb_read, None, self._ppb_write, None)
        self.cc = None
        if self.chip["cryptocell"]:
            self.cc = CryptoCell310(uc, RAM_BASE, RAM_SIZE, cc_profile or CC_PROFILES["central"],
                                    self._add_latency)
            uc.mmio_map(CC_BASE, CC_SIZE, self.cc.read, None, self.cc.write, None)

        self.symbols = self._load_elf(elf_path)
        uc.hook_add(UC_HOOK_BLOCK, self._on_block)
        halt = self.symbols["platform_halt"] & ~1
        uc.hook_add(UC_HOOK_CODE, self._on_halt, begin=halt, end=halt)

    # ------------------------------------------------------------------ ELF
    def _load_elf(self, path):
        syms = {}
        with open(path, "rb") as f:
            elf = ELFFile(f)
            for seg in elf.iter_segments():
                if seg["p_type"] != "PT_LOAD" or not seg["p_filesz"]:
                    continue
                addr = seg["p_paddr"]
                if not (FLASH_BASE <= addr < FLASH_BASE + FLASH_SIZE):
                    raise SystemExit(f"load segment at {addr:#x} is not in flash")
                self.uc.mem_write(addr, seg.data())
            for sec in elf.iter_sections():
                if isinstance(sec, SymbolTableSection):
                    for s in sec.iter_symbols():
                        if s.name:
                            syms[s.name] = s["st_value"]
        return syms

    # --------------------------------------------------------------- hooks
    def _on_block(self, uc, address, size, _):
        info = self.block_len.get((address, size))
        if info is None:
            code = bytes(uc.mem_read(address, size))
            if self.model_p is None:
                info = (sum(1 for _ in self.cs.disasm_lite(code, address)), 0, False)
            else:
                insns = list(self.cs.disasm(code, address))
                c, ct = block_cost(insns)
                info = (len(insns), c, ct)
            self.block_len[(address, size)] = info
        n, c, ct = info
        self.icount += n
        if self.model_p is not None:
            if self.prev_ct and address != self.prev_end:
                self.ccount += self.model_p                   # taken branch
            self.ccount += c
            self.prev_ct = ct
            self.prev_end = address + size
        if self.icount > self.max_instructions:
            print(f"\n[emu] instruction limit reached at pc={address:#010x}", file=sys.stderr)
            uc.emu_stop()

    def _on_halt(self, uc, address, size, _):
        self.status = uc.reg_read(UC_ARM_REG_R0)
        uc.emu_stop()

    def _cyccnt(self):
        enabled = (self.ppb.get(0xEDFC, 0) >> 24) & 1 and self.ppb.get(0x1000, 0) & 1
        if enabled:
            return (self._clock() - self.cyc_base) & 0xFFFFFFFF
        return self.cyc_frozen

    def _add_latency(self, cycles):
        self.cyc_base -= cycles                                  # peripheral latency

    def _clock(self):
        return self.icount if self.model_p is None else self.ccount

    def _dma_check(self, what, ptr, n):
        if not (RAM_BASE <= ptr and ptr + n <= RAM_BASE + RAM_SIZE):
            self.dma_errors.append(f"{what}: EasyDMA pointer {ptr:#010x} (+{n}) not in RAM")
            return False
        return True

    # ----------------------------------------------------------- APB space
    def _apb_read(self, uc, offset, size, _):
        return self.regs.get(APB_BASE + offset, 0)

    def _apb_write(self, uc, offset, size, value, _):
        addr = APB_BASE + offset
        self.regs[addr] = value
        if addr == 0x40000000 and value:                        # CLOCK HFCLKSTART
            self.regs[0x40000100] = 1
        elif addr == 0x40002008 and value:                      # UARTE0 STARTTX
            self._uarte_tx()
        elif addr == 0x4000E000 and value:                      # ECB STARTECB
            self._ecb_start()

    def _uarte_tx(self):
        r = self.regs
        if r.get(0x40002500, 0) != 8:
            self.dma_errors.append("UARTE0 STARTTX while not enabled (ENABLE != 8)")
            return
        if r.get(0x4000250C, 0xFFFFFFFF) & 0x80000000:
            self.dma_errors.append("UARTE0 STARTTX with PSEL.TXD disconnected")
        ptr, n = r.get(0x40002544, 0), r.get(0x40002548, 0) & self.chip["maxcnt"]
        if r.get(0x40002548, 0) != n:
            self.dma_errors.append(f"UARTE0 TXD.MAXCNT {r.get(0x40002548, 0)} exceeds the "
                                   f"field width of this chip")
        r[0x40002150] = 1                                        # TXSTARTED
        if n and self._dma_check("UARTE0 TXD", ptr, n):
            data = bytes(self.uc.mem_read(ptr, n))
            self.console += data
            self.uart_bytes += n
            sys.stdout.write(data.decode("latin-1").replace("\r\n", "\n"))
            sys.stdout.flush()
        r[0x4000254C] = n                                        # TXD.AMOUNT
        r[0x40002120] = 1                                        # ENDTX

    def _ecb_start(self):
        ptr = self.regs.get(0x4000E504, 0)
        if not self._dma_check("ECB ECBDATAPTR", ptr, 48):
            self.regs[0x4000E104] = 1                            # ERRORECB
            return
        blob = bytes(self.uc.mem_read(ptr, 32))
        enc = Cipher(algorithms.AES(blob[:16]), modes.ECB()).encryptor()
        self.uc.mem_write(ptr + 32, enc.update(blob[16:32]) + enc.finalize())
        self.ecb_ops += 1
        self.cyc_base -= self.ecb_cycles                         # peripheral latency
        self.regs[0x4000E100] = 1                                # ENDECB

    # ---------------------------------------------------------------- GPIO
    def _gpio_read(self, uc, offset, size, _):
        if offset == 0x504:
            return self.gpio_out
        if offset == 0x514:
            return self.gpio_dir
        return self.regs.get(GPIO_BASE + offset, 0)

    def _gpio_write(self, uc, offset, size, value, _):
        before = self.gpio_out
        if offset == 0x504:
            self.gpio_out = value
        elif offset == 0x508:
            self.gpio_out |= value
        elif offset == 0x50C:
            self.gpio_out &= ~value
        elif offset == 0x518:
            self.gpio_dir |= value
        elif offset == 0x51C:
            self.gpio_dir &= ~value
        else:
            self.regs[GPIO_BASE + offset] = value
        if not self.quiet_leds:
            for pin, name in LED_PINS.items():
                if (self.gpio_dir >> pin) & 1 and ((before ^ self.gpio_out) >> pin) & 1:
                    on = not (self.gpio_out >> pin) & 1           # active low
                    print(f"[emu] {name} {'on' if on else 'off'}", file=sys.stderr)

    def led_states(self):
        return {name: (self.gpio_dir >> p) & 1 and not (self.gpio_out >> p) & 1
                for p, name in LED_PINS.items()}

    # ----------------------------------------------------------------- PPB
    def _ppb_read(self, uc, offset, size, _):
        if offset == 0x1004:
            return self._cyccnt()
        return self.ppb.get(offset, 0)

    def _ppb_write(self, uc, offset, size, value, _):
        if offset == 0x1004:                                     # CYCCNT
            self.cyc_base = self._clock() - value
            self.cyc_frozen = value
            return
        was = self._cyccnt()
        self.ppb[offset] = value
        if offset in (0x1000, 0xEDFC):
            # the count continues from its value when the counter is
            # started, and holds while it is stopped
            self.cyc_base = self._clock() - was
            self.cyc_frozen = was

    # ----------------------------------------------------------------- run
    def run(self):
        sp, pc = struct.unpack("<II", bytes(self.uc.mem_read(0, 8)))
        self.uc.reg_write(UC_ARM_REG_SP, sp)
        try:
            self.uc.emu_start(pc | 1, 0xFFFFFFFF)
        except UcError as e:
            pcr = self.uc.reg_read(UC_ARM_REG_PC)
            lr = self.uc.reg_read(UC_ARM_REG_LR)
            name = min(((pcr - v, n) for n, v in self.symbols.items()
                        if 0 <= pcr - (v & ~1) < 0x10000), default=(0, "?"))[1]
            print(f"\n[emu] CPU error: {e} at pc={pcr:#010x} ({name}) lr={lr:#010x}",
                  file=sys.stderr)
            return 4
        return self.status


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("elf")
    ap.add_argument("--chip", default="nrf52840", choices=sorted(CHIPS))
    ap.add_argument("--csv", help="write the benchmark lines (CSV,...) to this file")
    ap.add_argument("--max-instructions", type=int, default=20_000_000_000)
    ap.add_argument("--cycle-model", type=int, metavar="P", choices=(1, 2, 3),
                    help="CYCCNT = estimated Cortex-M4 cycles, taken-branch refill P")
    ap.add_argument("--ecb-cycles", type=int, default=None,
                    help="cycles added to CYCCNT per ECB block (default: t_ECB of the "
                         "chip, 461 = 7.2 us on the nRF52840, 384 = 6 us on the nRF52832)")
    ap.add_argument("--cc-profile", default="central", choices=sorted(CC_PROFILES),
                    help="CryptoCell latency profile (nRF52840; see CC_PROFILES)")
    for k in ("aes_op", "aes_blk", "hash_op", "hash_blk"):
        ap.add_argument("--cc-" + k.replace("_", "-"), type=int, default=None,
                        help=f"override the profile's {k} (cycles)")
    args = ap.parse_args()
    prof = dict(CC_PROFILES[args.cc_profile])
    for k in prof:
        if getattr(args, "cc_" + k) is not None:
            prof[k] = getattr(args, "cc_" + k)

    if args.ecb_cycles is None:
        args.ecb_cycles = CHIPS[args.chip]["ecb"]
    what = ("executed instructions" if args.cycle_model is None else
            f"estimated Cortex-M4 cycles (emu/m4_timing.py, P={args.cycle_model})")
    cc = CHIPS[args.chip]["cryptocell"]
    print(f"[emu] {args.chip} model: Unicorn Cortex-M4 + CLOCK/UARTE0/ECB/"
          f"{'CRYPTOCELL/' if cc else ''}GPIO/DWT; "
          f"DWT->CYCCNT = {what} (+{args.ecb_cycles} per ECB block"
          + (f"; CryptoCell profile {args.cc_profile}: AES {prof['aes_op']} + "
             f"{prof['aes_blk']}/block, SHA-256 {prof['hash_op']} + {prof['hash_blk']}/block "
             f"per transfer" if cc else "") + ")", file=sys.stderr)
    emu = Nrf52(args.elf, args.max_instructions, args.ecb_cycles,
                cycle_model=args.cycle_model, chip=args.chip, cc_profile=prof)
    t0 = time.time()
    status = emu.run()
    dt = time.time() - t0
    if emu.cc:
        emu.dma_errors += emu.cc.errors
    for err in emu.dma_errors:
        print(f"[emu] peripheral error: {err}", file=sys.stderr)
    leds = ", ".join(f"{k} {'on' if v else 'off'}" for k, v in emu.led_states().items())
    print(f"\n[emu] firmware stopped in platform_halt(status={status}); "
          f"{emu.icount:,} instructions"
          + (f" (~{emu.ccount:,} est. cycles)" if args.cycle_model else "")
          + f" in {dt:.1f} s "
          f"({emu.icount / max(dt, 1e-9) / 1e6:.1f} MIPS emulated); "
          f"{emu.ecb_ops:,} ECB operations; "
          + (f"CryptoCell: {emu.cc.aes_ops:,} AES transfers ({emu.cc.aes_blocks:,} blocks, "
             f"{emu.cc.aes_dec_ops:,} decrypting), {emu.cc.hash_ops:,} SHA-256 transfers "
             f"({emu.cc.hash_blocks:,} blocks); " if emu.cc else "")
          + f"{emu.uart_bytes:,} UART bytes; {leds}",
          file=sys.stderr)
    if args.csv:
        lines = [l for l in emu.console.decode("latin-1").splitlines() if l.startswith("CSV,")]
        with open(args.csv, "w") as f:
            unit = "instructions" if args.cycle_model is None else "est_cycles"
            f.write(f"config,len,enc_{unit},dec_{unit}\n")
            for l in lines:
                f.write(l[4:].strip() + "\n")
        print(f"[emu] wrote {len(lines)} benchmark lines to {args.csv}", file=sys.stderr)
    ok = status == 0 and not emu.dma_errors
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
