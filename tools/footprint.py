#!/usr/bin/env python3
"""Flash and RAM footprint of each mode on the nRF52840 or nRF52832 (Cortex-M4).

Builds board/footprint_main.c once per mode, with the compiler flags of the
firmware, AES-128 round keys only (AES_MAX_NR=10) and only the backends under
test compiled in (software references on both chips; ECB-only forward AES on
the nRF52832; CryptoCell-only AES and SHA-256 on the nRF52840), subtracts a baseline image (start-up, platform layer,
console, measuring code), and runs each image in the emulator to measure the
peak stack depth of key setup, encryption and decryption of 4096 bytes.
Reports, in bytes:
  flash   .text + .rodata + .ARM.exidx + .data initialisers
  tables  static RAM of the mode (.data + .bss, e.g. the AES tables built at
          start-up), without the context
  ctx     the per-key context (sizeof)
  stack   peak stack depth over key setup, encryption and decryption
  RAM     tables + ctx + stack
  setup   key setup of this configuration, in DWT units of the emulator:
          executed instructions, and estimated cycles (cycle model P = 2),
          each plus the modelled hardware latency (ECB: t_ECB; CryptoCell:
          the central profile)

    python3 tools/footprint.py [--chip nrf52832] [--csv results/<chip>/footprint.csv]
                               [--detail]
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
CROSS = os.environ.get("CROSS", "arm-none-eabi-")
OPT = os.environ.get("OPT", "-O2 -fno-schedule-insns").split()
CFLAGS = ["-std=gnu11", *OPT, "-mcpu=cortex-m4", "-mthumb", "-mfloat-abi=soft",
          "-Wall", "-Wextra", "-Wno-pointer-sign", "-ffunction-sections",
          "-fdata-sections", "-fno-common", "-Isrc", "-Iboard"]
CHIP = "nrf52840"
LDFLAGS = ["-T", None, "-nostartfiles", "--specs=nano.specs",
           "-Wl,--gc-sections"]
COMMON = ["board/footprint_main.c", "board/platform_nrf52.c",
          "board/startup_nrf52.c", "src/print.c"]
AES = ["src/aes.c"]
AES_DEC = ["src/aes_dec.c", "src/aes_ct.c"]
HCTR2 = AES + AES_DEC + ["src/polyval.c", "src/hctr2.c"]
SCHEME = AES + ["src/keccak.c", "src/sha256.c", "src/scheme.c"]

# Backends: AES_IMPL_SW 0, ECB 1, CC310 2, CT 3; POLYVAL ct32 0, ct64 1,
# table4 2, table8 3; SHA256_IMPL_CC310 2.
SW_AES = ["-DAES_MAX_NR=10", "-DAES_WITH_ECB=0", "-DAES_WITH_CC310=0"]
POLY = {0: ["-DPOLYVAL_WITH_CT64=0", "-DPOLYVAL_WITH_TABLE4=0", "-DPOLYVAL_WITH_TABLE8=0"],
        2: ["-DPOLYVAL_WITH_CT32=0", "-DPOLYVAL_WITH_CT64=0", "-DPOLYVAL_WITH_TABLE8=0"],
        3: ["-DPOLYVAL_WITH_CT32=0", "-DPOLYVAL_WITH_CT64=0", "-DPOLYVAL_WITH_TABLE4=0"]}
DEC_TABLE = ["-DAES_DEC_CT=0", "-DFP_AES_DEC=0"]
DEC_CT = ["-DAES_DEC_TABLE=0", "-DFP_AES_DEC=3"]
# HCTR2 uses the inverse cipher for one block per decryption: its tables
# (and the S-box of its key schedule) are kept in flash, which costs little
# time and saves RAM.
DEC_TABLE_FLASH = DEC_TABLE + ["-DAES_TABLES_IN_FLASH=1"]
SHA3_ONLY = ["-DSCHEME_WITH_SHA256=0", "-DKECCAK_WITH_REF64=0", "-DSHA256_WITH_CC310=0"]
SHA2_SW = ["-DSCHEME_WITH_SHA3=0", "-DSHA256_WITH_REF=0", "-DSHA256_WITH_CC310=0"]
SHA2_CC = ["-DSCHEME_WITH_SHA3=0", "-DSHA256_WITH_REF=0", "-DSHA256_WITH_SW=0",
           "-DFP_HASH_IMPL=2"]
ECB = ["-DAES_MAX_NR=10", "-DAES_ECB_ONLY=1", "-DFP_AES=1"]
CC = ["-DAES_MAX_NR=10", "-DAES_CC310_ONLY=1", "-DFP_AES=2"]


def hctr2(mid, label, poly, aes, dec):
    return (mid, label, ["-DFP_MODE=2", f"-DFP_POLYVAL={poly}", *POLY[poly], *aes, *dec],
            HCTR2)


# Software only (both chips): the configurations of the software benchmark.
SOFTWARE = [
    ("xts", "AES-XTS", ["-DFP_MODE=1", *SW_AES, *DEC_TABLE], AES + AES_DEC + ["src/xts.c"]),
    hctr2("hctr2", "HCTR2, POLYVAL ct32", 0, SW_AES, DEC_TABLE),
    hctr2("hctr2-t4", "HCTR2, POLYVAL table4", 2, SW_AES, DEC_TABLE),
    hctr2("hctr2-t8", "HCTR2, POLYVAL table8", 3, SW_AES, DEC_TABLE),
    ("concertina-sha3", "Concertina (HMAC-SHA3-256)",
     ["-DFP_MODE=3", "-DFP_HASH=0", *SHA3_ONLY, *SW_AES], SCHEME),
    ("concertina-sha256", "Concertina (HMAC-SHA-256)",
     ["-DFP_MODE=3", "-DFP_HASH=1", *SHA2_SW, *SW_AES], SCHEME),
]
# nRF52832: forward AES-128 only in the ECB peripheral (no software forward
# cipher); the inverse cipher of HCTR2 and AES-XTS in software.
NRF52832 = [
    ("xts-ecb", "AES-XTS, ECB (dec: table)", ["-DFP_MODE=1", *ECB, *DEC_TABLE],
     AES + AES_DEC + ["src/xts.c"]),
    hctr2("hctr2-ecb", "HCTR2 ct32, ECB, dec: table", 0, ECB, DEC_TABLE_FLASH),
    hctr2("hctr2-ecb-ctdec", "HCTR2 ct32, ECB, dec: constant-time", 0, ECB, DEC_CT),
    hctr2("hctr2-t4-ecb", "HCTR2 table4, ECB, dec: table", 2, ECB, DEC_TABLE_FLASH),
    hctr2("hctr2-t8-ecb", "HCTR2 table8, ECB, dec: table", 3, ECB, DEC_TABLE_FLASH),
    ("concertina-sha3-ecb", "Concertina (SHA3 sw), ECB",
     ["-DFP_MODE=3", "-DFP_HASH=0", *SHA3_ONLY, *ECB], SCHEME),
    ("concertina-sha256-ecb", "Concertina (SHA-256 sw), ECB",
     ["-DFP_MODE=3", "-DFP_HASH=1", *SHA2_SW, *ECB], SCHEME),
]
# nRF52840: AES-128 (both directions) and SHA-256 on the CryptoCell only.
NRF52840 = [
    ("xts-cc", "AES-XTS, CryptoCell", ["-DFP_MODE=1", *CC], AES + AES_DEC + ["src/xts.c"]),
    hctr2("hctr2-cc", "HCTR2 ct32, CryptoCell AES", 0, CC, ["-DFP_AES_DEC=2"]),
    hctr2("hctr2-t4-cc", "HCTR2 table4, CryptoCell AES", 2, CC, ["-DFP_AES_DEC=2"]),
    hctr2("hctr2-t8-cc", "HCTR2 table8, CryptoCell AES", 3, CC, ["-DFP_AES_DEC=2"]),
    ("concertina-sha3-cc", "Concertina (SHA3 sw), CryptoCell AES",
     ["-DFP_MODE=3", "-DFP_HASH=0", *SHA3_ONLY, *CC], SCHEME),
    ("concertina-sha256-cc", "Concertina, SHA-256+AES CryptoCell",
     ["-DFP_MODE=3", "-DFP_HASH=1", *SHA2_CC, *CC], SCHEME),
]
BASELINE = ("baseline", "start-up + platform (subtracted)", ["-DFP_MODE=0"], [])


def modes_for(chip):
    return [BASELINE] + SOFTWARE + (NRF52840 if chip == "nrf52840" else NRF52832)


def section_sizes(elf):
    out = subprocess.run([CROSS + "size", "-A", elf], capture_output=True, text=True,
                         check=True).stdout
    sizes = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].startswith("."):
            sizes[parts[0]] = int(parts[1])
    return sizes


def symbols(elf):
    out = subprocess.run([CROSS + "nm", "-S", "--size-sort", "-t", "d", elf],
                         capture_output=True, text=True, check=True).stdout
    res = {}
    for line in out.splitlines():
        p = line.split()
        if len(p) == 4:
            res[p[3]] = (p[2], int(p[1]))
    return res


def build(mode, tmp):
    mid, _, defs, srcs = mode
    elf = os.path.join(tmp, mid + ".elf")
    ld = list(LDFLAGS)
    ld[1] = f"board/{CHIP}.ld"
    common = COMMON + (["board/cc310_nrf52840.c"] if CHIP == "nrf52840" else [])
    cmd = [CROSS + "gcc", *CFLAGS, f"-DCHIP_{CHIP.upper()}", *defs, *common, *srcs, *ld,
           "-lc", "-lgcc", "-o", elf]
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if r.returncode or r.stderr.strip():
        sys.exit(f"build of {mid} failed or warned:\n{r.stderr}")
    s = section_sizes(elf)
    flash = s.get(".text", 0) + s.get(".ARM.exidx", 0) + s.get(".data", 0)
    ram = s.get(".data", 0) + s.get(".bss", 0)
    setup = []
    for extra in ([], ["--cycle-model", "2"]):
        emu = subprocess.run([sys.executable, os.path.join(ROOT, "emu", "nrf52_emu.py"),
                              "--chip", CHIP, *extra, elf], capture_output=True, text=True)
        m = re.search(r"FP ctx=(\d+) stack_setup=(\d+) stack_enc=(\d+) stack_dec=(\d+) "
                      r"setup=(\d+) roundtrip=(\w+)", emu.stdout)
        if emu.returncode or not m or m.group(6) != "ok":
            sys.exit(f"run of {mid} failed:\n{emu.stdout}\n{emu.stderr}")
        setup.append(int(m.group(5)))
    ctx, st = int(m.group(1)), [int(m.group(i)) for i in (2, 3, 4)]
    return flash, ram, symbols(elf), ctx, st, setup


def main():
    global CHIP
    ap = argparse.ArgumentParser()
    ap.add_argument("--chip", default="nrf52840", choices=("nrf52840", "nrf52832"))
    ap.add_argument("--csv")
    ap.add_argument("--detail", action="store_true", help="list the largest symbols")
    args = ap.parse_args()
    CHIP = args.chip
    with tempfile.TemporaryDirectory() as tmp:
        modes = modes_for(CHIP)
        res = {m[0]: build(m, tmp) for m in modes}
    bf, br, bsym, _, _, _ = res["baseline"]
    print(f"Footprint on {CHIP} ({' '.join(OPT)}, AES-128), bytes, baseline subtracted "
          f"(baseline: flash {bf}, static RAM {br})")
    print(f"  {'mode':36s} {'flash':>7s} {'tables':>7s} {'ctx':>6s} {'stack':>6s} "
          f"{'RAM':>6s} {'setup':>8s} {'est.cyc':>8s}   stack: setup/enc/dec")
    rows = []
    for mid, label, _, _ in modes[1:]:
        f, r, sym, ctx, st, setup = res[mid]
        tables = (r - br) - (ctx - 4)       # the baseline's ctx is an int
        stack = max(st)
        rows.append((mid, f - bf, tables, ctx, stack, tables + ctx + stack, *st, *setup))
        print(f"  {label:36s} {f - bf:7d} {tables:7d} {ctx:6d} {stack:6d} "
              f"{tables + ctx + stack:6d} {setup[0]:8d} {setup[1]:8d}   "
              f"{st[0]}/{st[1]}/{st[2]}")
        if args.detail:
            extra = sorted(((v[1], k, v[0]) for k, v in sym.items() if k not in bsym),
                           reverse=True)
            extra = [e for e in extra if e[2] in "bBdD"] + \
                [e for e in extra if e[2] not in "bBdD"][:10]
            for size, name, typ in extra:
                print(f"      {size:6d} {typ} {name}")
    if args.csv:
        with open(args.csv, "w") as f:
            f.write("mode,flash,tables,ctx,stack,ram,stack_setup,stack_enc,stack_dec,"
                    "setup,setup_est_cycles\n")
            for r in rows:
                f.write(",".join(str(x) for x in r) + "\n")
        print(f"wrote {args.csv}")


if __name__ == "__main__":
    main()
