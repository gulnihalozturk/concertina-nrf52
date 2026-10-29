#!/usr/bin/env python3
"""Compares the primitive costs of two benchmark logs (e.g. -O2 against the
default -O2 -fno-schedule-insns build).

    python3 tools/compare_flags.py <log -O2> <log default>
"""
import re
import sys


def prims(path):
    out = {}
    for line in open(path, encoding="latin-1"):
        m = re.match(r"CSV,prim-([\w-]+),(\d+),(\d+),0", line.strip())
        if m:
            out[m.group(1)] = int(m.group(3))
    return out


def main():
    a, b = prims(sys.argv[1]), prims(sys.argv[2])
    print("Primitive cost (executed instructions, emulator): -O2 vs -O2 -fno-schedule-insns "
          "(default)")
    print(f"{'primitive':24s} {'-O2':>8s} {'default':>8s} {'change':>8s}")
    for k in b:
        if k in a:
            print(f"{k:24s} {a[k]:8d} {b[k]:8d} {100 * (b[k] - a[k]) / a[k]:+7.1f}%")


if __name__ == "__main__":
    main()
