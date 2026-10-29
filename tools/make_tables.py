#!/usr/bin/env python3
"""Tables, figures and the paper's appendix for the microcontroller measurements
(nRF52840 and nRF52832, one section).

Inputs, per chip (make CHIP=<chip> results):
  results/<chip>/emu_results.csv                 executed instructions + hardware latency
  results/<chip>/emu_results_cycles_p{1,2,3}.csv estimated cycles (model P) + latency
  results/<chip>/emu_results_cycles_p2_*.csv     P = 2 with one latency changed
  results/<chip>/footprint.csv                   tools/footprint.py

Every benchmark time is linear in the modelled hardware latencies, and the
CPU part does not depend on them (the driver's polling loops exit on their
first test in the emulator). From the runs that set one latency to zero, the
script recovers, for every benchmark line, the exact number of hardware
operations of each kind, and splits each time into
    CPU part     executed instructions (exact) or estimated cycles (model P)
    hardware     sum over operations of (count x latency)  (estimated)
It checks that the fast and slow CryptoCell runs agree with this split.

Outputs: paper/appendix_mcu.tex (from paper/appendix_mcu.in.tex, whose
<<name>> fields are filled in with the numbers computed here),
results/table_mcu_*.tex, and a summary on stdout.

    python3 tools/make_tables.py
"""
import csv
import math
import os
import re
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
RES = os.path.join(ROOT, "results")
SIZES = ["32", "64", "256", "512", "1024", "4096"]
F_CPU = 64e6

sys.path.insert(0, os.path.join(ROOT, "emu"))
from nrf52_emu import CC_PROFILES, CHIPS  # noqa: E402

CENTRAL = dict(CC_PROFILES["central"])
# hardware latency parameters of each chip, with the value used in the
# main runs (CryptoCell: central profile; ECB: t_ECB of the PS)
PARAMS = {
    "nrf52840": dict(CENTRAL, ecb=CHIPS["nrf52840"]["ecb"]),
    "nrf52832": dict(ecb=CHIPS["nrf52832"]["ecb"]),
}
RUN_OF = {"aes_op": "no-aes-op", "aes_blk": "no-aes-blk", "hash_op": "no-hash-op",
          "hash_blk": "no-hash-blk", "ecb": "no-ecb"}

HW840 = [("xts-cc", r"AES-XTS$^\dagger$"),
         ("hctr2-cc", r"HCTR2, constant-time POLYVAL"),
         ("hctr2-t4-cc", r"HCTR2, 4-bit POLYVAL tables"),
         ("hctr2-t8-cc", r"HCTR2, 8-bit POLYVAL tables"),
         ("concertina-sha256-cc", r"Concertina (HMAC-SHA-256)"),
         ("concertina-sha3-cc", r"Concertina (HMAC-SHA3-256)")]
HW832 = [("xts-ecb", r"AES-XTS$^\dagger$"),
         ("hctr2-ecb", r"HCTR2, constant-time POLYVAL"),
         ("hctr2-t4-ecb", r"HCTR2, 4-bit POLYVAL tables"),
         ("hctr2-t8-ecb", r"HCTR2, 8-bit POLYVAL tables"),
         ("concertina-sha256-ecb", r"Concertina (HMAC-SHA-256)"),
         ("concertina-sha3-ecb", r"Concertina (HMAC-SHA3-256)")]
SW = [("xts", r"AES-XTS$^\dagger$"),
      ("hctr2", r"HCTR2, constant-time POLYVAL"),
      ("hctr2-t8", r"HCTR2, 8-bit POLYVAL tables"),
      ("concertina-sha256", r"Concertina (HMAC-SHA-256)"),
      ("concertina-sha3", r"Concertina (HMAC-SHA3-256)")]
HCTR2_840 = ("hctr2-cc", "hctr2-t4-cc", "hctr2-t8-cc")
HCTR2_832 = ("hctr2-ecb", "hctr2-t4-ecb", "hctr2-t8-ecb")
PV = {"hctr2-cc": "ct32", "hctr2-t4-cc": "table4", "hctr2-t8-cc": "table8",
      "hctr2-ecb": "ct32", "hctr2-t4-ecb": "table4", "hctr2-t8-ecb": "table8",
      "hctr2-ecb-ctdec": "ct32"}


def load(path):
    d = {}
    with open(path) as f:
        for r in csv.reader(f):
            if r and r[0] == "CSV":
                r = r[1:]
            if len(r) != 4 or r[0] == "config":
                continue
            try:
                d.setdefault(r[0], {})[r[1]] = (int(r[2]), int(r[3]))
            except ValueError:
                continue
    return d


class Chip:
    """Benchmark lines of one chip, split into CPU part and hardware part."""

    def __init__(self, chip):
        self.chip = chip
        self.res = os.path.join(RES, chip)
        self.p = PARAMS[chip]
        self.instr = load(os.path.join(self.res, "emu_results.csv"))
        self.cyc = {P: load(os.path.join(self.res, f"emu_results_cycles_p{P}.csv"))
                    for P in (1, 2, 3)}
        self.var = {}
        for k, run in RUN_OF.items():
            if k in self.p:
                self.var[k] = load(os.path.join(self.res, f"emu_results_cycles_p2_{run}.csv"))
        self.prof = {}
        for prof in ("fast", "slow"):
            path = os.path.join(self.res, f"emu_results_cycles_p2_{prof}.csv")
            if os.path.exists(path):
                self.prof[prof] = load(path)
        with open(os.path.join(self.res, "footprint.csv")) as f:
            self.fp = {r["mode"]: {k: int(v) for k, v in r.items() if k != "mode"}
                       for r in csv.DictReader(f)}
        self._check()

    def counts(self, m, s, k=0):
        """Exact number of hardware operations of each kind."""
        n = {}
        for p, v in self.p.items():
            diff = self.cyc[2][m][s][k] - self.var[p][m][s][k]
            if m.startswith("prim-"):       # some primitives print per-block averages
                n[p] = diff / v
                continue
            if diff % v:
                raise SystemExit(f"{self.chip} {m} {s}: latency {p} not linear ({diff}/{v})")
            n[p] = diff // v
        return n

    def hw(self, m, s, k=0, prof=None):
        prof = prof or self.p
        n = self.counts(m, s, k)
        return sum(prof.get(p, self.p[p]) * c for p, c in n.items())

    def instructions(self, m, s, k=0):
        return self.instr[m][s][k] - self.hw(m, s, k)

    def cpu(self, m, s, k=0, P=2):
        return self.cyc[P][m][s][k] - self.hw(m, s, k)

    def total(self, m, s, k=0, P=2, prof=None):
        return self.cpu(m, s, k, P) + self.hw(m, s, k, prof)

    def cpb(self, m, s, k=0, P=2, prof=None):
        return self.total(m, s, k, P, prof) / int(s)

    def _check(self):
        for prof, d in self.prof.items():
            pv = dict(self.p, **CC_PROFILES[prof])
            for m in d:
                for s in d[m]:
                    if s not in SIZES or m.startswith("prim-"):
                        continue
                    for k in (0, 1):
                        if d[m][s][k] != self.total(m, s, k, 2, pv):
                            raise SystemExit(f"{self.chip} {prof} {m} {s}: run "
                                             f"{d[m][s][k]} != split {self.total(m, s, k, 2, pv)}")


def rng2(lo, hi):
    """A range with two decimals, rounded outwards (so that 0.996..1.004 does
    not print as 1.00--1.00)."""
    return f"{math.floor(lo * 100) / 100:.2f}", f"{math.ceil(hi * 100) / 100:.2f}"


def fmt(v):
    """Three significant digits, as in Table 3."""
    if v >= 100:
        return f"{v:.0f}"
    if v >= 10:
        return f"{v:.1f}"
    return f"{v:.2f}"


def us(v):
    return num(round(v)) if v >= 1000 else fmt(v)


def num(v):
    return f"{v:,}".replace(",", "{,}")


def speed_table(c840, c832, k=0):
    what = "Encryption" if k == 0 else "Decryption"
    lines = [
        r"\begin{table}[!hbt]",
        r"\caption{" + what + r" cost on the nRF52840 and the nRF52832 (Arm Cortex-M4F, "
        r"64~MHz) with AES-128 and a 16-byte tweak, in estimated cycles per byte: "
        r"the CPU cycles of the executed instructions under the Cortex-M4 timing model "
        r"($P = 2$), plus the latency of each hardware operation (CryptoCell-310: central "
        r"profile of Table~\ref{tab:mcu-latency}; ECB peripheral: typical $t_\mathrm{ECB}$ "
        r"of 6~$\mu$s). The software rows are the same on both chips.}",
        r"\label{tab:mcu-" + ("speed" if k == 0 else "dec") + "}",
        r"\centering", r"\small", r"\renewcommand{\arraystretch}{1.25}",
        r"\setlength{\tabcolsep}{4pt}", r"\begin{tabular}{lrrrrrr}", r"\hline",
        r" & \multicolumn{6}{c}{Message length (bytes)} \\",
        r"Mode & " + " & ".join(SIZES) + r" \\", r"\hline\hline",
    ]
    groups = [
        (c840, HW840, r"nRF52840: AES-128 and SHA-256 on the CryptoCell-310"),
        (c832, HW832, r"nRF52832: forward AES-128 on the ECB peripheral"),
        (c840, SW, r"Software only (either chip)"),
    ]
    for i, (c, rows, title) in enumerate(groups):
        if i:
            lines.append(r"\hline")
        lines.append(r"\multicolumn{7}{l}{\emph{" + title + r"}} \\")
        for m, label in rows:
            if k == 1 and m == "hctr2-ecb":
                for mm, ll in (("hctr2-ecb", r"HCTR2, table $\mathrm{AES}^{-1}$$^\ddagger$"),
                               ("hctr2-ecb-ctdec", r"HCTR2, constant-time "
                                                    r"$\mathrm{AES}^{-1}$$^\ddagger$")):
                    lines.append(f"{ll:52s} & " + " & ".join(
                        fmt(c.cpb(mm, s, k)) for s in SIZES) + r" \\")
                continue
            lines.append(f"{label:52s} & " + " & ".join(fmt(c.cpb(m, s, k)) for s in SIZES)
                         + r" \\")
    lines += [r"\hline",
              r"\multicolumn{7}{l}{\footnotesize $^\dagger$Narrow-block mode, listed as a "
              r"reference only.}" + (r" \\" + "\n" + r"\multicolumn{7}{l}{\footnotesize "
                                     r"$^\ddagger$With the constant-time POLYVAL.}"
                                     if k == 1 else ""),
              r"\end{tabular}", r"\end{table}"]
    return "\n".join(lines) + "\n"


def memory_table(c840, c832):
    lines = [
        r"\begin{table}[!hbt]",
        r"\caption{Memory footprint with AES-128, in bytes: flash for key setup, "
        r"encryption and decryption (including the hardware drivers); static RAM (tables, "
        r"DMA buffers); per-key context; peak stack depth; and their sum (RAM). Each "
        r"configuration is built with only the backends it uses; on the nRF52832, the "
        r"tables of HCTR2's table-based inverse cipher are kept in flash (one block per "
        r"decryption), those of AES-XTS in RAM. Key setup in $\mu$s at "
        r"64~MHz, estimated as in Table~\ref{tab:mcu-speed}.}",
        r"\label{tab:mcu-memory}",
        r"\centering", r"\small", r"\renewcommand{\arraystretch}{1.25}",
        r"\setlength{\tabcolsep}{3.5pt}", r"\begin{tabular}{lrrrrrr}", r"\hline",
        r"Mode & Flash & Static & Context & Stack & RAM & Key setup \\",
        r"\hline\hline",
    ]
    rows832 = list(HW832)
    rows832.insert(2, ("hctr2-ecb-ctdec", r"HCTR2, constant-time $\mathrm{AES}^{-1}$$^\ddagger$"))
    rows832[1] = ("hctr2-ecb", r"HCTR2, table $\mathrm{AES}^{-1}$$^\ddagger$")
    groups = [(c840, HW840, r"nRF52840: AES-128 and SHA-256 on the CryptoCell-310"),
              (c832, rows832, r"nRF52832: forward AES-128 on the ECB peripheral"),
              (c840, SW, r"Software only (nRF52840 build)")]
    for i, (c, rows, title) in enumerate(groups):
        if i:
            lines.append(r"\hline")
        lines.append(r"\multicolumn{7}{l}{\emph{" + title + r"}} \\")
        for m, label in rows:
            f = c.fp[m]
            lines.append(f"{label:52s} & {num(f['flash'])} & {num(f['tables'])} & "
                         f"{num(f['ctx'])} & {num(f['stack'])} & {num(f['ram'])} & "
                         f"{us(f['setup_est_cycles'] / 64)}" + r" \\")
    lines += [r"\hline",
              r"\multicolumn{7}{l}{\footnotesize $^\dagger$Narrow-block mode, listed as a "
              r"reference only. $^\ddagger$With the constant-time POLYVAL.}",
              r"\end{tabular}", r"\end{table}"]
    return "\n".join(lines) + "\n"


def robustness_table(c840, c832, V):
    """HCTR2 time / Concertina time over the timing assumptions."""
    lines = [
        r"\begin{table}[!hbt]",
        r"\caption{Speed-up of Concertina (HMAC-SHA-256) over HCTR2 (time of HCTR2 divided "
        r"by that of Concertina; encryption, and decryption in the last row) under all combinations of the CPU timing model "
        r"($P = 1, 2, 3$) and the hardware latencies: on the nRF52840 the three CryptoCell "
        r"profiles of Table~\ref{tab:mcu-latency}, on the nRF52832 $t_\mathrm{ECB}$ = 3, 6 "
        r"and 12~$\mu$s. Minimum and maximum, rounded outwards; values above 1 favor "
        r"Concertina.}",
        r"\label{tab:mcu-robust}",
        r"\centering", r"\scriptsize", r"\renewcommand{\arraystretch}{1.25}",
        r"\setlength{\tabcolsep}{3pt}", r"\begin{tabular}{lrrrrrr}", r"\hline",
        r" & \multicolumn{6}{c}{Message length (bytes)} \\",
        r"POLYVAL of HCTR2 & " + " & ".join(SIZES) + r" \\", r"\hline\hline",
    ]
    for c, hctrs, conc, title in (
            (c840, HCTR2_840, "concertina-sha256-cc", r"nRF52840 (CryptoCell-310)"),
            (c832, HCTR2_832 + ("hctr2-ecb-ctdec",), "concertina-sha256-ecb",
             r"nRF52832 (ECB peripheral)")):
        lines.append(r"\multicolumn{7}{l}{\emph{" + title + r"}} \\")
        for h in hctrs:
            k = 1 if h == "hctr2-ecb-ctdec" else 0
            label = {"ct32": "Constant-time", "table4": "4-bit tables",
                     "table8": "8-bit tables"}[PV[h]]
            if h == "hctr2-ecb-ctdec":
                label = r"Constant-time, with $\mathrm{AES}^{-1}$ (dec.)"
            cells = []
            for s in SIZES:
                r = speedups(c, h, conc, s, k)
                lo, hi = rng2(min(r), max(r))
                cells.append(f"{lo}--{hi}")
            lines.append(f"{label:44s} & " + " & ".join(cells) + r" \\")
        lines.append(r"\hline")
    lines += [r"\end{tabular}", r"\end{table}"]
    return "\n".join(lines) + "\n"


def latency_variants(c):
    if c.chip == "nrf52840":
        return [dict(c.p, **CC_PROFILES[p]) for p in ("fast", "central", "slow")]
    return [dict(ecb=e) for e in (192, 384, 768)]


def speedups(c, h, conc, s, k=0):
    return [c.total(h, s, k, P, pv) / c.total(conc, s, k, P, pv)
            for P in (1, 2, 3) for pv in latency_variants(c)]


def main():
    c840, c832 = Chip("nrf52840"), Chip("nrf52832")
    V = {}
    out = []

    def say(*a):
        out.append(" ".join(str(x) for x in a))

    # the software rows must be the same on both chips
    for m, _ in SW:
        for s in SIZES:
            for k in (0, 1):
                a, b = c840.cyc[2][m][s][k], c832.cyc[2][m][s][k]
                if a != b:
                    say(f"NOTE: software {m} {s} differs between chips: {a} vs {b}")

    # ---- main numbers
    for c, tag in ((c840, "a"), (c832, "b")):
        say(f"== {c.chip}: estimated cycles/byte, P=2, main latencies (enc | dec) ==")
        rows = (HW840 if tag == "a" else HW832 + [("hctr2-ecb-ctdec", "")]) + SW
        for m, _ in rows:
            say(f"  {m:24s}" + " ".join(f"{c.cpb(m, s):8.1f}" for s in SIZES) + "  | "
                + " ".join(f"{c.cpb(m, s, 1):8.1f}" for s in SIZES))
        say(f"== {c.chip}: hardware operations per message (exact) ==")
        for m, _ in (HW840 if tag == "a" else HW832):
            say(f"  {m:24s}" + "  ".join(
                f"{s}:" + ",".join(f"{p}={n}" for p, n in c.counts(m, s).items() if n)
                for s in SIZES))
        say(f"== {c.chip}: CPU instructions per byte (exact) and share of hardware time "
            f"(P=2) ==")
        for m, _ in (HW840 if tag == "a" else HW832):
            say(f"  {m:24s}" + " ".join(f"{c.instructions(m, s) / int(s):8.1f}" for s in SIZES)
                + "   hw share " + " ".join(
                    f"{100 * c.hw(m, s) / c.total(m, s):4.0f}%" for s in SIZES))

    # ---- named values for the text
    def r(x, nd=1):
        return f"{x:.{nd}f}"

    for s in SIZES:
        V[f"a_conc_{s}"] = fmt(c840.cpb("concertina-sha256-cc", s))
        V[f"a_sha3_{s}"] = fmt(c840.cpb("concertina-sha3-cc", s))
        V[f"a_xts_{s}"] = fmt(c840.cpb("xts-cc", s))
        V[f"b_conc_{s}"] = fmt(c832.cpb("concertina-sha256-ecb", s))
        V[f"b_sha3_{s}"] = fmt(c832.cpb("concertina-sha3-ecb", s))
        for h in HCTR2_840:
            V[f"a_{PV[h]}_{s}"] = fmt(c840.cpb(h, s))
            V[f"a_speedup_{PV[h]}_{s}"] = r(c840.total(h, s) / c840.total(
                "concertina-sha256-cc", s))
        for h in HCTR2_832:
            V[f"b_{PV[h]}_{s}"] = fmt(c832.cpb(h, s))
            V[f"b_speedup_{PV[h]}_{s}"] = r(c832.total(h, s) / c832.total(
                "concertina-sha256-ecb", s), 2)
        V[f"b_dec_ct_{s}"] = fmt(c832.cpb("hctr2-ecb-ctdec", s, 1))
        V[f"b_dec_tab_{s}"] = fmt(c832.cpb("hctr2-ecb", s, 1))
        V[f"b_conc_dec_{s}"] = fmt(c832.cpb("concertina-sha256-ecb", s, 1))
        V[f"b_speedup_ctdec_{s}"] = r(c832.total("hctr2-ecb-ctdec", s, 1) / c832.total(
            "concertina-sha256-ecb", s, 1), 2)
    # robustness ranges
    say("== speed-up HCTR2/Concertina-SHA-256 over P=1..3 x latency variants (min..max) ==")
    for c, hs, conc in ((c840, HCTR2_840, "concertina-sha256-cc"),
                        (c832, HCTR2_832, "concertina-sha256-ecb")):
        for h in hs:
            rng = {s: speedups(c, h, conc, s) for s in SIZES}
            say(f"  {c.chip} {h:16s}" + " ".join(
                f"{s}:{min(v):.2f}..{max(v):.2f}" for s, v in rng.items()))
            for s in SIZES:
                tag = "a" if c is c840 else "b"
                V[f"{tag}_rmin_{PV[h]}_{s}"], V[f"{tag}_rmax_{PV[h]}_{s}"] = \
                    rng2(min(rng[s]), max(rng[s]))
    rng = {s: speedups(c832, "hctr2-ecb-ctdec", "concertina-sha256-ecb", s, 1) for s in SIZES}
    say("  nrf52832 hctr2-ecb-ctdec (dec) " + " ".join(
        f"{s}:{min(v):.2f}..{max(v):.2f}" for s, v in rng.items()))

    # crossover lengths (P=2, main latencies): first tabulated length from which
    # Concertina is faster
    for c, hs, conc, tag in ((c840, HCTR2_840, "concertina-sha256-cc", "a"),
                             (c832, HCTR2_832, "concertina-sha256-ecb", "b")):
        for h in hs:
            faster = [s for s in SIZES if c.total(conc, s) < c.total(h, s)]
            V[f"{tag}_from_{PV[h]}"] = faster[0] if faster else "--"
            say(f"  {c.chip}: Concertina faster than {h} at lengths {faster}")

    faster = [s for s in SIZES if c832.total("concertina-sha256-ecb", s, 1)
              < c832.total("hctr2-ecb-ctdec", s, 1)]
    V["b_from_ctdec"] = faster[0] if faster else "--"
    say(f"  nrf52832: Concertina decrypts faster than hctr2-ecb-ctdec at lengths {faster}")

    # claims made in the text, checked over all timing variants
    def claim(text, ok):
        say(("  claim ok:   " if ok else "  CLAIM FAILS: ") + text)
        if not ok:
            V["claims_failed"] = V.get("claims_failed", 0) + 1
    big = [s for s in SIZES if int(s) >= 256]
    claim("nRF52840: Concertina-SHA-256 faster than every HCTR2 variant from 256 B, all "
          "variants", all(min(speedups(c840, h, "concertina-sha256-cc", s)) > 1
                          for h in HCTR2_840 for s in big))
    claim("nRF52840: HCTR2 (every variant) faster at 32 B, all variants",
          all(max(speedups(c840, h, "concertina-sha256-cc", "32")) < 1 for h in HCTR2_840))
    claim("nRF52840: HMAC-SHA3-256 Concertina slower than every HCTR2 at every length (P=2)",
          all(c840.total("concertina-sha3-cc", s) > c840.total(h, s)
              for h in HCTR2_840 for s in SIZES))
    claim("nRF52832: Concertina-SHA-256 slower than HCTR2 table8 at every length, all variants",
          all(max(speedups(c832, "hctr2-t8-ecb", "concertina-sha256-ecb", s)) < 1
              for s in SIZES))
    cf = c832.fp["concertina-sha256-ecb"]
    allh = HCTR2_832 + ("hctr2-ecb-ctdec",)
    claim("nRF52832: Concertina-SHA-256 needs the least flash of all HCTR2 configurations",
          all(cf["flash"] < c832.fp[h]["flash"] for h in allh))
    claim("nRF52832: Concertina RAM above HCTR2 with table AES^-1 (ct32, table4), below "
          "constant-time HCTR2 and table8",
          all(cf["ram"] > c832.fp[h]["ram"] for h in ("hctr2-ecb", "hctr2-t4-ecb")) and
          all(cf["ram"] < c832.fp[h]["ram"] for h in ("hctr2-ecb-ctdec", "hctr2-t8-ecb")))
    claim("nRF52840: Concertina more stack, smaller context than every HCTR2 (CC)",
          all(c840.fp["concertina-sha256-cc"]["stack"] > c840.fp[h]["stack"] and
              c840.fp["concertina-sha256-cc"]["ctx"] < c840.fp[h]["ctx"] for h in HCTR2_840))
    claim("Concertina HMAC-SHA3-256 slower than every HCTR2 at every length on nRF52832 (P=2)",
          all(c832.total("concertina-sha3-ecb", s) > c832.total(h, s)
              for h in HCTR2_832 for s in SIZES))
    claim("constant-time minus table AES^-1 decryption: the same at every length",
          len({c832.total("hctr2-ecb-ctdec", s, 1) - c832.total("hctr2-ecb", s, 1)
               for s in SIZES}) == 1)
    claim("nRF52840: Concertina faster from the same length vs ct32 and table4 (P=2)",
          V["a_from_ct32"] == V["a_from_table4"])
    sp64 = {h: speedups(c840, h, "concertina-sha256-cc", "64") for h in HCTR2_840}
    claim("nRF52840 at 64 B: order vs ct32 depends on the assumptions; Concertina faster "
          "than table4 and slower than table8 under all",
          min(sp64["hctr2-cc"]) < 1 < max(sp64["hctr2-cc"]) and min(sp64["hctr2-t4-cc"]) > 1
          and max(sp64["hctr2-t8-cc"]) < 1)

    # break-even SHA-256 block latency and transfer overhead (nRF52840, P=2)
    say("== nRF52840 break-even (P=2, other latencies central) ==")
    conc = "concertina-sha256-cc"
    for h in HCTR2_840:
        hb, ov = [], []
        for s in SIZES:
            n = c840.counts(conc, s)
            tc0 = c840.total(conc, s) - CENTRAL["hash_blk"] * n["hash_blk"]
            hb.append((c840.total(h, s) - tc0) / n["hash_blk"])
            # common per-transfer overhead o for both engines and both modes
            nh = c840.counts(h, s)
            ops_c, ops_h = n["aes_op"] + n["hash_op"], nh["aes_op"] + nh["hash_op"]
            t0c = c840.total(conc, s) - CENTRAL["aes_op"] * n["aes_op"] - \
                CENTRAL["hash_op"] * n["hash_op"]
            t0h = c840.total(h, s) - CENTRAL["aes_op"] * nh["aes_op"] - \
                CENTRAL["hash_op"] * nh["hash_op"]
            ov.append((t0h - t0c) / (ops_c - ops_h) if ops_c > ops_h else float("inf"))
        say(f"  vs {h:12s} SHA-256 cycles/block at break-even: "
            + " ".join(f"{s}:{v:.0f}" for s, v in zip(SIZES, hb)))
        say(f"  vs {h:12s} transfer overhead at break-even:    "
            + " ".join(f"{s}:{v:.0f}" for s, v in zip(SIZES, ov)))
        for s, v, o in zip(SIZES, hb, ov):
            V[f"a_be_hash_{PV[h]}_{s}"] = num(round(v)) if v > 0 else "--"
            V[f"a_be_op_{PV[h]}_{s}"] = num(round(o)) if o > 0 else "--"
    for h in HCTR2_840:
        V[f"a_cpu_{PV[h]}_4096"] = fmt(c840.cpu(h, "4096") / 4096)
    sw_block = round(c840.cpu("prim-sha256-block", "64"))
    V["a_sw_sha256_block"] = num(sw_block)
    say(f"  software SHA-256 compression (P=2): {sw_block} cycles/block")

    # operation counts used in the text
    for s in SIZES:
        nc, nh = c840.counts(conc, s), c840.counts("hctr2-t8-cc", s)
        V[f"a_conc_ops_{s}"] = num(nc["aes_op"] + nc["hash_op"])
        V[f"a_hctr2_ops_{s}"] = num(nh["aes_op"] + nh["hash_op"])
    for s in ("32", "4096"):
        n = c840.counts(conc, s)
        V[f"a_conc_hashops_{s}"] = num(n["hash_op"])
        V[f"a_conc_hashblk_{s}"] = num(n["hash_blk"])
        V[f"a_conc_aesops_{s}"] = num(n["aes_op"])
        V[f"a_conc_aesblk_{s}"] = num(n["aes_blk"])
        V[f"a_conc_hwshare_{s}"] = r(100 * c840.hw(conc, s) / c840.total(conc, s), 0)
        V[f"a_conc_instr_{s}"] = num(c840.instructions(conc, s))
        n = c840.counts("hctr2-cc", s)
        V[f"a_hctr2_aesops_{s}"] = num(n["aes_op"])
        V[f"a_hctr2_aesblk_{s}"] = num(n["aes_blk"])
        V[f"a_hctr2_hwshare_{s}"] = r(100 * c840.hw("hctr2-cc", s) / c840.total("hctr2-cc", s), 0)
    # POLYVAL share of HCTR2 on the nRF52840 (CPU cycles of POLYVAL blocks)
    for h, prim in (("hctr2-cc", "prim-polyval-ct32"), ("hctr2-t8-cc", "prim-polyval-t8"),
                    ("hctr2-t4-cc", "prim-polyval-t4")):
        pv = round(c840.cpu(prim, "16"))
        V[f"a_pvblock_{PV[h]}"] = num(pv)
        for s in ("32", "4096"):
            nb = 1 + 2 * -(-(int(s) - 16) // 16)
            V[f"a_pvshare_{PV[h]}_{s}"] = r(100 * nb * pv / c840.total(h, s), 0)
    # POLYVAL cost per block at which HCTR2 (8-bit-table configuration minus its
    # POLYVAL blocks) would match Concertina with HMAC-SHA-256 (P=2, central)
    for s_ in ("256", "1024", "4096"):
        nb = 1 + 2 * -(-(int(s_) - 16) // 16)
        xs = []
        for h, prim in (("hctr2-cc", "prim-polyval-ct32"), ("hctr2-t8-cc", "prim-polyval-t8"),
                        ("hctr2-t4-cc", "prim-polyval-t4")):
            other = c840.total(h, s_) - nb * c840.cpu(prim, "16")
            xs.append((c840.total("concertina-sha256-cc", s_) - other) / nb)
        V[f"a_pvbe_{s_}"] = num(round(max(xs)))
        worst = max((c840.total("concertina-sha256-cc", s_, 0, P, pv) -
                     (c840.total(h, s_, 0, P, pv) - nb * c840.cpu(prim, "16", 0, P))) / nb
                    for P in (1, 2, 3) for pv in latency_variants(c840)
                    for h, prim in (("hctr2-cc", "prim-polyval-ct32"),
                                    ("hctr2-t8-cc", "prim-polyval-t8"),
                                    ("hctr2-t4-cc", "prim-polyval-t4")))
        V[f"a_pvbe_worst_{s_}"] = num(round(worst))
        if s_ == "4096":
            claim("POLYVAL break-even at 4096 B below 64 loads + 64 XORs (128 cycles) under "
                  "all assumptions", worst < 128)
        say(f"  POLYVAL break-even per block at {s_} B: " + ", ".join(f"{x:.1f}" for x in xs))
    V["a_aes_cc_block"] = num(round(c840.total("prim-aes-cc", "16")))
    V["a_aes_cc_ctr16"] = num(round(c840.total("prim-aes-cc-ctr16", "16")))
    V["a_sha_cc_block"] = num(round(c840.total("prim-sha256-cc-block", "64")))
    V["a_sha_cc_block16"] = num(round(c840.total("prim-sha256-cc-block16", "64")))
    V["b_aes_dec_ct"] = num(round(c832.cpu("prim-aes-dec-ct", "16")))
    V["b_aes_dec_tab"] = num(round(c832.cpu("prim-aes-dec", "16")))
    V["b_ecb_block"] = num(round(c832.total("prim-aes-ecb", "16")))
    # decryption vs encryption
    for c, m, tag in ((c832, "hctr2-ecb", "b_dectab"), (c832, "hctr2-ecb-ctdec", "b_decct"),
                      (c840, "hctr2-cc", "a_dec")):
        dv = [c.total(m, s, 1) / c.total(m, s, 0) - 1 for s in SIZES]
        V[f"{tag}_max"] = r(100 * max(dv), 1)
        V[f"{tag}_32"] = r(100 * dv[0], 0)
        V[f"{tag}_4096"] = r(100 * dv[-1], 1)
        say(f"  decryption vs encryption {c.chip} {m}: " + " ".join(f"{100 * x:+.1f}%" for x in dv))
    dd = [c832.total("hctr2-ecb-ctdec", s, 1) - c832.total("hctr2-ecb", s, 1) for s in SIZES]
    V["b_ctdec_extra"] = num(dd[0])
    say(f"  constant-time vs table inverse cipher, extra cycles per message: {dd}")
    # CPI range
    cpi = [c.cpu(m, s, k, P) / c.instructions(m, s, k)
           for c, rows in ((c840, HW840 + SW), (c832, HW832)) for m, _ in rows
           for s in SIZES for k in (0, 1) for P in (1, 2, 3)]
    V["cpi_min"], V["cpi_max"] = r(min(cpi), 2), r(max(cpi), 2)
    say(f"  cycles per instruction (model, P=1..3, all main modes): {min(cpi):.2f}..{max(cpi):.2f}")
    # memory figures
    for c, tag in ((c840, "a"), (c832, "b")):
        for m, f in c.fp.items():
            key = m.replace("-", "_")
            for col in ("flash", "tables", "ctx", "stack", "ram"):
                V[f"{tag}_fp_{key}_{col}"] = num(f[col])
            V[f"{tag}_fp_{key}_setup_us"] = fmt(f["setup_est_cycles"] / 64)
            V[f"{tag}_fp_{key}_setup_instr"] = num(f["setup"])
            V[f"{tag}_fp_{key}_setup_ms"] = f"{f['setup_est_cycles'] / 64000:.1f}"
    # self-test counts
    for c, tag in ((c840, "a"), (c832, "b")):
        for name, key in (("emu_output.txt", "checks"),
                          ("emu_output_full_selftest.txt", "checks_full")):
            with open(os.path.join(c.res, name)) as f:
                mm = re.search(r"all passed \((\d+) checks", f.read())
            V[f"{tag}_{key}"] = num(int(mm.group(1))) if mm else "??"
    for k in ("aes_op", "aes_blk", "hash_op", "hash_blk"):
        for p in ("fast", "central", "slow"):
            V[f"prof_{p}_{k}"] = str(CC_PROFILES[p][k])

    # ---- outputs
    tables = {
        "SPEED_TABLE": speed_table(c840, c832, 0),
        "DEC_TABLE": speed_table(c840, c832, 1),
        "MEMORY_TABLE": memory_table(c840, c832),
        "ROBUST_TABLE": robustness_table(c840, c832, V),
    }
    for name, t in tables.items():
        with open(os.path.join(RES, f"table_mcu_{name.split('_')[0].lower()}.tex"), "w") as f:
            f.write(t)
    tpl = os.path.join(ROOT, "paper", "appendix_mcu.in.tex")
    if os.path.exists(tpl):
        with open(tpl) as f:
            text = f.read()
        for name, t in tables.items():
            text = text.replace(f"%%{name}%%\n", t)
        missing = sorted(set(re.findall(r"<<(\w+)>>", text)) - set(V))
        if missing:
            raise SystemExit(f"template fields without a value: {missing}")
        text = re.sub(r"<<(\w+)>>", lambda mo: V[mo.group(1)], text)
        with open(os.path.join(ROOT, "paper", "appendix_mcu.tex"), "w") as f:
            f.write("% GENERATED from appendix_mcu.in.tex by tools/make_tables.py\n" + text)
        say("wrote paper/appendix_mcu.tex")
    with open(os.path.join(RES, "values.txt"), "w") as f:
        for k in sorted(V):
            f.write(f"{k} = {V[k]}\n")
    print("\n".join(out))


if __name__ == "__main__":
    main()
