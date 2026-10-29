"""Approximate Cortex-M4 instruction timing, after the cycle counts of the
ARM Cortex-M4 Technical Reference Manual (DDI 0439B with Errata 01, Table 3-1,
"Cortex-M4 instruction set summary"). Used by nrf52_emu.py --cycle-model
to estimate cycles; it is an estimate, not a cycle-accurate simulation.

Modelled:
  * data processing, MUL, MLA, MLS (1 cycle per Errata 01),
    UMULL/SMULL/UMLAL/SMLAL, bit-field, IT: 1 cycle
  * LDR/STR (single, any width): 2, or 1 when the previous instruction is a
    single LDR (address/data phase pipelining of neighbouring loads and
    stores; the TRM's load/store timing notes allow no pipelining after a
    store, so a store resets it)
  * LDRD/STRD: 3; LDM/STM/PUSH/POP: 1 + N
  * UDIV/SDIV: 7 (the TRM gives 2 to 12)
  * branches (B, BL, BX, BLX, CBZ, CBNZ): 1, plus P when taken; TBB/TBH: 2 + P;
    any other write to PC (POP {..pc}, LDR pc): + P
Not modelled: flash wait states and the instruction cache (the nRF52840 PS
gives 0 wait states from RAM; both chips have an instruction cache for
flash), bus contention, and pipelining across basic-block boundaries. P is the pipeline
refill, 1 to 3 cycles according to the TRM.
"""
from capstone.arm import ARM_OP_REG, ARM_REG_PC

LOADS = {"ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrex", "ldrexb", "ldrexh",
         "ldrt", "ldrbt", "ldrht", "ldrsbt", "ldrsht"}
STORES = {"str", "strb", "strh", "strex", "strexb", "strexh", "strt", "strbt",
          "strht"}
DOUBLES = {"ldrd", "strd"}
MULTI = {"ldm", "ldmdb", "stm", "stmdb", "push", "pop"}
BRANCHES = {"b", "bl", "bx", "blx", "cbz", "cbnz"}
TABLE_BRANCHES = {"tbb", "tbh"}
TWO = set()  # MLA/MLS are single-cycle on Cortex-M4 (TRM Errata 01)
DIVS = {"udiv", "sdiv"}


def _writes_pc(insn):
    for op in insn.operands:
        if op.type == ARM_OP_REG and op.reg == ARM_REG_PC:
            return True
    return False


def block_cost(insns):
    """Returns (static cycles, ends_with_control_transfer) for a basic block,
    excluding the taken-branch penalty, which the caller adds when the next
    executed block is not the fall-through."""
    cycles = 0
    prev_load = False
    ends_ct = False
    for insn in insns:
        n = insn.insn_name()
        ct = False
        is_load = False
        if n in LOADS:
            c = 1 if prev_load else 2
            is_load = True
            if insn.operands and insn.operands[0].type == ARM_OP_REG and insn.operands[0].reg == ARM_REG_PC:
                ct = True
        elif n in STORES:
            c = 1 if prev_load else 2
        elif n in DOUBLES:
            c = 3
        elif n in MULTI:
            nregs = len(insn.operands) - (1 if n.startswith(("ldm", "stm")) else 0)
            c = 1 + max(nregs, 1)
            if n in ("pop", "ldm", "ldmdb") and _writes_pc(insn):
                ct = True
        elif n in BRANCHES:
            c = 1
            ct = True
        elif n in TABLE_BRANCHES:
            c = 2
            ct = True
        elif n in TWO:
            c = 2
        elif n in DIVS:
            c = 7
        else:
            c = 1
            if n in ("mov", "add") and insn.operands and insn.operands[0].type == ARM_OP_REG \
                    and insn.operands[0].reg == ARM_REG_PC:
                ct = True
        cycles += c
        prev_load = is_load
        ends_ct = ct
    return cycles, ends_ct
