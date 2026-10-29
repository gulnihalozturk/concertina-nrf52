# Concertina and HCTR2 on the nRF52840 / nRF52832 (Cortex-M4F), bare metal.
#
#   make [CHIP=nrf52832]   build build/<chip>/concertina.{elf,hex,bin}
#   make flash             program a DK with nrfjprog (erases the chip)
#   make emu               run the firmware in the emulator (emu/nrf52_emu.py)
#   make results           emulator runs (instructions, cycle model P=1..3,
#                          hardware-latency variations), full self-test,
#                          footprint -> results/<chip>/
#   make paper             tables and the paper's appendix for both chips
#                          (after "make results" for each) -> paper/
#   make host              build and run the portable code natively (tests)
#   make kat               regenerate src/kat_generated.h (Python 3 + cryptography)
#   make gen               regenerate src/keccak_bi32.inc
#
# CHIP: nrf52840 (default; nRF52840 DK) or nrf52832 (nRF52832-QFAA, nRF52 DK).
# Options: OPT="-O2 ...", UART_TX_PIN=<n> (default 6 = P0.06, the virtual COM
#          port of both DKs), SELFTEST_FULL_SPLITS=1, BENCH_NTRIES=<n>,
#          RUN_BENCHMARKS=0

CHIP   ?= nrf52840
ifeq ($(CHIP),nrf52840)
CHIPDEF = -DCHIP_NRF52840
else ifeq ($(CHIP),nrf52832)
CHIPDEF = -DCHIP_NRF52832
else
$(error CHIP must be nrf52840 or nrf52832)
endif

CROSS  ?= arm-none-eabi-
CC      = $(CROSS)gcc
OBJCOPY = $(CROSS)objcopy
SIZE    = $(CROSS)size
# -fno-schedule-insns: scheduling before register allocation raises register
# pressure on the in-order Cortex-M4 (see results/<chip>/compiler_flag.txt).
OPT    ?= -O2 -fno-schedule-insns
B      ?= build/$(CHIP)
RES     = results/$(CHIP)

UART_TX_PIN          ?= 6
SELFTEST_FULL_SPLITS ?= 0
BENCH_NTRIES         ?= 15
RUN_BENCHMARKS       ?= 1
DEFS = $(CHIPDEF) -DUART_TX_PIN=$(UART_TX_PIN) \
       -DSELFTEST_FULL_SPLITS=$(SELFTEST_FULL_SPLITS) \
       -DBENCH_NTRIES=$(BENCH_NTRIES) -DRUN_BENCHMARKS=$(RUN_BENCHMARKS)

CPUFLAGS = -mcpu=cortex-m4 -mthumb -mfloat-abi=soft
# -ffile-prefix-map: no absolute paths of the build machine in the debug info
CFLAGS   = -std=gnu11 $(OPT) $(CPUFLAGS) -g -Wall -Wextra -Wno-pointer-sign \
           -ffunction-sections -fdata-sections -fno-common -Isrc -Iboard $(DEFS) \
           -ffile-prefix-map=$(CURDIR)=.
LDFLAGS  = -T board/$(CHIP).ld -nostartfiles --specs=nano.specs \
           -Wl,--gc-sections -Wl,-Map=$(B)/concertina.map -Wl,--print-memory-usage

CORE_SRCS = src/aes.c src/aes_dec.c src/aes_ct.c src/arena.c src/keccak.c \
            src/sha256.c src/scheme.c \
            src/polyval.c src/hctr2.c src/xts.c src/print.c src/selftest.c \
            src/bench.c src/main.c src/testvecs/hctr2_testvecs.c \
            src/testvecs/polyval_testvecs.c src/testvecs/xctr_testvecs.c
FW_SRCS   = $(CORE_SRCS) board/platform_nrf52.c board/startup_nrf52.c
ifeq ($(CHIP),nrf52840)
FW_SRCS  += board/cc310_nrf52840.c
endif
HDRS      = $(wildcard src/*.h src/testvecs/*.h board/*.h) src/keccak_round.inc src/aes_tables.inc \
            src/keccak_bi32.inc

all: $(B)/concertina.hex $(B)/concertina.bin

$(B)/concertina.elf: $(FW_SRCS) $(HDRS) board/$(CHIP).ld Makefile
	@mkdir -p $(B)
	$(CC) $(CFLAGS) $(FW_SRCS) $(LDFLAGS) -lc -lgcc -o $@
	$(SIZE) $@

$(B)/concertina.hex: $(B)/concertina.elf
	$(OBJCOPY) -O ihex $< $@

$(B)/concertina.bin: $(B)/concertina.elf
	$(OBJCOPY) -O binary $< $@

flash: $(B)/concertina.hex
	nrfjprog -f nrf52 --program $< --chiperase --verify --reset

emu: $(B)/concertina.elf
	python3 emu/nrf52_emu.py --chip $(CHIP) $< --csv $(B)/results.csv

EMU = python3 emu/nrf52_emu.py --chip $(CHIP)
P2  = $(EMU) $< --cycle-model 2

# Emulator runs. Instruction counts (exact) and estimated cycles (cycle
# model P = 1..3), each plus the modelled hardware latency. The extra runs
# vary one hardware latency at a time; since the time of each benchmark line
# is linear in these latencies, they give, per line, the number of hardware
# operations, from which tools/make_tables.py computes the sensitivity and
# the break-even latencies.
results: $(B)/concertina.elf
	@mkdir -p $(RES)
	python3 emu/test_cryptocell.py > results/emu_model_tests.txt
	$(EMU) $< --csv $(RES)/emu_results.csv > $(RES)/emu_output.txt
	for p in 1 2 3; do $(EMU) $< --cycle-model $$p \
	  --csv $(RES)/emu_results_cycles_p$$p.csv > $(RES)/emu_output_cycles_p$$p.txt; done
ifeq ($(CHIP),nrf52840)
	for prof in fast slow; do $(P2) --cc-profile $$prof \
	  --csv $(RES)/emu_results_cycles_p2_$$prof.csv > $(RES)/emu_output_cycles_p2_$$prof.txt; done
	for k in aes-op aes-blk hash-op hash-blk; do $(P2) --cc-$$k 0 \
	  --csv $(RES)/emu_results_cycles_p2_no-$$k.csv > $(RES)/emu_output_cycles_p2_no-$$k.txt; done
endif
	$(P2) --ecb-cycles 0 --csv $(RES)/emu_results_cycles_p2_no-ecb.csv \
	  > $(RES)/emu_output_cycles_p2_no-ecb.txt
	$(MAKE) CHIP=$(CHIP) B=build/$(CHIP)-full-selftest SELFTEST_FULL_SPLITS=1 \
	  RUN_BENCHMARKS=0 all
	$(EMU) build/$(CHIP)-full-selftest/concertina.elf \
	  > $(RES)/emu_output_full_selftest.txt
	$(MAKE) CHIP=$(CHIP) B=build/$(CHIP)-O2 OPT=-O2 BENCH_NTRIES=1 all
	$(EMU) build/$(CHIP)-O2/concertina.elf > $(RES)/emu_output_O2.txt
	python3 tools/compare_flags.py $(RES)/emu_output_O2.txt $(RES)/emu_output.txt \
	  > $(RES)/compiler_flag.txt
	python3 tools/footprint.py --chip $(CHIP) --csv $(RES)/footprint.csv \
	  > $(RES)/footprint.txt

# Tables and the paper's appendix for both chips (after make results for each).
paper:
	python3 tools/make_tables.py > results/summary.txt
	cat results/summary.txt

host:
	@mkdir -p build/host
	cc -std=gnu11 -O2 -Wall -Wextra -Wno-pointer-sign -Isrc $(DEFS) $(CORE_SRCS) \
	   board/platform_host.c -o build/host/concertina-host
	./build/host/concertina-host

kat:
	python3 python/scheme_ref.py

gen:
	python3 tools/gen_keccak_bi32.py

clean:
	rm -rf build

.PHONY: all flash emu results paper host kat gen clean
