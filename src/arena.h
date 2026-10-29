/*
 * Work memory shared by the self-tests and the benchmark, which never run at
 * the same time (keeps the benchmark firmware within the 64 KiB of RAM of
 * the nRF52832).
 */
#pragma once
#include "hctr2.h"
#include "scheme.h"
#include "xts.h"

#define ARENA_LEN 4096

extern u8 arena_a[ARENA_LEN], arena_b[ARENA_LEN];
extern union arena_ctx {
	scheme_ctx s;
	hctr2_ctx h;
	xts_ctx x;
} arena_ctx;
