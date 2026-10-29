#include "arena.h"

u8 arena_a[ARENA_LEN] __attribute__((aligned(4)));
u8 arena_b[ARENA_LEN] __attribute__((aligned(4)));
union arena_ctx arena_ctx;
