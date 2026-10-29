/*
 * Start-up code for the nRF52840 / nRF52832 (Cortex-M4F): vector table, reset handler
 * (copies .data, clears .bss), and a HardFault handler that prints the
 * faulting PC. No interrupts are enabled by this firmware.
 */
#include <stdint.h>

extern uint32_t _sidata, _sdata, _edata, _sbss, _ebss, _estack;
extern int main(void);
extern void platform_fault(const uint32_t *frame, uint32_t exc_return);

void Reset_Handler(void);
void Default_Handler(void);
void HardFault_Handler(void);

void Reset_Handler(void)
{
	uint32_t *src = &_sidata, *dst = &_sdata;

	while (dst < &_edata)
		*dst++ = *src++;
	for (dst = &_sbss; dst < &_ebss;)
		*dst++ = 0;
	/* Grant access to the FPU (CP10/CP11), should hard-float code be linked
	 * in; the default build is soft-float and does not use it. */
	*(volatile uint32_t *)0xE000ED88u |= 0xFu << 20;
	__asm volatile("dsb\n\tisb" ::: "memory");
	main();
	for (;;)
		__asm volatile("wfe");
}

void Default_Handler(void)
{
	for (;;)
		__asm volatile("wfe");
}

__attribute__((naked)) void HardFault_Handler(void)
{
	__asm volatile("tst lr, #4\n\t"
		       "ite eq\n\t"
		       "mrseq r0, msp\n\t"
		       "mrsne r0, psp\n\t"
		       "mov r1, lr\n\t"
		       "b platform_fault\n\t");
}

#define H(name) void name(void) __attribute__((weak, alias("Default_Handler")))
H(NMI_Handler);
H(MemManage_Handler);
H(BusFault_Handler);
H(UsageFault_Handler);
H(SVC_Handler);
H(DebugMon_Handler);
H(PendSV_Handler);
H(SysTick_Handler);

/* 16 system exceptions + 48 device interrupts (the nRF52840 has 48, the
 * nRF52832 39; the extra entries are unused); the device interrupts are
 * never enabled here, so they all point to the default handler. */
__attribute__((section(".isr_vector"), used))
void (*const vector_table[16 + 48])(void) = {
	(void (*)(void))(&_estack),
	Reset_Handler,
	NMI_Handler,
	HardFault_Handler,
	MemManage_Handler,
	BusFault_Handler,
	UsageFault_Handler,
	0, 0, 0, 0,
	SVC_Handler,
	DebugMon_Handler,
	0,
	PendSV_Handler,
	SysTick_Handler,
	[16 ... 63] = Default_Handler,
};
