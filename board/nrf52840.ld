/* nRF52840 without SoftDevice or bootloader: 1 MiB flash at 0, 256 KiB RAM. */
MEMORY
{
	FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 1024K
	RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 256K
}

ENTRY(Reset_Handler)
_min_stack = 16K;

SECTIONS
{
	.text :
	{
		KEEP(*(.isr_vector))
		/* newlib-nano's strlen is 64-byte aligned: placed right after the
		 * 256-byte vector table, it needs no padding, so that the size of
		 * the image does not depend on the size of the code before it
		 * (tools/footprint.py compares images). */
		*libc_a-strlen.o(.text .text.*)
		*(.text*)
		*(.rodata*)
		. = ALIGN(4);
	} > FLASH

	.ARM.exidx :
	{
		*(.ARM.exidx* .gnu.linkonce.armexidx.*)
	} > FLASH

	_sidata = LOADADDR(.data);
	.data :
	{
		. = ALIGN(4);
		_sdata = .;
		*(.data*)
		. = ALIGN(4);
		_edata = .;
	} > RAM AT > FLASH

	.bss (NOLOAD) :
	{
		. = ALIGN(4);
		_sbss = .;
		*(.bss*)
		*(COMMON)
		. = ALIGN(4);
		_ebss = .;
	} > RAM

	_estack = ORIGIN(RAM) + LENGTH(RAM);
	ASSERT(_ebss + _min_stack <= _estack, "not enough RAM left for the stack")

}
