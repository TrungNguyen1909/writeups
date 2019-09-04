.globl _prepIretq
.globl _swapgs
_swapgs:
	swapgs
	ret
_prepIretq:
	cli
	mov $0x23, %ax
	mov %ax, %ds
	mov %ax, %es
	mov $0x0f, %ax
	mov $0, %ax
	mov %ax, %fs
	swapgs
	ret

