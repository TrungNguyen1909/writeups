section .data
	cmd db "/bin/sh",0
section .text
global _start
_start:
	mov eax, 0x2
	lea rdi, [rel cmd]
	int 0x80
	cmp eax, 0
	je shell
loop:
	test eax, eax
	jmp loop
shell:
	lea ebx, [rel cmd]
	mov eax, 0xb
	xor ecx, ecx
	xor edx, edx
	int 0x80
	ret
