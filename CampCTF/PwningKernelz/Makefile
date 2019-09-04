main: main.c definitions.h asm.S
	gcc -Wl,-pagezero_size -Wl,0 -m32 asm.S main.c -o main
