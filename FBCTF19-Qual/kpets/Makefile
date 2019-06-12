exploit: exploit.c
	gcc exploit.c -static -pthread -std=c11 -o ./exploit
run: exploit initramfs/
	cp ./exploit initramfs/bin/
	cd initramfs;\
	find . -print0 | cpio --null --create --verbose --format=newc > ../initramfs.cpio
	./start_qemu.sh bzImage initramfs.cpio
