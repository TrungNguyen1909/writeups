.PHONY: all exploit install run
all: exploit install run

exploit: exploit.c scull.h
	gcc exploit.c -static -pthread -std=c11 -o exploit
install: exploit
	sudo mount disk.img /mnt
	sudo cp exploit /mnt/root/exploit
	sudo umount /mnt
run: install exploit
	./run.sh	
