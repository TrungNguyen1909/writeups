---
title: "TetCTF babySandbox"
date: 2019-02-22T23:17:46+07:00
Tags: ["TetCTF", "CTF", "pwn","sandbox","ROP","NX"]
Language: ["English"]
---

# Baby Sandbox

This is a challenge of TetCTF, which is hosted from Jan 1st to Jan 7th by MeePwn Team of Vietnam

## Challenge description

We are given 2 binary, one is `sandbox` and the other one is `program`.

`sandbox`, judging by its name, is a implementation of sandbox, executing the program passed in argv[1] in an sandbox environment.

`program` is executed by `sandbox`, which is a simple static stripped executable which simply reads your input and then output it.

## Reversing

`sandbox` forks and execve a child process that passed in argv[1], then use ptrace to monitor it

At every syscall, it checks if the syscall is not blacklist and not violates custom rules and then choosing whether to stop it or continue.

Some syscalls are blocked are fork, execve, open (filename containing flag), ...

`program` is a statically-linked stripped binary, reads input, writes it out, do a mystery function 3 times then exits.

## Bugs

`sandbox` blacklists syscall, but it only blacklists x86_64 system call numbers. 
The difference between x86 and x86_64 syscall table allows us to using forbidden syscalls

`program` has a buffer-overflow, which allowing arbitrary code execution

## Exploit

To escape the sandbox, we can fork it using 32bit syscall number. The newly spawned process will be off-the-radar.

The file `poc.s` is a sandbox-escape proof-of-concept, which will escape itself and spawn a shell

`program` is a statically-linked, which allows us to have a good surface for ROPing

I decided to make the stack executable to allow us to injecting the shellcode.

While searching for solutions such as mmap or mprotect, I suddenly remember to `_dl_make_stack_executable`,
which always available in statically-linked binary.

The way I found it was while searching for `mov eax, 9;syscall` for `mprotect` syscall, 
I suddenly realised that the function that it was found in, is definitely the libc wrapper for `mprotect`

Searching reference to this function, I found 3 ones that has reference to `mprotect`.

By comparing those function reference offset to `mprotect` to the one in the others libc, 
We can find the `_dl_make_stack_executable` function. Its reference to `mprotect` is about 0x26 to 0x27 bytes from the function beginning.

With some reversing in that function, we can use it to make the stack executable again.
This technique first appeared in the CTF was in the BKPCTF Simple Calc Challenge.

After that, we can `push rsp;ret` to jump to our following shellcode.

While doing this, you will realise that the function that is called last in main was `close(fd)`.
It was used to close all pipe before leaving.

Also, please bear in mind that `program` will only read 256(0x100) bytes so make sure everything fits in.
My exploit use 255/256 bytes, which is nice(although it is a bit infuriating by leaving one-byte unused)

The first shellcode is responsible for opening a reverse shell, reading the next shellcode to a fixed executable mmap then returning to this.

The second shellcode is responsible for escaping sandbox and then gives us a shell.


