---
title: "matesCTF KSMASH"
date: 2019-02-18T16:48:13+07:00
Tags: ["matesCTF", "CTF", "pwn","kernel","linux"]
Language: ["English"]
---

# KSMASH - Kernel Stack Smashing

## Background
This is a Linux Kernel Module(LKM) exploitation challenge by nyaacate@gmail.com host in Round 3 MatesCTF 2018-2019

I solved this challenge overtime :<
But It seems that no team solved this so I still sent the exploit to the challenge author for testing and also wrote this writeup.

## Challenge Description

A kernel module is running, escape from non-root user to r00t to read `/root/flag`

## Reversing

Kernel module is named kmod, You can find the module using this command

```
$ modinfo kmod
filename:       /lib/modules/4.18.0-15-generic/kernel/drivers/char/kmod.ko
author:         nyaacate
license:        Unlicense
srcversion:     764EF51CE35A221A02D9CA0
depends:
retpoline:      Y
name:           kmod
vermagic:       4.18.0-15-generic SMP mod_unload
```

Fire up IDA64, load kmod.ko, It shown that

- Kernel module can be communicated through the pseudo-file `/proc/havoc`

- Read from it, the kernel module will read up the kernel stack memory for us with the function `careless_read`

- Write to it, the kernel module will copy our data to the kernel stack memory for us with the function `careless_write` :)

- Both of them perform `copy_from_user/copy_to_user` for all of the input to an one-byte sized stack variable

- This is a Simple Buffer-Overflow... but at _Kernel_ level.

### Protection : 

- kASLR (kernel level Address Space Layout Randomization)

- SMEP (Supervisor Mode Execution Protection) : Preventing Ring 0 from fetching instruction from userspace memory

- Kernel Stack Cookies (Canary)

## Exploit Vector :
**From kernel, we need to call `commit_creds(prepare_kernel_cred(0))` to elevate privilege to r00t then return safely to userspace.**

- At first, we read kernel stack memory from `/proc/havoc` to have some informations

- All important ones are located from offset 1. Below this the data layout from offset 1.

```
	---------------------------
	|       Stack Canary       |
	---------------------------
	|       Saved RBX          |
	---------------------------
	|       Saved RBP          |
	---------------------------
	|       Saved RIP          |
	---------------------------
```
	
- Based on this, we can easily defeat Stack Canary and kASLR

- Kernel ASLR can be defeated by calculating saved RIP offset.

- Last job is to elevate to r00t and then safely return back.
	
	+ Although there aren't usable gadget `mov rdi, rax` to manipulate `prepare_kernel_cred` result for `commit_creds`,
	But RAX is the same with RDI after the call for some reason so we can skip that gadget.
	
	+ Finally do `SWAPGS` then `IRETQ` (interrupt return) to return to our exploit program from Kernel.
	
	IRETQ is responsible for recovering RIP, CS, RFLAGS, RSP, SS, Specifically, it will pop from stack like this figure.
	
	```

	|--------------------------|
	|       Low mem addr       |  ^        
	|--------------------------|  |
	|           RIP            |  |
	|--------------------------|  |
	|           CS             |  |
	|--------------------------|  |
	|          EFLAGS          |  |
	|--------------------------|  |
	|           RSP            |  |
	|--------------------------|  |
	|           SS             |  |
	|--------------------------|  |
	|      High mem addr       |  |
	|--------------------------|  |

	```
	
### Notes & Issue

+ When `IRETQ` back, I got `SIGSEGV` on every single instruction RIP is pointed to :<

So I used a cool dirty trick to handle is to handle signal SIGSEGV with a function that calls `system("/bin/sh")` :))

+ ret2usr can't be used since Linux 4.15, all userspace memory in kernel will be mapped as non-executable
+ `SIGSEGV` when `iretq` is caused by KPTI(Kernel Page Table Isolation) (a.k.a KAISER) which appeared since 4.15 as a patch for Meltdown
  (Can be resolved by patching CR3?)
  
+ Everything else should be found from `exploit.c` file
	
## Gotchas :)
+ Source is available within the distribution in `/home/nyan`
	
## Reference

[Distribution](https://drive.google.com/file/d/1V4OtrqzHZc7TUr4h0VUGprnHcAoo5kp-/edit)

[ROP your way to Kernel part 1](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/linux-kernel-rop-ropping-your-way-to-part-1/)
	
[ROP your way to Kernel part 2](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/linux-kernel-rop-ropping-your-way-to-part-2/)
	
[Practical SMEP bypass techniques on Linux](https://cyseclabs.com/slides/smep_bypass.pdf)
	
All 3 from Vitaly Nikolenko :O
		
[Changes in Linux Kernel](https://outflux.net/blog/archives/2018/02/05/security-things-in-linux-v4-15/)



