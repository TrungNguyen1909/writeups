---
title: "Pwnable01 scull - Whitehat Grandprix 06"
date: 2020-12-28T17:22:26+0700
Tags: ["WhiteHatGrandprix", "CTF", "pwn", "linux", "kernel", "race-condition", "use-after-free", "UAF"]
Language: ["English"]
---

Pwnable01
===

## Intro

Hi guys, this is the writeup for the challenge _Pwnable01_ from Whitehat Grandprix 06 Final

You may want to checkout the [exploit code and challenge's source](https://github.com/TrungNguyen1909/writeups/tree/master/WhiteHatGrandPrix06/Pwn01)

## Challenge

> #pwn01:
You can ssh into our server as a low-privilege user. Can you exploit our scull driver and read the flag?

>Note: - You have 12 times to request us to restart your virtual machine (in case your virtual machine crashed).

We are provided a zip file containing a VM image for the challenge and its source code. 

### Spot the differences
Noticing the open source license text on top of the source code files, I did a quick search to find the [original source code](https://github.com/jesstess/ldd4/blob/master/scull/main.c), which then could be diffed to find the changes.

#### Differences

The mutex statements were removed, definitely mean there will be some race conditions going on here.

A new function, reachable from `ioctl`, named `scull_shift`.

### Device structure

Each device has a linked list of quantum sets, each set contains a quantum, which is an array of data.

The number of quantum in each set and the size of each quantum is initialized with global variables
```c
extern int scull_quantum;
extern int scull_qset;
```

These parameters can be get/set using ioctl cmds `SCULL_IOCGQUANTUM`, `SCULL_IOCSQUANTUM`, `SCULL_IOCGQSET`, and `SCULL_IOCSQSET`, respectively.

Each set and its quantums' data are allocated with `kmalloc` in function `scull_write`, called when writing data to the device.

The data could also be read. The function handling that operation is `scull_read`.

`scull_read` and `scull_write` use the current file offset `f_pos` to determine which buffer to read from/write to. Sets are "next to" each others, in each set, quantums are "next to" each other.

### Racy `scull_shift`

This function will go through each set, freeing `n` first quantums, and shift the remaining ones to the front.

However, the process is done while not holding to the lock and freed pointers are left as it until all quantums have been freed, there is time frame starts after the quantums are freed and ends when all quantums are shifted. During the time, read and write operations to the device may be done on the freed buffers, causing a _use-after-free_ bug.

## Exploitation

We will try to win the race by spawn another thread repeatedly writing data to the `fd` to the start of each quantum, using `lseek` to set the position.

While doing so, we spawn another thread allocating victim data structures to be overwritten. To gain code execution, ideally, the victim structure should contain a function pointer or a virtual function table (vtable).

Finally, trigger `scull_shift` through `ioctl`.

In the ideal situation, after a `kfree` completed, a victim object is allocated to the same location, and  a `write` happened just before the shift.

To increase the likelihood of such event, we will allocate lots and lots of sets, the magic number for me is `0x100`

### Victim data structure

Because we can set the quantum size, we have no limitation on choosing victim structure.

One of the ideal structures to overwrite is [`struct tty_struct`](https://elixir.bootlin.com/linux/latest/source/include/linux/tty.h#L285).

At offset 32 bytes there's a vtable pointer `const struct tty_operations *ops;` to be overwritten with our crafted one.

You can allocate it by `open("/dev/ptmx", O_RDWR)` and deallocate it by calling `close()` on the file descriptor.

One more interesting thing is that there's a [magic number](https://elixir.bootlin.com/linux/latest/source/include/linux/tty.h#L286) equals to [0x5401](https://elixir.bootlin.com/linux/latest/source/include/linux/tty.h#L355) at the beginning of the struct. This can be used to check whether you have successfully overwritten the correct structure or not.

### Executing code @ ring 0

Since [SMEP and SMAP is turned off](./guide.txt), we can craft a fake vtable at userspace and set a function address pointed to our shellcode at userspace. Without knowing which `struct tty_struct` has been overwritten, a brute force solution of attempting to trigger it on all allocated ttys would work anyway.

With shellcode execution, getting root by calling `commit_creds(prepare_kernel_creds(0))` at kernel level is _relatively_ trivial to do.

## Shoutout

- [ptr-yudai](https://ptr-yudai.hatenablog.com/), for the technique.