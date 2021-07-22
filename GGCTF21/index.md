---
title: "Full chain - Google CTF 2021"
date: 2021-07-21T13:37:00+0000
Tags: ["GGCTF", "CTF", "pwn", "linux", "kernel", "use-after-free", "UAF"]
Language: ["English"]
---

Full chain
===

> Do you have what it takes to pwn all the layers?

## Intro

Hi, last weekend I participated in Google CTF 2021 with my team `vh++`.

To quote from my last year's writeup: 
> Although I didn't solve the challenge in time for the points, 
> still, here is a writeup for the challenge `teleport` for you.

```
s/I/we/g
s/teleport/full chain/g
```

The challenge consists of 3 parts: V8 - Mojo - Kernel
This is the writeup for the kernel LPE part.

You may want to checkout [the exploit code for this part](https://github.com/TrungNguyen1909/writeups/tree/master/GGCTF21/exploit.c) for this part.

The writeup for two other parts is available at [my friend's blog](https://ret2.life/posts/Google-CTF-2021/)

## Overview

The source of the kernel module is [provided](https://github.com/TrungNguyen1909/writeups/tree/master/GGCTF21/ctf.c).

The module registers a file at `/dev/ctf` with 3 registered functions: `ctf_read`, `ctf_write`, `ctf_ioctl`.

The function `ctf_ioctl` (accessible over `ioctl(2)`) has 2 selectors:
- 1337 to `kmalloc` a buffer (< 2000 bytes in size)
- 1338 to `kfree` that buffer.

`ctf_read`, `ctf_write` copy user data from and to the allocated buffer; size checks seem to be done correctly.

Let's take a look at the following snippet from `ctf_ioctl` function.

```ctf.c
static ssize_t ctf_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
  struct ctf_data *data = f->private_data;
  char *mem;

  switch(cmd) {
  case 1337:
    if (arg > 2000) {
      return -EINVAL;
    }

    mem = kmalloc(arg, GFP_KERNEL);
    if (mem == NULL) {
      return -ENOMEM;
    }

    data->mem = mem;
    data->size = arg;
    break;

  case 1338:
    kfree(data->mem);
    break;

  default:
    return -ENOTTY;
  }

  return 0;
}
```

We can see that selector `1338` does not zero out the `data->mem` field after `kfree`, this results in a dangling pointer which we can read and write freely.

Also, the QEMU script enables SMEP and SMAP for the VM, which means that the kernel can't fetch instructions from and also cannot arbitrarily read or write data from and to the userland address space.

## Goals

To get root, we want to run `commit_creds(prepare_kernel_cred(0))` in the kernel in the with our process as current task. 
- Because of KASLR, our first goal is to leak kernel code/static data address.

- The second one is to obtain kernel code execution.

These could be done by freeing `data->mem` and reallocate with an interesting object.

When talking of Linux kernel UAF, the go-to victim object is [`struct tty_struct`](https://elixir.bootlin.com/linux/v5.12.18/source/include/linux/tty.h#L284)

### Why `tty_struct` is a game changer?

- First, it has a magic number at its start (`magic == TTY_MAGIC`) so we know if we have leaked a `struct tty_struct`.

- Second, it has `const struct tty_operations *ops;` member, which is a pointer to a function table(array) lying on the kernel's static data section.

- Third, by overwriting `ops`, to a address we could control, we can get kernel code execution.

- Forth, it is in the `kmalloc-1024` slab.

## Debug

To simplify the debugging process, we will want root in the VM. To do that, you can use the following commands (run as root/sudo) to mount and edit `/init` script and give ourselves root privilege for debugging.

To mount the Root Filesystem:
```mount.sh
#!/bin/sh

mkdir mnt
mount -t ext4 ./rootfs.img ./mnt
```

To unmount:

```umount.sh
#!/bin/sh

umount ./mnt
```

## Leaking KASLR slide.

KASLR shifts the whole kernel by a random offset upon startup. This can be defeated by leaking a kernel pointer.

With our UAF we can allocate a 1024-byte buffer with the `ioctl(2)` selector `1337` of the kernel module; `kfree` it with selector `1338`, and then try re-allocate it with a `struct tty_struct` by opening `/dev/ptmx`.

To increase our odd, we can allocate about 0x40 `ctf`'s buffers; free them; then allocate 0x40 `struct tty_struct`s. Don't forget that you can allocate multiple data buffers by opening `/dev/ctf` multiple times.

When reading back from our `ctf`'s buffer, we can find the `tty_struct` by checking the first dword for [the magic value](https://elixir.bootlin.com/linux/v5.12.18/source/include/linux/tty.h#L353). Then we can proceed with leaking its `ops`.

With some testing, I found that there are 2 possible addresses that could be found in `ops`, one with `0x4c0` and one with `0x5e0` as the lowest bytes.

Both should derive the kernel base after subtracting from a static offset.

_Side note_: you can find the static offset by subtract the address you found in `ops` to the address of the `_text` found in `/proc/kallsyms` (readable by root only)

## Kernel code execution?

At this point, we can overwrite `ops` member with an address in userspace where we can put our function pointers, or can't we?

The answer is no, because SMAP is enabled, the kernel won't be able to read that address. We need to set `ops` to somewhere in the kernel lies our controlled data.

### 0x4c0 or 0x5e0

But that aside, lets just put `0xdeadbeef` in there, `ioctl(2)` the ttys, and see what happened.

```
[   34.402123] BUG: unable to handle page fault for address: 00000000deadbf4f
[   34.406823] #PF: supervisor read access in kernel mode
[   34.409823] #PF: error_code(0x0000) - not-present page
[   34.413409] PGD 0 P4D 0
[   34.414875] Oops: 0000 [#1] SMP NOPTI
[   34.417087] CPU: 0 PID: 80 Comm: exploit Tainted: P           O      5.12.9 #1
[   34.424596] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS ?-20191223_100556-anatol 04/01/2014
[   34.431040] RIP: 0010:tty_ioctl+0x379/0x930
[   34.432986] Code: 81 fc 09 54 00 00 0f 84 a4 01 00 00 41 81 fc 0b 54 00 00 0f 85 fa 02 00 00 49 f7 c5 fd ff ff ff 0f 84 ba 02 00 00 48 8b 45 18 <2
[   34.444744] RSP: 0018:ffffa41540157e60 EFLAGS: 00000246
[   34.447612] RAX: 00000000deadbeef RBX: ffff94c942add000 RCX: 0000000042424242
[   34.449129] RDX: ffff94c942add000 RSI: ffff94c942b04400 RDI: ffff94c942b04800
[   34.458397] RBP: ffff94c942b04800 R08: 4343434343434343 R09: 0000000000000000
[   34.459561] R10: 0000000000000042 R11: 0000000000000042 R12: 0000000042424242
[   34.460935] R13: 4343434343434343 R14: ffff94c942add000 R15: ffff94c942b04400
[   34.462239] FS:  00007f159bede540(0000) GS:ffff94c95f400000(0000) knlGS:0000000000000000
[   34.463656] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   34.465125] CR2: 00000000deadbf4f CR3: 0000000002a62000 CR4: 00000000003006f0
[   34.466574] Call Trace:
[   34.468057]  ? selinux_file_ioctl+0x130/0x220
[   34.469253]  __x64_sys_ioctl+0x7e/0xb0
[   34.470915]  do_syscall_64+0x33/0x40
[   34.471597]  entry_SYSCALL_64_after_hwframe+0x44/0xae
```

And

```
[    9.610574] BUG: unable to handle page fault for address: 00000000deadbf97
[    9.612095] #PF: supervisor read access in kernel mode
[    9.612574] #PF: error_code(0x0000) - not-present page
[    9.613322] PGD 0 P4D 0
[    9.613762] Oops: 0000 [#1] SMP NOPTI
[    9.614176] CPU: 0 PID: 80 Comm: exploit Tainted: P           O      5.12.9 #1
[    9.614493] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS ?-20191223_100556-anatol 04/01/2014
[    9.615148] RIP: 0010:tty_driver_flush_buffer+0x4/0x20
[    9.616217] Code: 84 00 00 00 00 00 48 8b 47 18 48 8b 40 50 48 85 c0 74 05 e9 9e df 91 00 b8 00 08 00 00 c3 0f 1f 84 00 00 00 00 00 48 8b 47 18 <f
[    9.618605] RSP: 0018:ffff963140157e00 EFLAGS: 00000286
[    9.619180] RAX: 00000000deadbeef RBX: ffff8a5e429955b0 RCX: 0000000000000000
[    9.619718] RDX: ffff9631401c5000 RSI: 0000000000000000 RDI: ffff8a5e42b04400
[    9.620310] RBP: ffff8a5e42b04400 R08: 0000000000000001 R09: ffff8a5e42b04668
[    9.620937] R10: 0000000000000000 R11: 000000000000014c R12: 0000000000000000
[    9.621467] R13: ffff8a5e42b04428 R14: ffff8a5e42b04404 R15: 0000000000000000
[    9.622125] FS:  00007fc9755ff540(0000) GS:ffff8a5e5f400000(0000) knlGS:0000000000000000
[    9.622740] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[    9.623692] CR2: 00000000deadbf97 CR3: 0000000002a62000 CR4: 00000000003006f0
[    9.624317] Call Trace:
[    9.625617]  tty_ldisc_hangup+0x47/0x200
[    9.626277]  __tty_hangup.part.0+0x1ea/0x330
[    9.626582]  tty_release+0x123/0x430
[    9.626792]  __fput+0x87/0x230
[    9.627075]  task_work_run+0x57/0x90
[    9.627391]  exit_to_user_mode_prepare+0x114/0x120
[    9.627640]  syscall_exit_to_user_mode+0x1d/0x40
[    9.628179]  entry_SYSCALL_64_after_hwframe+0x44/0xae
```

We panic as expected, YAY.

Those are panic outputs for `...5e0` and `...4c0` as `ops`, respectively.

The first one crashes in `_tty_ioctl`, and the second one crashes in `_tty_driver_flush_buffer`.

Here you may also ask why I use `ioctl(2)` for this. The reason is that it gives us better control over the arguments (`ESI` and `RDX`), which tends to be useful when doing ROP.

Thus we also want to avoid the second one as [`flush_buffer`](https://elixir.bootlin.com/linux/v5.12.18/source/include/linux/tty_driver.h#L272) doesn't give us any control over any registers.

This is the reason why I filtered out for `...0x5e0` ops in my exploit code.

### ops and SMAP

Because of SMAP, now we need a kernel address that points to our controlled data so that we can put the first gadget of our ROP chain there.

It might be possible to leak a `tty_struct`'s address and put our crafted function table there; however, that soon becomes a problem.

Because we have 0x40 ttys and it is not possible to find the one that we can use to trigger the bug (the one that we will overwrite the `ops` pointer), we can't free the ttys but have to attempt to trigger the bug by ioctl-ing all ttys. 

Thus, when we overwrite it with a `tty_struct` address where we put our crafted function table, we may crash the kernel by hitting the corrupted one.

Also don't forget that we also need kernel space for the ROP stack if we proceed with this strategy, not just the `ops` table.

#### We need better primitives

`struct tty_struct` isn't enough for us, so we need to find another way to leak a controllable kernel buffer address.

I tried `msg_msg`, but you will need to dereference the address at `+0x0` to get the actual address of the buffer.

Looking again at the kernel module, I saw this line of code

```c
struct ctf_data {
  char *mem;
  size_t size;
};
...
  struct ctf_data *data = kzalloc(sizeof(struct ctf_data), GFP_KERNEL);
```

The `struct ctf_data` stores our buffer address and size and can also be re-allocated to our dangling pointers.

This is how I did it:
1. Create a whole new set of `ctf` buffers with size 16 (the same with `struct ctf_data`) called _A_.
2. Free all the buffers in set _A_.
3. Allocate a set of 0x40 `ctf` buffers size ranging from `1337` to `1337 + 0x40` called _B_.

The result is some `struct ctf_data` of _B_ will have the same address with some dangling buffer pointers in _A_.

Notice that I use the size range to determine which buffer I leaked, and also to make sure that I don't touch other kernel objects in the same slab.

Now we will have control over a working `struct ctf_data` struct, which means we can overwrite the `mem` pointer and the `size`.

We now have arbitrary kernel R/W over 2 file descriptors (one in set _A_ to control the second one in _B_ where we can read/write) :D

### Kernel RW to root

I can't seem to find a way to find our process's `task_struct` in the kernel using pointers path from a static variable, so I overwrite the `/sbin/modprobe` string (which is in the static data section) with a path to a script.

This script will be executed as root when we execute an invalid file.

So I dropped a `0777` shell script in `/tmp/x` contains commands to copy `/dev/vdb` (the flag) to `/tmp`, `chmod 777` the flag so that we can read it as a user. 

Then I created a invalid file (`/tmp/dummy`) (containing 4 0xff bytes) and execute it, it is an invalid executable so `/tmp/x` will be executed as root.

_Side note_: While I am writing this, I realized that you can just `chmod 777 /dev/vdb` in the script to make it user-readable.

After `system("/tmp/dummy")` returns, we can read out the flag in `/tmp`.

P/s: I'm not sure what will happen if we put `/bin/sh` in `/sbin/modprobe`. If it is executed in the same fd context with our exploit (likely because I saw the script errors out), we can get a root shell.

Done, we now have the flag.

```sh
echo -ne "CTF{...}" | sha256sum

71baa3b8e0e8b41f14609f6501f7704a2f5023ddf57aab00f4211ecb1aa88f7e  -
```

## References
- [ptr-yudai's blog for `struct tty_struct`](https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628#tty_struct)
- [lkmidas's blog for modprobe overwrite](https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/)

