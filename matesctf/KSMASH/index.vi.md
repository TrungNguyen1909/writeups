---
title: "matesCTF KSMASH"
date: 2019-02-18T16:48:13+07:00
Tags: ["matesCTF", "CTF", "pwn","kernel","linux"]
Language: ["Vietnamese"]
---

# KSMASH

## Background
Đây là 1 bài exploit linux kernel module của nyaacate@gmail.com host ở vòng 3 MatesCTF 2018-2019

Bài này mình solve sau giờ :< nhưng vì trước khi kết thúc CTF khoảng 2hr mà chưa mình chưa thấy team nào solved bài này cả,
nên là mình vẫn mạnh dạn gửi exploit code vào mail tác giả.

## Challenge Description

Có một kernel module đang chạy, nhiệm vụ là từ non-root user escape lên r00t để đọc file `/root/flag`

## Reversing

Kernel module có tên là kmod, bạn có thể tìm thấy file executable bằng lệnh

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

mở IDA64, load kmod.ko lên, sẽ tìm thấy những điều sau

- Kernel module giao tiếp bằng file /proc/havoc

- Khi đọc từ đó, kernel module sẽ ngây thơ đọc kernel memory cho chúng ta bằng hàm careless_read

- Khi viết vào đó, kernel module sẽ ngây thơ viết nguyên si vào kernel memory cho chúng ta bằng hàm careless_write

- Có thể thấy, 2 hàm đều đọc và viết và 1 kí tự :)

- Đây là 1 bài Buffer Overflow kernel cơ bản :)

### Protection : 

- kASLR (kernel level Address Space Layout Randomization) : chắc là quen thuộc rồi nhỉ :) nhưng là ở kernel thôi :)

- SMEP (Supervisor Mode Execution Protection) : Cơ chế bảo vệ ở CPU, không cho phép đọc instruction từ user memory :)

- Kernel Stack Cookies (Canary)

## Exploit Vector :
**Từ kernel, gọi `commit_creds(prepare_kernel_cred(0))` để lên r00t rồi trở về userspace.**

- Đầu tiên, chúng ta đọc kernel memory từ `/proc/havoc` để lấy thông tin

- Thông tin quan trọng sẽ nằm ở offset 1

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
	
- Như vậy, chúng ta có thể Leak và Defeat Stack Canary

- Kernel ASLR defeated bằng cách tính offset từ RIP

- Công việc còn lại là ROP để lên r00t và quay về
	
	+ Trong kernel không có gadget `mov rdi, rax` để chuyển kết quả của `prepare_kernel_cred` cho `commit_creds`,
	tuy nhiên, vì 1 lý do nào đó, RAX lúc đó lại sẵn = RDI nên chúng ta không cần :) (dùng kernel Debugger sẽ hiểu :))
	
	+ Cuối cùng là SWAPGS xong rồi IRETQ (interrupt return) để trở về chương trình của chúng ta từ kernel
	
	IRETQ sẽ khôi phục lại một số register như là RIP, CS, RFLAGS, RSP, SS, cụ thể, nó sẽ pop từ stack như sau
	
	![KSMASH-01](/img/KSMASH-01.png)
	
### Notes & Issue
+ Chúng ta không thể để fake stack ở vị trí đầu memory page vì như vậy sẽ gây stack overflow trong kernel,
	
Ta cần chọn address như là `0x60fffe00` chẳng hạn ( nói chung là đừng nhiều số 0 quá là được :))
	
+ Khi mình IRETQ về, mình bị SIGSEGV ở mọi câu lệnh mà RIP trỏ vào :< (IDKY),
	
Thế nên mình đã làm 1 trò dirty bẩn bựa là handle signal SIGSEGV bằng 1 hàm, trong đó, mình để `system("/bin/sh")` :))
	
+ Tất cả thông tin về cách giao tiếp & những thứ khác vv thì các bạn có thể check file exploit.c
	
+ KP trên các máy >= 4th Gen(Haswell) do SMAP -> bypassable = ROP cr4
+ Solution ret2usr sẽ không qua được vì từ Linux 4.15, kernel sẽ map tất tần tần userspace memory thành NX.
+ SIGSEGV khi iretq cũng là do KPTI(Kernel Page Table Isolation) (a.k.a KAISER) có từ khi patch Meltdown
  => Resolve bằng cách ROP CR3?
	
## Gotchas :)
+ Trong `/home/nyan`  có source của kernel module :)))
	
## Reference

[ROP your way to Kernel part 1](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/linux-kernel-rop-ropping-your-way-to-part-1/)
	
[ROP your way to Kernel part 2](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/linux-kernel-rop-ropping-your-way-to-part-2/)
	
[Practical SMEP bypass techniques on Linux](https://cyseclabs.com/slides/smep_bypass.pdf)
	
Cả 3 đều là của tác giả Vitaly Nikolenko :O
		
[Changes in Linux Kernel](https://outflux.net/blog/archives/2018/02/05/security-things-in-linux-v4-15/)



