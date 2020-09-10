---
title: "matesCTF notebook"
date: 2018-10-10T11:56:50+07:00
Tags: ["matesCTF", "CTF", "pwn","heap"]
Language: ["Vietnamese"]
---

Notebook
===

[Exploit](https://github.com/TrungNguyen1909/writeups/tree/master/matesctf/notebook)

Bài này mình pwn được sau khi được tiền bối *Đào Xuân Nghĩa* thông não sau giờ.

Đây là 1 bài *Heap overflow*.

checksec:

```
[*] '/root/matesctf/notebook'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Có 2 loại note (bình thường: 1000bytes. Lớn: 2000bytes)

Các notes được lưu ở dạng double linked-list. 16 bytes đầu của mỗi note sẽ lưu note tiếp theo(FD) và note trước (BK)

## Goal

Overwrite FD và BK để nó trỏ về GOT của `_IO_getc`. Sau đó dùng chức năng Edit để ghi vị trí của `canyourunme` vào

## Bug

Lỗi logic nghiêm trong ở phần Edit.

Đối với note bé, ta sẽ có (1000-16)=984 bytes cho dữ liệu, tuy nhiên, ta lại được EDIT những 992 bytes. 

=> Tức là đã tràn 8 bytes để có thể edit cái size của note tiếp theo

## Exploit

Như vậy là ta có thể áp dụng kĩ thuật [overlapping chunks](https://github.com/shellphish/how2heap/blob/master/glibc_2.25/overlapping_chunks_2.c)

Mình sẽ edit size của 1 note thành tổng của nó và cái tiếp theo rồi free.
Như vậy, ptmalloc2 sẽ bị lừa rằng là nó sẽ có 1 khoảng trống gấp đôi ở đó và sẽ allocate Big note vào đó.

Trên thực tế, cái note sau vẫn được chương trình coi như bình thường

=> Ta sẽ tạo 1 cái Big note ở đó rồi đè lên FD và BK bằng `vị trí của GOT _IO_getc - 16`

Khi đi qua cái note đó, thì dù Back hay Next đều khiến cho chương trình coi GOT là 1 cái note và tức là ta có thể edit tuỳ ý.

Edit nó bằng vị trí của `canyourunme` là ta có shell.

Như thường lệ, `cat flag` sẽ cho chúng ta flag.

## Reference

Đào Trọng Nghĩa

[how2heap](https://github.com/shellphish/how2heap/blob/master/glibc_2.25/overlapping_chunks_2.c)
