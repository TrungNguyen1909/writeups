# Kernel Debugger

[English version here](./KDB.md)

## Setup

Mình dùng VirtualBox để debug kernel, VmWare chắc cũng làm được tương tự

Vào Machine Settings -> Ports -> Serial -> Enable Serial Port

Port Number: Tuỳ :)))

Port mode: Host Pipe

Connect to existing : unchecked

Path/Address: /tmp/vbox (placeholder purpose :))

Boot Linux lên bình thường, Lấy root dùng

`echo ttyS0,9600 > /sys/module/kgdboc/parameters/kgdboc`

nếu Port Number là COM1 -> ttyS0, COM2 -> ttyS1, vv

Sang máy khác, chạy 

`socat -d -d /tmp/vbox pty &`

Socat sẽ chay background, output ra cái tty là debugger port.

Lấy `/boot/vmlinuz` , extract bằng `extract-vmlinux` có trên linux source tree

```
gdb vmlinuz
(gdb) target remote /dev/ttyXXX //Cái mà socat output
```

Enjoy

## NOTES:

- Chỉ có thể attach gdb khi vào lúc nó chuẩn bị panic :<

P/s: Hình như cũng có thể attach từ đầu = boot flag `kgdboc ttyS0,9600 kgdbwait` thì phải?

## Reference
  Somewhere in the internet :< Sorry
