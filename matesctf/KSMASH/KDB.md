# Kernel Debugging Instruction

[Vietnamese version here](./KDB.vi.md)

## Setup

I used VirtualBox for Kernel Debugging, VMWare shoud be able to do the same thing.

Enter Machine Settings -> Ports -> Serial -> Enable Serial Port

Port Number: Any :)))

Port mode: `Host Pipe`

Connect to existing : `unchecked`

Path/Address: `/tmp/vbox` (placeholder purpose :))

Boot Linux normally, run as root

`$ echo ttyS0,9600 > /sys/module/kgdboc/parameters/kgdboc`

if Port Number is COM1, use ttyS0; if it is COM2, use ttyS1... etc

Return to the host machine, run 

`$ socat -d -d /tmp/vbox pty &`

Socat will run in the background, output the debugger serial port tty.

Fetch `/boot/vmlinuz` , extract with `extract-vmlinux` (available in the Linux Source Tree)

```
gdb vmlinuz
(gdb) target remote /dev/ttyXXX //The one that socat outputed
```

Enjoy!

## Notes

- You can only attach when the kernel panic, the KDB fired up

P/s: Maybe we can attach from start with boot flag `kgdboc ttyS0,9600 kgdbwait`?
But it is irrelevant for the purpose of this document so I won't discuss about it here

## Reference
  Somewhere in the internet :< Sorry
