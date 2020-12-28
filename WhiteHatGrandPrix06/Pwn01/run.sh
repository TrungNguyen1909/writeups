#!/bin/sh

qemu-system-x86_64 -m 1G -s -smp 2 \
    -kernel ./vmlinuz-5.0.0-61-generic \
    -append "console=ttyS0 root=/dev/sda nokaslr nosmep nopti nosmap earlyprintk=serial" \
    -drive file=./disk.img \
    -net user,host=10.0.2.11,hostfwd=tcp:127.0.0.1:10023-:22 \
    -serial mon:stdio \
    -net nic,model=e1000 -nographic -snapshot
