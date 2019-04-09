---
title: "RITSEC18 Gimme sum fud"
date: 2018-11-22T21:30:28+07:00
Tags: ["RITSEC", "CTF", "pwn","golang"]
Language: ["English"]
---

The binary loads the flag.txt to the memory and asks us to provide input.

Interesting things is that it loads to the same memory segment with the input.

Debugging locally, I found it at the offset 752 from the first input bytes.

Running it multiple times on the server and at sometimes, the null bytes will be all-cleared and puts will print it all.
