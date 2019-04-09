---
title: "RITSEC18 Freeze"
date: 2018-11-22T21:30:28+07:00
Tags: ["RITSEC", "CTF", "reversing","Python"]
Language: ["English"]
---

It's clearly a python compiled program since there is a libpython and also, when using decompiler, there was a function name `PyDontWriteByteCode`

using 'pyi-archive-viewer' we can extract the main function.

Append headers to the file

```

"\x03\xf3\x0d\x0a\xf1\x32\x75\x5a"

```

using uncompyle, we can get the main function.

Change the key a little bit ±k\*360 and we will get the flag.

