---
title: "RITSEC18 The tangled web"
date: 2018-11-22T21:30:28+07:00
Tags: ["RITSEC", "CTF", "web"]
Language: ["English"]
---

`wget -r fun.ritsec.club:8007`

You may find the file `Fl4gggg1337.html` is referenced or has already been download. The flag wasn't there, but it has link to `Stars.html`.

Fetch that file, the base64 encoded string is the flag for this challenge.
