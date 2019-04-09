---
title: "RITSEC18 Yet another HR Management Framework"
date: 2018-11-22T21:30:28+07:00
Tags: ["RITSEC", "CTF", "pwn","heap","golang"]
Language: ["English"]
---

By judging the program's interface, we know that it was a heap challenge.

Spent quite a lot of time reversing it, I figured it out that it malloc a few bytes for the person struct on the heap, then the name will be malloc with the size entered and that address will be put in the person struct.

The person struct also has a function pointer which is set to the `printPerson` function.

The edit feature doesn't check the bound, it just read the number of bytes that we specified.

So we can use the edit name function to overwrite other person data, which included the function pointer and the name pointer.

Since the person struct is small, I decided to first create a person with small name and then edit it to overflow the second one to make the heap looks like this

-------------------------------------------------------------------

Struct person 1 | Person 1 Name | Struct person 2 | Person 2 Name |

-------------------------------------------------------------------

I did some reversing and testing and find out what to overwrite.

First I overwrite the name pointer to the got table to leak the libc.

Then I overwrite the function pointer to system and put the ";/bin/sh\x00" string at the address.

Mind the semi-colon, It allows you to skip the prepended bytes.

Well, I figured out how the addresses are being used just by testing and inspecting the heap many times.

Anyhow, it works.

Well, the problem is that the offset isn't always the same.

But with some luck, I managed to exploit the networked binary once after many times running it again and get the flag. :) 

But then after, I couldn't exploit it again, ever.

After the ctf ended, I investigated and find 2 others offset which makes the chance of success increased a lot.

The chance of success is about 80%, but that's enough for the flag.
