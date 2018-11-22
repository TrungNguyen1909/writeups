By cating and grepping the file, we know that there was a file named `/home/memes/flag.c`

It's probably a program, so I searched for ./flag
Just printing the line doesn't seem to work so I tried

```

cat memorydump | grep -A 10 -B 10 ./flag

```

I found an interesting base64-encoded string that is repeated multiple times.

Decode it, the flag is yours.

Also, later I realised that a great pattern to grep for challs like this are the base64-encoded of the beginning part of the flag format, which is constant.

Such as

```

cat memorydump | grep UklUU0VDe 

```

which works really well for this challs.
