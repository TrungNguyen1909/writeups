# [pwnable.tw] hacknote

The program we are going to exploit is a note program. There are 4 type of actions: Add, Delete, Print, Exit

This kind of UI probably a *heap* exploitation

I started by try adding some notes. From small notes to big one.

It asks me the note size I am going to enter so I tried enter longer.

But the program didn't read it and gave me message invalid input.

Next I tried deleting some notes then something wrong happen.
I found that we can delete a note as many times as we want.

We can even print the note. But it just crash.

## Bug
This behavior is a sign of heap *use-after-free*.

## Exploit

So what next? 

I think of trying to allocate the big note over 2 freed small note so we can overwrite stuff

First, I tried note size at about 12 bytes. But it didn't work. Probably because the algorithm use fastbins for small notes.

Oh, btw, I found a new tools which is great for this type of debugging: ltrace

```

ltrace -e malloc+free-@libc.so* ./hacknote

```

So it printout the return result and arguments of the malloc and free so we will know what happened behind the scene.

When I tried 1000 bytes notes. Bum. malloc returns the same address of the first note we created.

I created a 1500 bytes notes and put an De-Bruijn pattern in and print it.

Bum! Segfault. The EIP is at offset 1008. So we now have nearly-full control over the program.

The next question is: What will we put in that?

It took me a day to figure it out.

First, We need to leak the libc address.

When debugging with gdb, I found out that the address of the argument(data) is put after the function location.

So It will print where we put at here.

So I put the address of the print function in like before, put the GOT address of free in there and print it.

It now print the what we want: The real address of 'free' in libc.

Now, we can calculate the address of others function in libc.

Next, what will we called now?

I tried one_gadget for a day but ended with failure just because 1 is in the address that should be 0.
The result is the exit code 127 due to argv=1 in execve call.

Haizz, the plan doesn't work.

The other day, after debugging, I realize that I have forgotten a wonderful thing that I found earlier.

"""

The address of the argument(data) is put after the function location.

"""

SO WHAT? I put system in the func address and then "/bin/sh"
sh said some syntax error, because the argument the address of the function is called is the where we put the function address.

Simple. I put an ";" before `/bin/sh`, then an null byte to terminate the execute string.

Pwned!

I feel SO AWESOME.