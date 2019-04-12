---
title: "AceBear Security Contest House-of-loop"
date: 2019-04-08T14:35:17+07:00
Tags: ["AceBear", "CTF", "pwn","heap"]
Language: ["English"]
---

# House-of-loop
Hi everyone, this is the writeup for the challenge _House-of-loop_ in the _AceBear Security Contest 2019_

## Description

We are given a stripped ELF x64 binary which can be interacted with, our task is to get remote code execution(RCE).

The binary presents us 3 options: Create, View and Delete a note.

When creating a note, we have 3 fields: Title, Private, and Description.

We have the limits on `Title`, `Private` field length but with Description, we can use as much as we specified.

When viewing a note, we can view the `Title` and `Description` fields but not Private.

When deleting a note, we specify the `Title` of the note which we want to delete and then it will be removed from the view.

I spent 1h30 to reverse and understand the binary and decompile the binary.

The fully decompiled program is at [here](./house_of_loop.c).

EDIT: Almost forgot, I used `syms2elf` plugin to get the function symbols into the executable (a.k.a de-strip) :)

## Technical Details

When creating a note, it `malloc(144)` for the note, note’s title is at offset 96 of the struct.

The title is null-terminated at offset 25 although we can write 32bytes.

Private data is written to the beginning(offset 0).

Lastly, It asks us for the description size, malloc enough data, zero it out, finally read in an exact number of bytes.

The address of the description is then saved in its field.

Then the program goes on a check if it was the first note created or loop through the singly-linked list until the `next_note` field is null, it puts the address of the newly-created note there.

When deleting a note, it loops through the linked list to find the note with the matched title, _unlink_ it from the singly-linked-list then free its data and itself.

## Bugs

While reversing the binary, I found out that the `next_note` field is not initialized at the time of creating and clear it at the time of deletion.

So it left a dangling pointer there and also picked up the dangling pointer which is left there earlier.

So that opens us a use-after-free vulnerability.

Meanwhile, it creates a problem that if we are careless, we can put the program in an endless loop by having the `next_note` field points (directly/indirectly) to itself.

After hours of trying the program, I also found a critical logic bug.

The chunk that is malloc-ed to store the Description is memset by the size we entered but not the _actual_ chunk size.

Which means, if we create a 0-sized description, it will then `malloc(0)`, which gives 16 bytes, then `memset(chunk,0,0)` (which is nonsense).

So, we got an information disclosure of anything that was there before :)

## Exploit

### Checksec

```
[+] checksec for '/root/house_of_loop/house_of_loop'
Canary: Yes
NX: Yes
PIE: Yes
Fortify: No
RelRO: Full
```

### Information Disclosure
To leak a pointer, we can use the _0-sized_ description to leak the FD, BK of that chunk.

FYI, FD, BK pointers are used when a chunk is freed to points to the next free one.

That’s cool, we can easily leak the heap address.

But what about libc? Where can I find it?

Since glibc 2.26 with the introduction of `tcache`, we have a _libc-info-leak_

A chunk inside the unsorted bin will have a pointer to an libc address in the `fd` if that is the last chunk and in `bk`, if it was the first one.

[Reference](http://eternal.red/2018/children_tcache-writeup-and-tcache-overview/)

In my exploit, at line 67, I allocate a description that is big enough to go to the unsorted-bin, then I freed it, try to re-allocate that chunk with a _0-sized_ description. Because it was the last chunk, there will be a pointer :)

There was a reason why I also free the last chunk allocated. If we don’t do so, the last chunk we allocated will point to that chunk, but the dangling pointer there will throw us a ∞ loop

In other words, let consider the heap currently be allocated like this

```
|    A     |   B       |      C     |      D    |
    v          ^   v          ^   v      ^
    └──────────┘   └──────────┘   └──────┘
```
A is that big chunk, D is the last one we allocated.

The line represents the linked list pointer to the next note. They **don’t** go away upon deleting.

When you free A, then reallocate it, it will stay at the same position but with the pointer.

D will the points to A(the next one allocated) then A->B->C->D => ∞ loop

By also free D after A, these things happen:

- D's `next_note`(which is 0 because it is the last one) will be saved to C, which marks C as the last note.

- Because of malloc’s natural of a first-fit algorithm, the reallocated one will have the struct lied on D’s location and the description at A’s description.

- Because D has `next_note` field equal to 0 so it will be the last note(the previous one is C)

- The address will be at the description of the last allocated note.

- And that’s how you leak the libc address.

You can see the execution trace at [here](./libc_leak_trace.txt)

### From UAF to ACE

So the only field that was not initialized was `next_note`, so how can we control it?

To leave there an arbitrary pointer, we need to create another note that has the description size is the same size as the note structure.

Then we can attempt to re-allocate the description(which we have full control) as the note structure.

To re-allocate it, firstly, we will need to allocate a note that has the description’s size strictly greater than the note structure.

By doing that, we can make sure that our crafted struct is not being used as the description of the other note.

Then, the next note we allocate will lie on our crafted struct

Illustration

Before:

```
|    A    | data of A(144)|     B     | data of B(144)|
          |    crafted    |
```

After:

```
|    C    |      D        |     B     | data of B(144)| Data of C(144+)   | 
```

But…, what will we put there…???

Okay, we will set up an arbitrary-write primitive.

The GOT is Fully Protected, which mean it is read-only

Now, we are introducing to you the MALLOC HOOKS

The malloc hooks are available for debugging heap purpose, and it’s executed before any malloc operations

If the data at variable `__free_hook` or `__malloc_hook` is not NULL, it will be executed.

So, if we write the address we want there, and we will have ACE (Arbitrary Code Execution)

Ideally, you may want to write an address of a `one_gadget` there for the sake of simplicity.

But how?

Let’s check out this piece of code:

```c
int del_note(){
  //tbf_note: to be freed note
  //prev_note: the previous note of the one we want to free
  //s1: the title of the note we want to free
  ...
  for ( tbf_note = first_note; tbf_note && strncmp(&s1, tbf_note->title, 0x20uLL); tbf_note = tbf_note->next_note )
    prev_note = tbf_note;
  if ( tbf_note )
  {
    if ( prev_note )
      prev_note->next_note = tbf_note->next_note;
    else
      first_note = tbf_note->next_note;
    free(tbf_note->data);
    free(tbf_note);
   ...
}
```

As you can see, the program finds the note that we want to delete then does this piece of code:

`prev_note->next_note = tbf_note->next_note;`

It takes the address of the note that goes after the note will want to free, and then make it be the `next_note` of the note that comes before the one we want to free.

Illustration!!!

Before:

```
|    A     |   B       |      C     |
     v          ^   v          ^
     └──────────┘   └──────────┘
```

After:

```
|    A     |  freed   |      C     |
    v                        ^
    └────────────────────────┘
```

Basically, what it does it _unlink_ that note from the linked list

> Hey, have you learned the old-school dlmalloc unlink exploit yet?

The idea is simple,
 -  Let's make the A note lie on somewhere near `__free_hook`
 
      - Use the _use-after-free` vuln to make `__free_hook` address as the `next_note`
      
 -  Create a new note from A(Let's called it B)
 
 -  Then we _unlink_ B off the linked_list
 
 -  Anything at B->next_note will be put in A->next_note !!!! (Isn't that Arbitrary Write?)
 
 => Let's make `__free_hook` is also the `next_note` field of A :)
 
 > Isn't that the famous dlmalloc unlink exploit? ;)
 
 Friendly Reminder: Don't forget to fill up the heap holes you created by any stage of this exploit :)

[UAF->AW->ACE trace](./UAF-AW-ACE-trace.txt)

## Shoutout to

- chung96vn for creating this challenge(or the opportunity for me to learn heap exploit :))

- [This writeup](http://eternal.red/2018/children_tcache-writeup-and-tcache-overview/)
  
- [@ducphanduyagentP for letting me know about syms2elf](https://protegototalum.faith/post/csaw-ctf-17-qual/)
  
- You, Yes. You, for staying till this end of this writeup :)
