---
title: "kpets FacebookCTF 2019 Qualification Round"
date: 2019-06-12T23:15:34+0700
Tags: ["FBCTF", "CTF", "pwn","linux","race-condition","double-fetch"]
Language: ["English"]
---

```
 __  __     ______   ______     ______   ______    
/\ \/ /    /\  == \ /\  ___\   /\__  _\ /\  ___\   
\ \  _"-.  \ \  _-/ \ \  __\   \/_/\ \/ \ \___  \  
 \ \_\ \_\  \ \_\    \ \_____\    \ \_\  \/\_____\ 
  \/_/\/_/   \/_/     \/_____/     \/_/   \/_____/ 

																									 
welcome to Kernel Pets Simulator!
```

> We wrote a pet store application that was too slow, so we made a kernel module for it instead.

> Author: pippinthedog

Hi everyone, this is the writeup for the Facebook CTF 2019 Qualification Round kpets challenge

# Description

We are given a linux kernel module, packed with a qemu VM that runs Linux 5.1.5.

The module, like it's self-introduction, is a application that can create and view pets.

We'll communicate with the module by reading and writing over the pseudo-file-descriptor `/dev/kpets`

`dev_read` is the read handler, while `dev_write` is the write handler.

The only path that leads us to the flag is in the `dev_read` method, when the value 0xAA is in the first byte of a pet.

The other path will print the pets and then return;

We should try to make a pet that have a 0xAA in the first byte.

`dev_write` will create a new pet from the struct that we written in.

It's perform some sanity checks to prevent buffer-overflow.

Most importantly, it checks that the first byte shouldn't be 0xAA

One more thing, by reversing (which I haven't found during the CTF 😭), we can see that it saves the pets backward.

# Bug

```c
int dev_write(__int64 a1, char *buf, __int64 sz)
{
	v17 = sz;
	copy_from_user(&v19, buf + 4, 4LL);
	if ( v19 > 0x20 )
	{
		printk("kpets: invalid pet name len: 0x%02x\n", v19);
		return v17;
	}
	copy_from_user(&v20, buf + 40, 4LL);
	if ( v20 > 0x40 )
	{
		printk("kpets: invalid pet description len: 0x%02x\n", v20);
		return v17;
	}
	//Cut off
	printk("kpets: your new pet owner is %s!", names[v21 % 6]);
	copy_from_user(&v18, buf, 1LL);
	if ( (unsigned __int8)(v18 + 64) > 1u && v18 != 0xC2u )
	{
		printk("kpets: invalid pet type: 0x%02hhx\n", v18);
	}
	else
	{
		copy_from_user(&v21, buf + 4, 4LL);
		*v10 = v18;
		copy_from_user(v10 + 8, buf + 8, (unsigned int)v21);
		copy_from_user(v10 + 44, buf + 44, v20);
	}
	return v17;
}
```

We can see that it checks the supplied length of the pet's name and the supplied length of the pet's description
and then copy that amount of data to kernel memory.

The problem is in this piece of code:

```c
copy_from_user(&v19, buf + 4, 4LL);
if ( v19 > 0x20 )
{
	printk("kpets: invalid pet name len: 0x%02x\n", v19);
	return v17;
}
...
copy_from_user(&v21, buf + 4, 4LL);
*v10 = v18;
copy_from_user(v10 + 8, buf + 8, (unsigned int)v21);
```

The module copies the length from the userspace, perform checks on it, and copies it **AGAIN** from the userspace, unchecked, to use it as the copy length.

By doing this, it introduces a race condition.

That value may have been changed in the user's memory between two copies, which invalidates the sanity checks.

From here, we have a buffer-overflow with arbitrary data's length on the name field of the kernel memory.

To exploit this, we can create a new thread that repeatedly changes the length value in the userspace.

# The remaining road to the flag....

Well, I did stop here 8 hours before the CTF ends....


It was a late Sunday night...


My teammates are resting for the next Monday...


I was stuck.


Well, after 2 weeks, I'm here.

To finish what I did start....

But then I continued to fail.

I decided to read some spoilers....

Back on.

We can see that it saves the pets backward.

So, we can just first create a pets that satisfies all the condition.

Then use the race condition to make the next pet's name overflows to the previous one with 0xAA

Then, we got the flag.

# Shoutout

- pippinthedog from Facebook CTF for bringing a great challenge for me.

- WALLY0813's writeup. Without that writeup, I couldn't have finish the leftover part.
