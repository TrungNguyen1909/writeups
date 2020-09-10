---
title: "IPwnKit DEFCON CTF 26 QR"
date: 2019-04-21T00:46:45+0700
Tags: ["DEFCON-CTF", "CTF", "pwn","xnu","IOKit","race-condition","double-fetch"]
Language: ["English"]
---

IPwnKit
===

> Come and take a bite of the Apple!

> We have reserved you a very special place at the WWPC (World Wide Pwning Conference).

> Email ipwnkit@gmail.com to RSVP and we will reply with your invite.

> Come, test your skills, and win pwn2ooown!!!

> Fine print: sw_vers 17E202.

> The VM will be reset between exploit attempts.

> If you panic the kernel and don't walk away with the flag, you are BANNED FROM THIS CHALLENGE, so make it count!

> Please don't waste our time.

> The flag is in `/var/root/flag`.

Hi everyone, this is the writeup for the DEFCON 26 Qualification Round's iPwnKit challenge

You may want to checkout the [exploit code](https://github.com/TrungNguyen1909/writeups/tree/master/DEFCON26-Qual/iPwnKit/)

## Prerequisites
- IOKit basic communication. You can read chapter 5 of the book _OS X and iOS Kernel Programming_.

## Description

The author gives us a macOS IOKit kernel extension and a kernel binary, and our job is to get root and read that file without panic the kernel.

There are many functions in the kernel extension, but we only need to care about the functions which are in the `io_oooverflow_IPwnKitUserClient` class.

When we invoke through the `IOConnectCall` method family, our passing arguments will be packed as the second parameter of the `externalMethod` function

From there, the kernel extension will check through the dispatch table and invoke our `selector` function.

Our vtable has the symbol `IPwnKitUserClient::sMethods` which is basically an array of `IOExternalMethodDispatch`

```cpp
struct IOExternalMethodDispatch
{
	IOExternalMethodAction function;
	uint32_t           checkScalarInputCount;
	uint32_t           checkStructureInputSize;
	uint32_t           checkScalarOutputCount;
	uint32_t           checkStructureOutputSize;
};
```

The data in this struct will be used to check the input/output size before it jumps to our selected function

When a check does not need to be enforced, the value `kIOUCVariableStructureSize` (-1) will be there.

According to the dispatch table in the kernel extension, it will dispatch to the methods that are prefixed with 's' before the actual function.

Obviously, the interesting methods are `ReadNum`, `WriteNum`, and `FillArray`

But before we can get there, we have to go through `sReadNum`, `sWriteNum`, and `sFillArray`, correspondingly.

I will not cover reverse-engineer stuff because after I finished my first exploit, I'd realized that I did lots of obsolete stuff due to errors in reverse engineer, and I will mostly show the source code instead.

> Reversing C++ is hard =(

But basically, the UserClient class has an array as property and we are supposed to use those functions to manipulate it.

Here is an over-simplified declaration of the struct `IOExternalMethodArguments` which is used to pass the method's arguments

```cpp
struct IOExternalMethodArguments
{
	...
	const uint64_t *    scalarInput;//24-8
	uint32_t        scalarInputCount;//32-4

	const void *    structureInput;//36-8
	uint32_t        structureInputSize;//44-4

	IOMemoryDescriptor * structureInputDescriptor;//48-8
   
	uint64_t *        scalarOutput;//56-8
	uint32_t        scalarOutputCount;//64-4

	void *        structureOutput;//68-8
	uint32_t        structureOutputSize;//76-4

	IOMemoryDescriptor * structureOutputDescriptor;//8
	uint32_t         structureOutputDescriptorSize;//4
	...
};
```

The `sReadNum` has an error called "no descriptor" and also, the input structure size limit is unlimited, which means that we need to make use the `IOMemoryDescriptor * structureInputDescriptor` field.

This field is used to pass structure that is larger than the page size (4096 bytes).

When the structure argument is smaller than the page size, it will be copied over the kernel memory.

But when it's larger than the page size, IOKit will use that field to create a _reference_ to the userland memory.

In other words, it's called out-of-line transmission.

## Bug

It's boring to write inside the array though, so we may want an out-of-bounds read and write.

```cpp
IOReturn IPwnKitUserClient::sReadNum(IPwnKitUserClient* target, void* reference, IOExternalMethodArguments* arguments)
{
	...
	int64_t idx;
	arguments->structureInputDescriptor->readBytes(0, &idx, sizeof (idx));
	if (idx >= sizeof (IPwnKitUserClient::myNumbers) || idx < 0) {
		IOLog("invalid index %d\n", idx);
		return KERN_FAILURE;
	}
	return target->ReadNum(arguments);
}
IOReturn IPwnKitUserClient::ReadNum(IOExternalMethodArguments *arguments) {
	IOLog("%s[%p]::%s reading number stored\n", getName(), this, __FUNCTION__);
	read_num_t rnum;
	arguments->structureInputDescriptor->readBytes(0, &rnum, sizeof (read_num_t));
	int64_t idx = rnum.index;
	arguments->scalarOutput[0] = idx;
	arguments->scalarOutput[1] = this->myNumbers[idx];
	
	return KERN_SUCCESS;
}
```

We can see that the method `sReadNum` read the structure from the Descriptor and then perform both the lower and upper bound checks for the index and invoke the `ReadNum` method

Did you spot the bug here?

The `structureInputDescriptor` is a **reference** to the userland memory. It does perform the check on the value but not always the one will be used later because the `ReadNum` method just read it again.

We got a race-condition double-fetch issue here.

## Exploit

So we pass a large structure to pass the size checks and then create a new thread that repeatedly changes the index argument field between a valid index and an out-of-bounds index until we have our target index in the output structure.

After tries, in the best-case scenario, we will have the correct value at the correct time.

The issue is shared between the `readNum` and `writeNum` method.

By printing the value at various out-of-bound index, we found a persistent(not across reboot) kernel address at the index -30.

Read that and we will defeat the kASLR.

(to be continued)

## Yet another bug

The `fillArray` method seems interesting as it may be exploited to smash the kernel stack for ROP.

It copies our passed array to a local static-size array and then manually copies 10 `int64_t` value to the field array.

The size will be copied is stored in an initialized field of the UserClient class.

## Exploit (continued)
With our relative address out-of-bound write, we can corrupt that value and make it copies as much as we want and _smash the kernel stack_.

Please bear in mind that the arguments struct reference is put on the stack and you must not overwrite it with an invalid address as it's later used to write the result of the write.

I was too lazy at that time so I decided to run the exploit in a kernel version which I've already made a privilege escalation ROP chain.

The kernel I used was the one of build `macOS 10.14.2 (18C54)` but everything should be basically the same.

To be honest, I have to read a little spoiler before I finished the first exploit.

The attached exploit is the one I have cleaned up after reading the source and understanding the exploit completely

The flag for the challenge is

> OOO{woah i didnt know about kernel races!}

## Shoutout

- Jeff Crowell - the challenge author for creating such an awesome challenge and sending me the source and the distribution after a year after the CTF took place.
	
- Ole Henry Halvorsen and Douglas Clarke - the authors of the book _OS X and iOS Kernel Programming_
