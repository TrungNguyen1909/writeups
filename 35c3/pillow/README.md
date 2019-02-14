Pillow
======

## Background
This is the writeup for the challenge Pillow, created by Samuel Groß(@saelo) of Project Zero, of 35C3 CTF annually organized by @EatSleepPwnRpt happening at the end of year 2018.

I didn't solve this challenge during the CTF, when revisiting this challenge after checkout @LinusHenze repo, I have a big learning oppuntunity to checkout XNU exploitation, which was completely new to me.

## Basic stuff
Feel free to skip this part if you have already had a basic knowledge in Mach.
### Mach
Mach 3.0 was originally conceived as a simple, extensible, communications microkernel. It is capable of running as a stand-alone kernel, with other traditional operating-system services such as I/O, file systems, and networking stacks running as user-mode servers.

Mach is used to _send messages_ or do _remote procedure_ calls (RPC) between separate tasks. This modular structure results in a more robust and extensible system than a monolithic kernel would allow, without the performance penalty of a pure microkernel.

[More information](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/KernelProgramming/Mach/Mach.html)

### Mach Port
In Mach kernel, port is a very important concept, especially at its reference counting.

Port is a **one-way** transmission channel. The corresponding object in kernel is the `ipc_port`. 

There can only be one receiver but there can be multiple senders.

To be able to send a message through a port, you must have a send right to it.

When sending and receiving mach messages from userspace there are two important kernel objects, which are the foundation of Mach Port: ipc_entry and
ipc_object.

> `ipc_entry` are the per-process handles or names which a process uses to refer to a particular ipc_object.

> `ipc_object` is the actual message queue (or kernel object) which the port refers to.

> `ipc_entry` have a pointer to the `ipc_object` they are a handle for along with the ie_bits field which contains
the urefs and capacility bits for this name/handle (whether this is a send right, receive right etc.)

> Each time a new right(send or receive) is received by a process, if it already had a name for that right the kernel will
increment the urefs count. Userspace can also arbitrarily control this reference count via `mach_port_mod_refs`
and `mach_port_deallocate`. When the reference count hits 0 the entry is free'd and the name can be **re-used** to
name another right.

> -Ian Beer(@i41nbeer) of Google Project Zero-

> [Source](https://bugs.chromium.org/p/project-zero/issues/detail?id=959)

Port has two different usage. The first is for inter-process-communication (IPC); the second is for representing a kernel object.

For this writeup, we will only focus on IPC usage.

### MIG
> In Apple's code, there is one called MIG, which is automatically generated according to the defs file. It usually does some inter-core object conversion (such as from port to kernel object) and object reference count management, and then call the real kernel functions. If the kernel developer is not familiar with the meaning of defs or MIG's management of object reference counts, there is high possibility to manage the reference counts of the kernel objects improperly in the real kernel API of this MIG package, thus causing leaks of the reference counts or double free.

> -Qixun Zhao(@S0rryMybad) of Qihoo 360 Vulcan Team-


## Challenge
The distribution gives you 4 files, 2 Launch Daemons config and 2 executable act at daemon.

shelld looks promising, there is a function shell_exec with call an arbitrary command after do some verification with capsd
## Bug

shelld

```c
kern_return_t register_completion_listener(mach_port_t server, const char* session_name, mach_port_t listener, audit_token_t client) {
	CFMutableDictionaryRef session = lookup_session(session_name, client);
	if (!session) {
		mach_port_deallocate(mach_task_self(), listener);
		return KERN_FAILURE;
	}

	CFNumberRef value = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &listener);
	CFDictionaryAddValue(session, CFSTR("listener"), value);
	CFRelease(value);

	return KERN_SUCCESS;
}
```

This function is called by the MIG server.

The problem is that it does not respect the MIG schematics

> If a MIG method returns KERN_SUCCESS it means that the method took ownership of *all* the arguments passed to it.
> If a MIG method returns an error code, then it took ownership of *none* of the arguments passed to it.
[Source](https://bugs.chromium.org/p/project-zero/issues/detail?id=1417)

What does it mean that if the function return `KERN_SUCCESS`, it is responsible to manage all the resources passed in.

Otherwise, MIG will responsible for freeing all of it.

By `mach_port_deallocate`, the listener port will be double-freed (by the function and MIG) and the uref will be decreased.

When the uref reaches zero, it means that all connection to that port is deallocated, the port will be freed and be reused later

> When the receive right/port have already have a reference(name) in the task, the uref will be increased by one
> and decreased by one when it is deallocated

### Exploitation
If we pass in the capsd port to the listener and an invalid session, the port that shelld communicates with capsd will be freed and we can attach our port to it by using `register_completion_handler`.

=> IPC Man-in-the-middle

One more thing, even if we have passed capsd check, we still have the macOS Sandbox enforced to a session-name
To bypass this, we create a session with a super long name, then the sandbox will refused to enforce due to long path.

=> Arbitrary Code Execution outside the sandbox.

Other technical/implementation is noted in the exploit.c, please check it out.

## Reference

[Official Source Code](https://github.com/saelo/35c3ctf/tree/master/pillow)

[Reference](https://github.com/LinusHenze/35C3_Writeups/tree/master/pillow)


