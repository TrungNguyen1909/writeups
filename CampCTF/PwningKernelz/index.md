---
title: "pwning your kernelz"
date: 2019-09-04T23:38:50+0700
Tags: ["Camp-CTF","pwn","kernel","xnu","0day"]
Language: ["English"]
---

pwning your kernelz
======

## Background

Hi everyone,

This is the writeup for the challenge _pwning your kernelz_, created by Linus Henze(@LinusHenze),
I came across this challenge when Linus tweeted a status update for the CTF.

Of course, I didn't solve this challenge during the time of the CTF. In fact, no one does.

So I decided to pick it up and exploit it with the support of Linus after the CTF ends.

## Challenge description

[Original description](https://camp.allesctf.net/tasks/pwning%20your%20kernelz)

The challenge required us to perform a Local Privilege Escalation to r00t user to get the flag.

SMEP is on,

SMAP is off,

kASLR slide is provided,

and the kernel is the _latest_ development macOS kernel from Apple's KDK.

Actually, at the time of the CTF,
Apple messed up and unpatched the 121 day (CVE-2019-8605) and you can just port the iOS exploit code to macOS and here we go.

But I didn't think of that during the time of the CTF, also I was pretty busy at that time so I didn't think about it.

But later, I decided to pick up the intended bug.

## POC

So the author provided us the following POC:

```c
x86_saved_state32_t state;
memset(&state, 0xFF, sizeof(x86_saved_state32_t));
thread_set_state(mach_thread_self(), x86_SAVED_STATE32, (thread_state_t) &state, x86_SAVED_STATE32_COUNT);
while (1) {}
```

You will need to compile it to a 32bit program (-m32) to make it works.

The POC is such a simple one that it immediately hang the whole machine.

## Debugging

I wasted a lot of time to setup the VM and trying to debug with Apple's kdp, but with this bug, triage it with kdp is hard.

The machine just hang because it's constantly doublefault.

Later, when I knew about the VMWare's gdb debugging stub, it actually makes my life much easier

[Check it out here](http://ddeville.me/2015/08/using-the-vmware-fusion-gdb-stub-for-kernel-debugging-with-lldb)

## Triaging the bug

The challenge mentioned about the need of 32bit apps, so we knows that the bug is somewhere in the `/osfmk/kern/i386/` 

The cross-arch code starts to differ from the `machine_thread_set_state` call.

So I found 2 snippets of code that share the same purpose but have different logic.

Inside the switch `flavor` case of the x86 version of `machine_thread_set_state`, you can find 2 different version

If the flavor is `x86_SAVED_STATE32`, the machine just hang.

If the flavor is `x86_THREAD_STATE32`, it does not cause any problem.

But they are supposed to have the similar behavior, so lets `diff` them out.

Although going through the same amount of checks, the second version forced the segment registers to be a value that's constantly defined

In the buggy one, we can see that it allows a wider range of segment registers' value, which could be malicious.

So, the bug is that we can set the segment registers' value to a malicious value.

This is similar to the _BadIRET_ bug

## Consequences

Attaching the debugger, tracing down through the 'iretq' instruction, it failed to return due to invalid segment registers and jump to the fault handler,

Following the execution, we can observe that the fault handler does *MISS* a `swapgs` instruction.

So why does this is troublesome?

The `swapgs` instruction changes the current GS base of the running code from kernelspace to userspace and vice versa.

Some data are accessed relatively through the GS register so we control some of the kernel's data.

In case you don't know what the segment registers are, they are just the index of some entries in the GDT (Global Descriptor Table).

Each entries contains meaningful data, one of them are the base address. And we can access data relatively from that base address through the registers

## Exploit

Following the buggy path, we can see that it repeatedly jump to the fault handler and always fault at the same instruction that access data through the GS base.

The reason is that it's using the userspace's GS value, which have the address based at 0x0.

To get over, we need to remove the _PAGEZERO segment by a linker switch, and allocate memory there with `vm_allocate` call.

Continuing with our zero-filled memory we just allocated, the kernel panic in `kernel_trap` with the error type is 13 (general protection (#GP))

According to the Intel's SDM, invalid segment registers can cause a #GP fault

So how can we escape that?

A piece of code that we did not consider yet is the specific handler for #GP fault:

```c
if (thread != THREAD_NULL && thread->recover) {
			set_recovery_ip(saved_state, thread->recover);
			thread->recover = 0;
			return;
		}
```

This might seems rather unintersting,

but if you disassemble it and resolve the macro,

we can see that we controlled the `thread->recover` value because it's accessed that through the GS base, which we controlled.

The `set_recovery_ip` set the location of the handler code in the next time the fault is occured, then we are dismissed from the fault handler.

So, by the next time we `iretq`, we have control over the kernel's RIP.

Next, I observed that we have some registers that we control over the `thread_set_state` call. One of them is the $RBP register.

So, I find a `leave; ret;` gadget (which should be plenty in the kernel code base) to pivot the kernel's stack to a userspace address.

There, we set up our ROP chain to escalate ourselves.

You can find the typical privilege escalation ROP chain [here](https://bazad.github.io/2016/05/mac-os-x-use-after-free/#elevating-privileges)

But there's still something to note.

First, we need to bear in mind that the GS base is still in the userspace upon the start of the ROP chain,
which causes some faulty in the `current_proc` function as it used the GS base, so we need to fix that.

Second, `thread_exception_return` will *NOT* work as the saved_state is invalid and messed up.

Because there aren't any `swapgs` gadgets, we need to make ourselves at the userspace and return there.

Before we can do that, we need to ROP to turn off SMEP by unset the 20th(0-indexed) bit of the $cr4 register.

To return to the userspace, we need to set up ourselves the `iret` stack, which looks like this
```

	|--------------------------|
	|       Low mem addr       |  ^
	|--------------------------|  |
	|           RIP            |  | <-- current RSP
	|--------------------------|  |
	|           CS             |  |
	|--------------------------|  |
	|          EFLAGS          |  |
	|--------------------------|  |
	|           RSP            |  |
	|--------------------------|  |
	|           SS             |  |
	|--------------------------|  |
	|      High mem addr       |  |
	|--------------------------|  |

```
  
then `swapgs` and `iretq` should do the trick.

Upon coming back, I encountered the `misaligned_stack_error_` when going through the dyld stub.
 
I workaround this by catching that SIGSEGV error: `signal(SIGSEGV,aftermath);`

## Ending words

During exploitation of this bug, I stuck lots of time and need to be pointed out.

I found lots of flaws in my reverse engineering and code reading skills and missed some of important points.

But at least, I make time for myself to reading through the kernel code.

Also, this's the first time I exploit a kernel 0 day that hasn't been disclosed and exploited publicly yet.

I enjoy this challenge.

## Shoutouts

- Apple for the 0day.

- Linus Henze(@LinusHenze). He created a challenge in which I learnt a lot.
Also, he helped me a lot in exploitation by pointing out the points that I have missed. Thank you very much.
