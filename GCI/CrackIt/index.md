---
title: "CrackIt, GCI"
date: 2019-12-06T13:33:37+07:00
Tags: ["GCI","CodeIn","Google","easy","reverse"]
Language: ["English"]
---

CrackIT
===

Writeup for CrackIt task at Google CodeIn 2019

## 1stcrackme

easy, you can use `strings 1stcrackme` to list all strings in binary

stripped output:
```
Enter password:
FEDORAGCIPASSEASY
Success!
Error! Wrong password!
```

Because the password should be around the prompt and the  so we could try `FEDORAGCIPASSEASY` because it looks like a password
(my intuition, please don't ask)
	
And it works
```
[user@archlinux Crackit-GCI]$ ./1stcrackme
Enter password: FEDORAGCIPASSEASY
Success!
Enter password:
```
When I enter the string again, It didn't work. At this point I look the `strings` output again and then I saw 2 more suspicious strings
```
0x1337
0x133337
```
Yeah, Who doesn't want to be l33t ;)

So I opened it in Ghidra to checkout the whole logic.
	
```c
undefined8 main(void)
{
  int iVar1;
	char local_78 [112];
	
	printf("Enter password: ");
	__isoc99_scanf(&DAT_00102015,local_78);
	iVar1 = strcmp(local_78,"FEDORAGCIPASSEASY");
	if (iVar1 == 0) {
		puts("Success!\r");
	}
	else {
		puts("Error! Wrong password!\r");
	}
	printf("Enter password: ");
	__isoc99_scanf(&DAT_00102015,local_78);
	iVar1 = strcmp(local_78,"0x1337");
	if (iVar1 == 0) {
		puts("Success!\r");
	}
	else {
		puts("Error! Wrong password!\r");
	}
	printf("Enter password: ");
	__isoc99_scanf(&DAT_00102015,local_78);
	iVar1 = strcmp(local_78,"0x133337");
	if (iVar1 == 0) {
		puts("Success!\r");
	}
	else {
		puts("Error! Wrong password!\r");
	}
	return 0;
}
```

Look at the `s2` parameter of `strcmp` call that compares our input with that hardcoded password,

we solved all 3 password challenges of this program.

```
[user@archlinux Crackit-GCI]$ ./1stcrackme
Enter password: FEDORAGCIPASSEASY
Success!
Enter password: 0x1337
Success!
Enter password: 0x133337
Success!
```

## 2ndcrackme

```
[user@archlinux Crackit-GCI]$ ./2ndcrackme
usage:
./2ndcrackme <password>
```
okok, so the binary requires us to put the password on the CLI paramter. I put a random string there.

```
[user@archlinux Crackit-GCI]$ ./2ndcrackme a
Error! Wrong Password!
```

The `strings` command output doesn't show any suspicious strings like before, so I use `ltrace`

Here is the output

```
[user@archlinux Crackit-GCI]$ ltrace ./2ndcrackme a
strcmp("a", "FEd0raGCIt@sk")                                   = 27
puts("Error! Wrong Password!"Error! Wrong Password!
)                                                              = 23
+++ exited (status 0) +++
```
We can see that the program does `strcmp` our supplied password with another string

that seems to be hardcoded in a way that it doesn't show up in `strings`

```
[user@archlinux Crackit-GCI]$ ./2ndcrackme FEd0raGCIt@sk
Success!
```
Solved

## 3rdcrackme

Okay, I open the binary in GHIDRA

```c
undefined8 main(void)

{
	int iVar1;
	char local_48 [32];
	undefined8 local_28;
	undefined8 local_20;
	undefined4 local_18;
	undefined2 local_14;
	int local_c;
	
	local_28 = 0x306b403136673030;
	local_20 = 0x313531646e616c30;
	local_18 = 0x6c656334;
	local_14 = 0x21;
	local_c = 0;
	printf("Enter the password! ");
	gets(local_48);
	iVar1 = memcmp(local_48,&local_28,0x16);
	if (iVar1 == 0) {
		local_c = 1;
	}
	puts("\nChecking password...\n");
	if (local_c != 0) {
		puts("Successfully logged in!\nGood job!");
				/* WARNING: Subroutine does not return */
		exit(0);
	}
	puts("Login failed!");
	return 0;
}
```

So it `gets` our password from `stdin` and then `memcmp` with a pointer(`&local_28`) and the size is 0x16

There're 5 integers which is intialized with 5 hexadecimal integers

By intuition, I immediately realized that those hexs are actually ASCII character.

Because Ghidra doesn't know the types of those variable, It splits them into 5 integers.

The integers are named after their locations on the stack (offset from stack base).

Also, because characters are represented in memory just like integers, it's just the way we understand it matters.

Knowning that, we convert those integers to characters.

Don't forget our architecture is Little endian so we have to reverse the byte order...

Anyway, I checkout the assembly code of that pseudo code.

```
	001011af 48 b8 30        MOV        RAX,"00g61@k0"
		 30 67 36 
		 31 40 6b 30
	001011b9 48 ba 30        MOV        RDX,"0land151"
		 6c 61 6e 
		 64 31 35 31
	001011c3 48 89 45 e0     MOV        qword ptr [RBP + local_28],RAX
	001011c7 48 89 55 e8     MOV        qword ptr [RBP + local_20],RDX
	001011cb c7 45 f0        MOV        dword ptr [RBP + local_18],"4cel"
		 34 63 65 6c
	001011d2 66 c7 45        MOV        word ptr [RBP + local_14],'!'
		 f4 21 00
```
and let Ghidra do the conversation for me.

So in the program memory, It should be `00g61@k00land1514cel!`,

which is `local_28+local_20+local_18+local_14+local_c` 

(plus is understood as string concatenation)

The `memcmp` get the pointer to the first character in the

Knowing the value that our password is going to be compare with, we solved the problem.

```
[user@archlinux Crackit-GCI]$ ./3rdcrackme
Enter the password! 00g61@k00land1514cel!

Checking password...

Successfully logged in!
Good job!
```
.

.

.

Wait, there's more.

The program used `gets` to read a string to the stack without size limitations.

This exposes the program to a buffer-over-flow vulnerbility.

We can overwrite those variables, including the correct password.

Here is a better pseudo code to look at.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
	char input[32]; // [rsp+0h] [rbp-40h]
	char password[28]; // [rsp+20h] [rbp-20h]
  int v6; // [rbp-8h]
	strcpy(password, "00g61@k00land1514cel!");
	v6 = 0;
	printf("Enter the password! ", argv);
	gets(input);
	if ( !memcmp(input, password, 0x16uLL) )
		v6 = 1;
	puts("\nChecking password...\n");
	if ( *(_DWORD *)&password[28] )
	{
		puts("Successfully logged in!\nGood job!");
		exit(0);
	}
	puts("Login failed!");
	return 0;
}
```

At here, you can see the intialized correct password.

By the way, strcpy might have been optimized so you won't see it in the binary. 

The input is located on top of the password. Which means that on the right of the `input` is the intialized `password`

Memory:
```
Low------------------->High
|input(32bytes)|password(28 bytes)|v6(4 bytes)|sp(8 bytes)|ip(8 bytes)|
```

So we can overwrite the password and make the input identical with the `password`.

```
[user@archlinux Crackit-GCI]$ ./3rdcrackme
Enter the password! AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Checking password...
Successfully logged in!
Good job!
```

.

.

.

Not so fast, Until I checkout the function list, I found a function named `secret` which seems to be our real destination.

The buffer-over-flow vulnerbility here is so powerful that it can drive us into any functions.

P/s: The memory representation up there still applied here.

IP = Instruction Pointer. It is saved there so we can return to our previous function. But if we overwrite it, we can go anywhere we want!

P/s 2: For the next part, I'm gonna disable Linux's ASLR:

Run this command from root shell.
```
# echo 0 > /proc/sys/kernel/randomize_va_space
```

So if we overwrite `ip` with `secret`'s address, we can get there.

`secret` is at 0x555555555175, we convert that address to bytes then put it at the `ip`, which is at 66 bytes from the start of our `input`.

Oh, by the way, If `exit(0)` is called, `ip` won't be used as `exit` use a short-circuit path to exit the program.

So you will need the password to be incorrect to reach there.

Because the comparison result(`v6`) is also saved on the stack,

we need to overwrite it with 4 zero bytes (because it is an integer) to force it to be zero.

If you overwrite it with non-zero bytes, it will `exit(0)` and we can't get `secret` running.

Here is the command to prepare the input and _pipe_ it in to the program.

```
$ python -c "print('\x41'*0x20+'\x42'*0x1c+'\x00'*4+'\xde\xad\xbe\xef'+'\x75\x51\x55\x55\x55\x55')" \
| ./3rdcrackme
Enter the password!
Checking password...

Login failed!
You found the secret function!
Congrats!
The password is: FEDORAPASSWORDGCI!
```

Thanks for reading!

