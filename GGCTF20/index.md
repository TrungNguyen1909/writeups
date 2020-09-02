---
title: "Google CTF 2020 teleport Chromium sandbox escape"
date: 2020-09-02T19:48:00+0700
Tags: ["GGCTF2020", "CTF", "pwn", "sandbox", "chromium", "browser", "mojo", "reversing", "offset"]
Language: ["English"]
---

Teleport
===

> Please write a full-chain exploit for Chrome. The flag is at /home/user/flag. Maybe there's some way to tele<port> it out of there?

# 1. Story

Hi, last week I participated in Google CTF 2020 with my team `pwnPHOfun`

Although I didn't solve the challenge in time for the points; 
still, here is a writeup for the challenge `teleport` for you.

I like to write detailed articles that are understandable and replicable to my past self. Feel free to skip any parts. Here is a table of content for you.

<!-- TOC -->

- [Teleport](#teleport)
- [1. Story](#1-story)
- [2. Overview](#2-overview)
  - [2.1. Sandboxed or not sandboxed](#21-sandboxed-or-not-sandboxed)
  - [2.2. Provided primitives](#22-provided-primitives)
- [3. Leaking the browser process](#3-leaking-the-browser-process)
- [4. Googling](#4-googling)
- [5. Leaking the renderer process](#5-leaking-the-renderer-process)
- [6. Nodes and Ports](#6-nodes-and-ports)
- [7. Leaking ports' names](#7-leaking-ports-names)
  - [7.1. Finding offsets](#71-finding-offsets)
    - [7.1.1. Simple structures](#711-simple-structures)
    - [7.1.2. F*ck C++/Traversing `std::unordered_map`](#712-fck-ctraversing-stdunordered_map)
- [8. What do we do with stolen ports?](#8-what-do-we-do-with-stolen-ports)
  - [8.1. Factory of network requests](#81-factory-of-network-requests)
  - [8.2. Making the leaked ports ours](#82-making-the-leaked-ports-ours)
    - [8.2.1. Calling functions from shellcode](#821-calling-functions-from-shellcode)
  - [8.3. Sending our messages](#83-sending-our-messages)
  - [8.4. Writing our messages](#84-writing-our-messages)
  - [8.5. To know who our receivers are](#85-to-know-who-our-receivers-are)
  - [8.6. Where are my factory ??](#86-where-are-my-factory-)
    - [8.6.1. Setting the sequence_num](#861-setting-the-sequence_num)
    - [8.6.2. Getting the correct function parameters](#862-getting-the-correct-function-parameters)
- [9. Closing words](#9-closing-words)
  - [9.1. Shoutout](#91-shoutout)
  - [9.2. Reference](#92-reference)

<!-- /TOC -->

You may want to checkout the [exploit code](https://github.com/TrungNguyen1909/ggctf20-teleport).

No IDA/Ghidra were used during the creation of this work. I used only GDB.

# 2. Overview

The challenge files include a patch for chromium version 84.0.4147.94,
which basically has 2 features.

The first one is the `Pwn` object, and a code execution(?) primitive `Mojo::rce`

Both could be trivially used through `MojoJS`, which is enabled for us.

## 2.1. Sandboxed or not sandboxed

On the first sight, the challenge seems unexpectedly easy, or wasn't it ;)

But the `rce` primitive only provides us code execution inside the _renderer_ process, which is strictly sandboxed.

The `Pwn` object is on the _browser_ process, and provides an address leak of itself and a memory read primitive.

## 2.2. Provided primitives

So we have 2 things

- Sandboxed code execution inside _renderer_ process
- Arbitrary read inside _browser_ process

# 3. Leaking the browser process

The primitive `Pwn::this` will return the address of itself, which is a C++ object.

As every C++ object have its `vtable` located at offset `0x0`, by dereference the pointer returned by `Pwn::this` twice, you will get a function pointer. Subtracting it to a constant value, you can find the `_text` base of the browser's process

# 4. Googling

Because no obvious way to get code execution inside the browser's process, I started looking around on the internet and found [this article](https://googleprojectzero.blogspot.com/2020/02/escaping-chrome-sandbox-with-ridl.html),

Which is, by itself, interesting:
- First the article is written by `@_tsuro` or `Stephen Roettger`, and you can find his name in `chall.patch`

- Second, these words in the article is also interesting:
    > ... used from a compromised renderer
    > ... if you have an info leak vulnerability in the browser process

Isn't that was our case ;)

Later, my teammate found [this video](https://www.youtube.com/watch?v=ugZzQvXUTIk), also by `tsuro`

Wasn't that a smart way to make people read your article and watch your talk? ;)

Anyway, I highly recommend you watch those to get a basic overview of the solution and even solve it yourself.

# 5. Leaking the renderer process

With the `rce` primitive in our hands, the sky is your limit...

First, we want a pointer in our renderer process to be able to reuse chrome's code.

Take a look at the `Mojo::rce` function

```cpp
+void Mojo::rce(DOMArrayBuffer* shellcode) {
  size_t sz = shellcode->ByteLengthAsSizeT();
  sz += 4096;
  sz &= ~(4096llu-1);
  void *mm = mmap(0, sz, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
  ...
  memcpy(mm, shellcode->Data(), shellcode->ByteLengthAsSizeT());
  void (*fn)(void) = (void (*)(void)) mm;
  fn();
}
```

So the function copy our code into a newly-allocated Read-Write-Executable(rwx) page, and then execute it right?

```asm
   0x0000000009088315 <+277>:	mov    rdi,rbx ; dest
   0x0000000009088318 <+280>:	mov    rsi,r15 ; source
   0x000000000908831b <+283>:	call   0xa00f7e0 <memcpy@plt>
   0x0000000009088320 <+288>:	call   rbx
```

The above was the assembly equivalent for 3 last lines of code. There are 2 things worth mentioned:

- `rbx` and `rdi` will store the address of the rwx page
- `r15` will store the address of our original buffer

This enables us to RETURN an arbitrary number of values by write to `r15+X`,
then read it back in JavaScript.

For me, I read the return pointer from `[rsp]` to get a function pointer,
and derive the renderer's `_text` base.

# 6. Nodes and Ports

Node could be understood as _process_; when you launch chrome, it will spawn multiple children to isolate their data in case of compromisation, and each of them is a node.

Node's name is a 128-bit random integer

A node has multiple ports listening for messages, each of them has an attached endpoint which will consume the messages.

Similar to node, port's name is also a 128-bit random integer

A port is addressed using its node's name and its name (node:port)

Knowing a port's name and its node's name is equivalent to have a send right to that port.

> “[...] any Node can send any Message to any Port of any other Node so long as it has knowledge of the Port and Node names. [...] It is therefore important not to leak Port names into Nodes that shouldn't be granted the corresponding Capability.”
[Security section of Mojo core](https://chromium.googlesource.com/chromium/src/+/master/mojo/core/README.md#security)

A [node](https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/ports/node.h;bpv=1;bpt=1;l=69?gsn=Node) knows its own name
```cpp
class COMPONENT_EXPORT(MOJO_CORE_PORTS) Node {
  ...
  const NodeName name_;
  ...
}
```

A [port](https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/ports/port.h;bpv=1;bpt=1;l=64?gsn=Port) knows its name and its node
```cpp
class Port : public base::RefCountedThreadSafe<Port> {
  // The Node and Port address to which events should be routed FROM this Port.
  // Note that this is NOT necessarily the address of the Port currently sending
  // events TO this Port.
  NodeName peer_node_name;
  PortName peer_port_name;
}
```

# 7. Leaking ports' names


A node keeps track of its name, its local ports, and its remote ports (ports from another nodes that is known to this node)

```cpp
class COMPONENT_EXPORT(MOJO_CORE_PORTS) Node {
  ...
  const NodeName name_;
  ...
  std::unordered_map<LocalPortName, scoped_refptr<Port>> ports_;
  ...
}
```

By reading the browser process's memory and traverse through `ports_`, it's possible to _steal_ a privileged port.

One possible pointer path is `g_core->node_controller_->node_`

Just traverse that and dump all the ports' names.

## 7.1. Finding offsets

### 7.1.1. Simple structures

Finding offsets isn't a trivial task when you haven't familiar with memory, but a way to do that is to disassemble functions where that field is used.

*If you are experienced in finding offsets, it is okay to skip this part.*

For example, to find the offset of `node_controller_` in `g_core`, you could try disassemble this function

```cpp
NodeController* Core::GetNodeController() {
  base::AutoLock lock(node_controller_lock_);
  if (!node_controller_)
    node_controller_.reset(new NodeController(this));
  return node_controller_.get();
}
```

`this` pointer is always passed as the first argument

```asm
  0x0000000003723fba <+10>:	mov  r15,rdi
```

and this time, it is stored in `r15` register

The following code should be equivalent to the `if(!node_controller_)`
```asm
  0x0000000003723fc9 <+25>: mov  rbx,QWORD PTR [r15+0x30]
  0x0000000003723fcd <+29>: test rbx,rbx
```

Or the below should be equivalent to the return

```asm
  0x0000000003723ffd <+77>:  mov  rbx,QWORD PTR [r15+0x30]
  0x0000000003724001 <+81>:  mov  rdi,r14
  0x0000000003724004 <+84>:  call 0xa00fad0
  0x0000000003724009 <+89>:  mov  rax,rbx
  0x000000000372400c <+92>:  add  rsp,0x8
```

So the offset is probably `+0x30`.

The way of finding the remaining offsets is left as an exercise to the readers.

### 7.1.2. F*ck C++/Traversing `std::unordered_map`

Okay, now how do we dump all ports?

The worst thing about C++ containers is that their methods are inlined

One of our candidates for disassembling this time is 
```cpp
int Node::GetPort(const PortName& port_name, PortRef* port_ref) {
  PortLocker::AssertNoPortsLockedOnCurrentThread();
  base::AutoLock lock(ports_lock_);
  auto iter = ports_.find(port_name);
  if (iter == ports_.end())
    return ERROR_PORT_UNKNOWN;
...
  *port_ref = PortRef(port_name, iter->second);
  return OK;
}
```

because it used the [`.find` method](https://source.chromium.org/chromium/chromium/llvm-project/libcxx.git/+/78d6a7767ed57b50122a161b91f59f19c9bd0d19:include/__hash_table;drc=3c73561841650afb4718223958b4b6e86983c862;l=2485)

Disassembling it will give you a loooong and complicated(?) function, but there are a few interesting points

```asm
  0x0000000006d6c443 <+51>:	mov  rdi,QWORD PTR [r14+0x50]
  0x0000000006d6c447 <+55>:	mov  r12d,0xfffffff6
  0x0000000006d6c44d <+61>:	test rdi,rdi
  0x0000000006d6c450 <+64>:	je   0x6d6c5d2 ; not found
```

There's a nullcheck here, which is equivalent to [this one](https://source.chromium.org/chromium/chromium/llvm-project/libcxx.git/+/78d6a7767ed57b50122a161b91f59f19c9bd0d19:include/__hash_table;drc=3c73561841650afb4718223958b4b6e86983c862;l=2489). So `0x50` is probably where `bucket_count()` is

Continuing the path through a bunch of calculation with constants:

```asm
  0x0000000006d6c4f4 <+228>: mov  rax,QWORD PTR [r14+0x48]
  0x0000000006d6c4f8 <+232>: mov  rax,QWORD PTR [rax+r8*8]
  0x0000000006d6c4fc <+236>: test rax,rax
```

The second line of the above snippet is what we want to talk about.

`[rax+r8*8]` is an array access, with `rax` holding the base address, `r8` is probably the index and `8` is surely the element size.

And it's definitely [this line](https://source.chromium.org/chromium/chromium/llvm-project/libcxx.git/+/78d6a7767ed57b50122a161b91f59f19c9bd0d19:include/__hash_table;drc=3c73561841650afb4718223958b4b6e86983c862;l=2492)
```cpp
size_t __chash = __constrain_hash(__hash, __bc);
__next_pointer __nd = __bucket_list_[__chash];
```

So `__bucket_list_` is probably at offset `+0x48`

At this point, it is reasonable for anyone to try to go through all non-null elements(bucket) to dump all the elements by traversing the linked list.

However, this turns out to be a bad way to do so and I could even find duplicate elements and bad pointers.

However, with a bit of more time, you will find this defintion

```cpp
__bucket_list                         __bucket_list_;
pair<__first_node, __node_allocator>  __p1_;
pair<size_type, hasher>               __p2_;
pair<float, key_equal>                __p3_;
```

So `__p1_.first` will be our first element (`.begin()`).

With the `.begin()` pointer, it is possible to iterate through all elements just like a linked list. Inspecting the memory, you will find that `+0x10` from the `__bucket_list_` is a good educated guess for the `.begin()` pointer.

[Reference](http://llvm.org/viewvc/llvm-project/lldb/trunk/examples/synthetic/unordered_multi.py?view=markup&pathrev=189964)

# 8. What do we do with stolen ports?

## 8.1. Factory of network requests

One of the good candidates for a good target is a _privileged_ `URLLoaderFactory`, which relies in the network service, and has the ability to make network requests ([`URLLoaderFactory::CreateLoaderAndStart`](https://source.chromium.org/chromium/chromium/src/+/master:services/network/url_loader_factory.h;drc=6e8b402a6231405b753919029c9027404325ea00;bpv=1;bpt=1;l=57?q=URLLoaderFactory::CreateLoaderAndStart)), with files

`URLLoaderFactories` are wrapped by `CorsURLLoaderFactories`, which enforced CORS to all requests.

To isolate origins, factories created with renderers cannot be used to make requests to another origins.
However, the browser can create factories (`process_id_==kBrowserProcess`) that allow it to make arbitrary requests with no CORS enforced.

If we could get such a loader from the browser,  we could upload any files to our server.

> However, I noticed a code path that allows you to create a large amount of privileged URLLoaderFactories using service workers. If you create a service worker with [navigation preload](https://developers.google.com/web/updates/2017/02/navigation-preload) enabled, every top-level navigation would [create such a loader](https://cs.chromium.org/chromium/src/content/browser/service_worker/service_worker_fetch_dispatcher.cc?l=334&rcl=a129610c20b22dd77f65f137d88fc37dd1eb064f). By simply creating a number of iframes and stalling the requests on the server side, you can keep a few thousand loaders alive at the same time. 
> @_tsuro

To do so is pretty trivial, just make sure to use HTTPS and you are good to go.

## 8.2. Making the leaked ports ours

To send messages to the leaked ports' names, we need to register it to our node. Below is my way of doing it:

- Create a new port on our node using [`Node::CreateUninitializedPort`](https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/ports/node.h;bpv=1;bpt=1;l=100?gsn=CreateUninitializedPort)
- Initialize it with our leaked names using [`Node::InitializePort`](https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/ports/node.h;bpv=1;bpt=1;l=103?gsn=InitializePort)

After doing that, the leaked port will be inserted into your node's `ports_` map.

### 8.2.1. Calling functions from shellcode

It is impractical to run an assembler to compile your shellcode with the functions' addresses, providing that they shift around all the time under ASLR.

There are probably many ways of doing this, including [ways](https://github.com/xerub/acorn) that allow you to call functions directly from JavaScript.
However, I will stick to the assembly this time and use the `Mojo::rce` primitive.

In my shellcode, there will be a common pattern, which looks like this

```asm
  mov rax, 0x4141414141414141
  call rax
```

The `0x4141414141414141` value will be encoded as 8 consecutive little-endian bytes in the machine code. The JavaScript will be responsible to replace it with the correct address calculated from the leak.

## 8.3. Sending our messages

In the `Core` object, there are some interesting APIs

- [`Core::CreateMessage`](https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/core.h;bpv=1;bpt=1;l=169?gsn=CreateMessage)
- [`Core::AppendMessageData`](https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/core.h;bpv=1;bpt=1;l=174?gsn=AppendMessageData)
- [`Core::SendMessage`](https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/core.h;bpv=1;bpt=1;l=201?gsn=WriteMessage)

The purposes of them are clear just by their names.

However, the `Core::SendMessage` API takes a `MojoHandle message_pipe_handle` (an `uint32_t`) as a parameter, which is the receiving port.

To get a `MojoHandle`, we can use the API

`MojoHandle CreatePartialMessagePipe(const ports::PortRef& port)`,

which creates handles for our newly-created ports.

Later, I found the function [`mojo::WriteMessageRaw`](https://source.chromium.org/chromium/chromium/src/+/master:mojo/public/cpp/system/message_pipe.cc;drc=6e8b402a6231405b753919029c9027404325ea00;bpv=1;bpt=1;l=13?gsn=WriteMessageRaw), which takes our port's `MojoHandle`, message buffer, and an array of `MojoHandles`(?) and send the message.

Unfortunately, it takes a C++ object [`MessagePipeHandle`](https://source.chromium.org/chromium/chromium/src/+/master:mojo/public/cpp/system/message_pipe.h;drc=6e8b402a6231405b753919029c9027404325ea00;bpv=1;bpt=1;l=30?gsn=MessagePipeHandle), which is not so easy to create. So all I can do was replicate its behavior.

## 8.4. Writing our messages
If you take a look at the binding JS code (i.e. `URLLoaderFactoryProxy.prototype.createLoaderAndStart`), you will see that it uses the API `MessageV0Builder` to craft a message. That function will return a `Message` object, which contains a buffer, and an array of handles.

Our message obviously should contain the buffer, but what are the handles?

The function `URLLoaderFactory::CreateLoaderAndStart` has 2 special parameters: `mojo::PendingReceiver<mojom::URLLoader> receiver` and `mojo::PendingRemote<mojom::URLLoaderClient> client`.  `PendingReceiver` and `PendingRemote` indicate that these are shared objects, which are used through ports.

To pass these objects as parameters, you need to pass their handles, just 2 `uint32_t` to `Core::AppendMessageData`.

If you inspect the message generated by `MessageV0Builder`, its array of handles will contain 2 elements, equivalent to `receiver` and `client`. These elements are strings: `URLLoaderInterfaceRequest`, and `URLLoaderClientPtr`, respectively.

So we need to pass 2 handles, an `InterfaceRequest` and an `Ptr`. But how do we figure them out?

Here is the code to create a client
```js
  var client = new network.mojom.URLLoaderClientPtr();
  Mojo.bindInterface(
    network.mojom.URLLoaderClient.name,
    mojo.makeRequest(client).handle,
    "process"
  );
```

This parameter `mojo.makeRequest(client).handle` also seems like a handle. Its implementation can be viewed [here](https://source.chromium.org/chromium/chromium/src/+/master:mojo/public/cpp/bindings/interface_request.h;drc=6e8b402a6231405b753919029c9027404325ea00;bpv=1;bpt=1;l=161?q=mojo::makeRequest). 

```cpp
template <typename Interface>
InterfaceRequest<Interface> MakeRequest(
    InterfacePtr<Interface>* ptr,
    scoped_refptr<base::SequencedTaskRunner> runner = nullptr) {
  MessagePipe pipe;
  ptr->Bind(InterfacePtrInfo<Interface>(std::move(pipe.handle0), 0u),
            std::move(runner));
  return InterfaceRequest<Interface>(std::move(pipe.handle1));
}
```

It seems to create a MessagePipe, which will create 2 `MojoHandles`: `handle0` and `handle1`.
- `handle0` is binded to the passed `Ptr` 
- `handle1` is binded to a newly created `InterfaceRequest`

Lucky to us, handles are [generated increasingly](https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/handle_table.cc;drc=6e8b402a6231405b753919029c9027404325ea00;l=56). So we are able to predict the handles of the `Ptr` and `InterfaceRequest` from the handle of our port.

## 8.5. To know who our receivers are

While creating this exploit, I ran into a programming bug which prevents my message buffer being copied. This leads me to discover a way to know which object is behind the port:

By sending an invalid message (set [the first `uint32_t`(`header_size`)](https://source.chromium.org/chromium/chromium/src/+/master:mojo/public/cpp/bindings/lib/validation_util.cc;drc=6e8b402a6231405b753919029c9027404325ea00;bpv=1;bpt=1;l=30?q=ValidateStructHeader&ss=chromium%2Fchromium%2Fsrc&gsn=ValidateStructHeaderAndClaimMemory) 0), you can trigger a validation error at [this line](https://source.chromium.org/chromium/chromium/src/+/master:mojo/public/cpp/bindings/lib/validation_util.cc;drc=6e8b402a6231405b753919029c9027404325ea00;l=45) and the verbose logging willl print something like this

```
Mojo error in NetworkService:Validation failed for network.mojom.CookieAccessObserver [master] MessageHeaderValidator [VALIDATION_ERROR_UNEXPECTED_STRUCT_HEADER]
```

That's it, you now know who are you sending to.

## 8.6. Where are my factory ??

I stucked and cannot find any factories within the ports. There are even some ports which never responds to my messages.

At this point (ofc after the CTF has ended), Stephen points out my missing bit: I didn't set the messages' [`sequence_num`](https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/ports/event.h;drc=6e8b402a6231405b753919029c9027404325ea00;l=157). It seems like the Mojo system use this number to prevent message duplication.

[This number is increased by one when a message is sent.](https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/ports/node.cc;drc=6e8b402a6231405b753919029c9027404325ea00;l=1293) Fortunately, the correct `sequence_num` is stored in the `Port` object in the [field `next_sequence_num_to_send`](https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/ports/port.h;drc=6e8b402a6231405b753919029c9027404325ea00;l=111), which can be leaked from where we found our ports in browser process's memory.

### 8.6.1. Setting the sequence_num

Let me remind you that `MojoMessageHandle` is actually a [pointer](https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/core.cc;drc=6e8b402a6231405b753919029c9027404325ea00;l=349) to a `UserMessageEvent`. Unfortunately, the function `set_sequence_num` is inlined so the offset isn't free. However, you could get it by disassembling [`Node::PrepareToForwardUserMessage`](https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/ports/node.cc;drc=6e8b402a6231405b753919029c9027404325ea00;bpv=1;bpt=1;l=1230?gsn=PrepareToForwardUserMessage)

### 8.6.2. Getting the correct function parameters

This is a trivial part. Just take a look at the JavaScript Mojo binding code.

# 9. Closing words

The devil is actually in the details, isn't it ;)

## 9.1. Shoutout
- To Stephen, for creating this challenge, and pointing out my missing bit (after the CTF, ofc). Thank you a lot.
  
## 9.2. Reference
- [Stephen's article on P0 blog](https://googleprojectzero.blogspot.com/2020/02/escaping-chrome-sandbox-with-ridl.html)
- [Stephen's talk at OffensiveCon20](https://www.youtube.com/watch?v=ugZzQvXUTIk)