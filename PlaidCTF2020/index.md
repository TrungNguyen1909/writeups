---
title: "PlaidCTF2020 PlaidStore mojo chromium"
date: 2020-04-22T19:42:49+0700
Tags: ["PlaidCTF2020", "CTF", "pwn", "chromium", "browser", "mojo", "use-after-free", "UAF"]
Language: ["English"]
---

PlaidStore
===

## Story

Hi, everyone, this is the writeup for the challenge 500pts "mojo" of PlaidCTF 2020.

As usual, I got the flag after the CTF has ended :<

Well, currently I am not in any active teams, so I decided to pick a hard challenge and do it on my own.

## Challenge Description
```
Chromium commit detached at 81.0.4044.92 (commit hash 82e68b9038ab5679543b300b42202bc053c50930).
```

Our task is to RCE chromium browser, after applying this [diff](./plaidstore.ctf)

We are also provided generated mojo-js files to interact with the IPC.

```
+++ b/third_party/blink/public/mojom/plaidstore/plaidstore.mojom
@@ -0,0 +1,11 @@
+module blink.mojom;
+
+// This interface provides a data store
+interface PlaidStore {
+
+  // Stores data in the data store
+  StoreData(string key, array<uint8> data);
+
+  // Gets data from the data store
+  GetData(string key, uint32 count) => (array<uint8> data);
+};
```

We now have access to the new interface through MojoJS.

## Path of Exploitation

### Creating connection

Urghhh, I stuck on this part for more than a day just to find the way to interact with the interface.
Lots of google-fu, renderer bad messages, promise rejection :<

But it's actually really easy :<. Just add those lines to your html

```html
<script src="mojo/public/js/mojo_bindings_lite.js"></script>
<script src="third_party/blink/public/mojom/plaidstore/plaidstore.mojom-lite.js"></script>
```

and in an async function of your Javascript, use this line to get a handle of the object, owned by the current frame, and interact.

```js
let p = blink.mojom.PlaidStore.getRemote(true);
await p.storeData("yeet",new Uint8Array(0x28).fill(0x41));
(await p.getData("yeet", count).data;
```

smh.

### The first bug

Well, the first bug I noticed was this one

```cpp
void PlaidStoreImpl::GetData(
	    const std::string &key,
	    uint32_t count,
	    GetDataCallback callback) {
	  if (!render_frame_host_->IsRenderFrameLive()) {
	    std::move(callback).Run({});
	    return;
	  }
	  auto it = data_store_.find(key);
	  if (it == data_store_.end()) {
	    std::move(callback).Run({});
	    return;
	  }
	  std::vector<uint8_t> result(it->second.begin(), it->second.begin() + count);
	  std::move(callback).Run(result);
	}
```

Can you spot the most obvious bug?

The `count` parameter has no checks on it.
As a result, the `result` array is being intialized with out-of-bound memory if `count` is larger than `it->second.size()`
So we got a heap out-of-bound read here.

To leak useful pointers from the heap, I put 0x40 arrays of (0x28 bytes) to the `PlaidStore`,
while attempting to allocate `PlaidStore` object right after each allocation.
Most of the time, the `PlaidStore` objects will lie after those arrays, which means we can read their pointers.

The most interesting one is their C++ `vtable` pointer, it points to the DATA section of the binary and contains pointers to instance methods.
So we could read that pointer, subtract it from the offset and find the base of the binary in memory.

`PlaidStoreImpl` objects will have the `vtable` pointer at offset `0` (always) and to its `render_frame_host_` at offset `8` (C++ classes are like structs).

Because a few high bits of the vtable address is always the same, and same goes to the highest byte, we could find them easily in the leak.

`content::PlaidStoreImpl::PlaidStoreImpl` is the constructor of the object so it will set the vtable
```
chrome[0x3c584a8] <+24>:  call   0x57044b0                 ; operator new(unsigned long)
chrome[0x3c584ad] <+29>:  lea    rcx, [rip + 0x635e2ec]    ; vtable for content::PlaidStoreImpl + 16
chrome[0x3c584b4] <+36>:  mov    qword ptr [rax], rcx
>>> hex(0x3c584b4+0x635e2ec)
'0x9fb67a0' -> the pointer(unslided) will be stored at offset 0
```

Or `(lldb) image lookup -r -v -s "vtable for content::PlaidStoreImpl"` will do the trick.

Keep it mind that the stored address will be off `+16` bytes from the symbol

Anyway, so we should find the pointer that looks like `0x5x..7a0`

And the pointer lie next to that will be its `render_frame_host_`

### Get code execution...

At the starts of all methods of `PlaidStore`, there's a check `(!render_frame_host_->IsRenderFrameLive())` seems to check whether its frame is live.
But it doesn't take into account that its `render_frame_host_` is valid or not.

If the `PlaidStore`'s frame has been freed, its `render_frame_host_` will be dangling and the memory it is pointing to is subjected to reallocation.

So there's definitely an use-after-free bug here.

To exploit that, we could create an `iframe` in the `document.body` and get its `PlaidStore` pointer, which will have its `render_frame_host_` pointed to the `iframe`.

We can easily access the `iframe`'s properties, as long as its source is in the same origin.

After get the `PlaidStore` pointer from there, we could deallocate the `iframe` by remove it from the `document.body`.

The best way to reallocate it back is to creating some allocations of the same size, for example 1024 allocations.
By doing that, we are creating pressure to the memory and most of the time, the frame will ended up being garbage-collected and let us allocate to the same memory.

Also, you can't rely on the fact that that memory is returned to allocation immediately, and by allocating numerous of times, it will increase the chance of successful reallocation.

The `RenderFrameHost` object's size is `0xc28`, which could be found by the method below:

- `content::RenderFrameHostImpl::RenderFrameHostImpl()` is called after that C++ object is allocated (a.k.a. constructor)

- Searching in the chromium source, it's called from content::RenderFrameHostFactory::Create(), looking into that function...

- Just before the constructor is called, the object's allocated using `operator new(unsigned long size)`

- So we can figure out the size using a `new` called that comes before the constructor is called.

```asm
	mov    edi, 0xc28;
	call operator new(); => size = 0xc28
```


So now we have a handle to a fake `RenderFrameHost` object that its content is controlled by us.

With that primitive, we could fake its vtable, and now `render_frame_host_->IsRenderFrameLive()`'s now ours.

```
//content::PlaidStoreImpl::StoreData
chrome[0x3c581da] <+26>:  mov    rdi, qword ptr [rdi + 0x8] //rdi = this->render_frame_host_
chrome[0x3c581de] <+30>:  mov    rax, qword ptr [rdi]//rax = vtable
chrome[0x3c581e1] <+33>:  call   qword ptr [rax + 0x160]//call vtable->IsRenderFrameLive
```

So the pointer at offset `0x160` of the fake object's vtable is called (`fake->vtable[0x160]()`), we could put the address of our first gadget in the ROP chain there.

I put a `xchg rax, rsp` first to change the stack pointer to point to our controlled data.

From here, we do a classic ROP chain to `execvp@plt` to read the flag.

> Use `ROPgadget` to find gadgets in the binary. `ropper` analysis took me forever.

Further details about the ROP chain could be found in [pwn.js](./pwn.js)

### Exploit

Most of the parts are contained in [pwn.js](./pwn.js).

The HTMLs parts are zipped in [exploit.zip](./exploit.zip).
Put them inside the extracted directory of `mojo_js.zip`

### The Flag

The flag is

> PCTF{PlaidStore\_more\_like\_BadStore}

But it didn't bring me any 500pts :<

Thanks~

- The challenge author for making me get into chromium for the first time.

- You, for reading till here.


