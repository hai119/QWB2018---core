from pwn import *
vmlinux = ELF("./vmlinux")
print("commit creds offset",hex(vmlinux.sym['commit_creds'] - 0xffffffff81000000))

