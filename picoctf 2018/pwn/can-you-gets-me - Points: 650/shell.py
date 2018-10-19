#!/usr/bin/python2

from pwn import *
context(os="linux", arch="i386")
print asm(shellcraft.linux.sh())