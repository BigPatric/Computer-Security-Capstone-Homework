#!/usr/bin/env python3
from pwn import *

p = process('../BACKUP/ret2flag')
p.sendline(cyclic(400))
p.wait()
core = p.corefile
print(hex(core.rip))
print(cyclic_find(core.rip))