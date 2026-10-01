#!/usr/bin/env python3
from pwn import *

target_ip = '140.113.207.245'
port = 30173

r = remote(target_ip, port)
print(r.recvline())
r.sendline(b'1')
print(r.recvline())
r.sendline(b'999999')
print(r.recvline())
r.interactive()
r.close()