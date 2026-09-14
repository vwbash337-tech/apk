import sys;sys.path.insert(0,'analysis')
from emu import Emu,STACK,STACK_SZ
from unicorn import UC_HOOK_MEM_WRITE
import aesref,collections
ZK=b'\x00'*16
n=400; pt=bytes((i*7+3)&0xff for i in range(n))
e=Emu(); X=STACK+STACK_SZ-0x10000
cnt=collections.Counter()
def w(mu,acc,addr,sz,val,ud):
    if STACK<=addr<STACK+STACK_SZ: cnt[addr-(X-0x5d0)]+=1
e.mu.hook_add(UC_HOOK_MEM_WRITE,w)
o=e.malloc(24); e.wr(o,b'\x00'*24)
e.call(0x38fa4,x0=e.mkstring(pt),x1=e.mkstring(b''),x8=o,timeout=900*1000000)
print("slots with >=5 writes (frame-relative), 0x00..0x620:")
for off in sorted(cnt):
    if cnt[off]>=5: print("  +0x%03x  %d"%(off,cnt[off]))
