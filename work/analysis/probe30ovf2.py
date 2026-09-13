import sys;sys.path.insert(0,'analysis')
from emu import Emu,STACK,STACK_SZ
from unicorn import UC_HOOK_MEM_WRITE
import aesref, collections
ZK=b'\x00'*16
n=1000
pt=bytes((i*7+3)&0xff for i in range(n))
e=Emu()
spstart=STACK+STACK_SZ-0x10000
base=spstart-0x5d0          # sp after `stp x29,x30,[sp,#-0x60]!` then `sub sp,sp,#0x570`
cnt=collections.Counter()
def w(mu,acc,addr,sz,val,ud):
    if STACK<=addr<STACK+STACK_SZ: cnt[addr-base]+=1
e.mu.hook_add(UC_HOOK_MEM_WRITE,w)
o=e.malloc(24); e.wr(o,b'\x00'*24)
e.call(0x38fa4,x0=e.mkstring(pt),x1=e.mkstring(b''),x8=o,timeout=900*1000000)
g=bytes.fromhex(e.getstring(o).decode()); exp=aesref.cbc_enc(pt,ZK,ZK)
d=next((i for i in range(min(len(g),len(exp))) if g[i]!=exp[i]),None)
print("pt=%d ct=%d firstdiv=%d"%(n,len(g),d))
print("frame-base-relative write histogram (top 25 by offset):")
for off in sorted(cnt)[-25:]: print("   +0x%04x  writes=%d"%(off,cnt[off]))
print("\ndensest 16-byte-aligned slots in 0x80..0x200:")
for a in range(0x80,0x200,16):
    tot=sum(cnt.get(a+k,0) for k in range(16))
    if tot: print("   +0x%03x total=%d"%(a,tot))
