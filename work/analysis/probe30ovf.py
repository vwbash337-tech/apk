import sys;sys.path.insert(0,'analysis')
from emu import Emu,STACK,STACK_SZ
from unicorn import UC_HOOK_MEM_WRITE
from unicorn.arm64_const import UC_ARM64_REG_SP
import aesref, collections
ZK=b'\x00'*16
for n in (200,400,1000):
    pt=bytes((i*7+3)&0xff for i in range(n))
    e=Emu()
    spstart=STACK+STACK_SZ-0x10000
    hist=collections.Counter()
    def w(mu,acc,addr,sz,val,ud):
        if STACK<=addr<STACK+STACK_SZ: hist[addr-spstart]+=1
    e.mu.hook_add(UC_HOOK_MEM_WRITE,w)
    o=e.malloc(24); e.wr(o,b'\x00'*24)
    e.call(0x38fa4,x0=e.mkstring(pt),x1=e.mkstring(b''),x8=o,timeout=900*1000000)
    g=bytes.fromhex(e.getstring(o).decode())
    exp=aesref.cbc_enc(pt,ZK,ZK)
    d=next((i for i in range(min(len(g),len(exp))) if g[i]!=exp[i]),None)
    print("pt=%4d ct=%4d firstdiv=%s"%(n,len(g),d))
    top=sorted(hist)[-6:]
    print("   highest stack write offsets (rel. initial SP):",[hex(t) for t in top])
