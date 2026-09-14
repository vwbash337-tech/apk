import sys;sys.path.insert(0,'analysis')
from emu import Emu
import aesref
ZK=b'\x00'*16
def f30(pt):
    e=Emu(); o=e.malloc(24); e.wr(o,b'\x00'*24)
    e.call(0x38fa4,x0=e.mkstring(pt),x1=e.mkstring(b''),x8=o,timeout=600*1000000)
    return e.getstring(o)
def f85(pt,key=ZK):
    e=Emu(); o=e.malloc(24); e.wr(o,b'\x00'*24)
    e.call(0x10c470,x0=e.mkstring(pt),x1=e.mkstring(key),x8=o,timeout=600*1000000)
    return e.getstring(o)
print("len  f30==cbc(zk,zk)  f30==ecb(zk)  outlen")
for n in list(range(0,80,1))+[96,128,200,255,256,300]:
    pt=bytes((i*7+3)&0xff for i in range(n))
    g=f30(pt); c=aesref.cbc_enc(pt,ZK,ZK).hex().encode(); ecb=aesref.ecb(pt,ZK).hex().encode()
    print("%4d  %-14s %-12s %4d %s"%(n,g==c,g==ecb,len(g), "" if g==c else ("ECB!" if g==ecb else "?")))
    if n>=70 and n<74:
        print("   got:",g.decode()[:96]); print("   cbc:",c.decode()[:96]); print("   ecb:",ecb.decode()[:96])
