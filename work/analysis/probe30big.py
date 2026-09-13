import sys;sys.path.insert(0,'analysis')
from emu import Emu
import aesref
ZK=b'\x00'*16
def f30(pt):
    e=Emu(); o=e.malloc(24); e.wr(o,b'\x00'*24)
    e.call(0x38fa4,x0=e.mkstring(pt),x1=e.mkstring(b''),x8=o,timeout=600*1000000)
    return e.getstring(o)
for n in (200,208,224,240,255,256,300,400):
    pt=bytes((i*7+3)&0xff for i in range(n))
    g=f30(pt)
    full=aesref.cbc_enc(pt,ZK,ZK).hex().encode()
    print("n=%3d outlen=%3d expect=%3d match=%s"%(n,len(g),len(full),g==full))
    if g!=full:
        # find first differing hex char
        d=next((i for i in range(min(len(g),len(full))) if g[i]!=full[i]),None)
        print("   first diff at hex char",d,"= byte",d//2 if d is not None else None)
        # does it match CBC of a prefix?
        for cut in range(0,n+1,16):
            if aesref.cbc_enc(pt[:cut],ZK,ZK).hex().encode()[:len(g)]==g[:len(aesref.cbc_enc(pt[:cut],ZK,ZK).hex().encode())][:64]:
                pass
        print("   got :",g.decode()[:80]); print("   exp :",full.decode()[:80])
