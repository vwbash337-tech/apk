import sys;sys.path.insert(0,'analysis')
from emu import Emu
import aesref
ZK=b'\x00'*16
def run(fn,pt,key):
    e=Emu(); o=e.malloc(24); e.wr(o,b'\x00'*24)
    e.call(fn,x0=e.mkstring(pt),x1=e.mkstring(key),x8=o,timeout=900*1000000)
    return e.getstring(o)
for n in (208,224,240,256,300,512,1024):
    pt=bytes((i*7+3)&0xff for i in range(n))
    g85=run(0x10c470,pt,b'0123456789abcdef')
    r85=aesref.ecb(pt,b'0123456789abcdef').hex().encode()
    g30=run(0x38fa4,pt,b'')
    r30=aesref.cbc_enc(pt,ZK,ZK).hex().encode()
    d=next((i for i in range(min(len(g30),len(r30))) if g30[i]!=r30[i]),None)
    print("n=%4d  #85(ECB) match=%-5s | #30(CBC) match=%-5s firstdiffbyte=%s len(got/exp)=%d/%d"%(
        n,g85==r85,g30==r30,(d//2 if d is not None else None),len(g30),len(r30)))
