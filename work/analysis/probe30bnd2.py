import sys;sys.path.insert(0,'analysis')
from emu import Emu
import aesref
ZK=b'\x00'*16
def f30(pt):
    e=Emu(); o=e.malloc(24); e.wr(o,b'\x00'*24)
    e.call(0x38fa4,x0=e.mkstring(pt),x1=e.mkstring(b''),x8=o,timeout=900*1000000)
    return e.getstring(o)
for n in range(192,226):
    pt=bytes((i*7+3)&0xff for i in range(n))
    g=f30(pt); r=aesref.cbc_enc(pt,ZK,ZK).hex().encode()
    print("pt=%3d padded=%3d blocks=%2d exact=%s"%(n,n+(16-n%16),(n+(16-n%16))//16,g==r))
