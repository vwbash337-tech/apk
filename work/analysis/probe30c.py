import sys;sys.path.insert(0,'analysis')
from emu import Emu
import aesref
ZK=b'\x00'*16
n=240
pt=bytes((i*7+3)&0xff for i in range(n))
e=Emu(); o=e.malloc(24); e.wr(o,b'\x00'*24)
e.call(0x38fa4,x0=e.mkstring(pt),x1=e.mkstring(b''),x8=o,timeout=600*1000000)
g=bytes.fromhex(e.getstring(o).decode())
exp=bytes.fromhex(aesref.cbc_enc(pt,ZK,ZK).hex())
print("got len",len(g),"exp len",len(exp))
for i in range(0,len(g),16):
    print("blk%2d got=%s exp=%s %s"%(i//16,g[i:i+16].hex(),exp[i:i+16].hex(),"==" if g[i:i+16]==exp[i:i+16] else "!!"))
# is got blk13 == ECB of pt blk13 (no chaining)?
print("ecb of pt[208:224] =",aesref.enc_block(pt[208:224],ZK).hex())
print("cbc-cont from blk12  =",aesref.enc_block(bytes(a^b for a,b in zip(pt[208:224],exp[192:208])),ZK).hex())
