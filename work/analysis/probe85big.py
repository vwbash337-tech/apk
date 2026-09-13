import sys;sys.path.insert(0,'analysis')
from emu import Emu
import aesref
def run(fn,pt,key):
    e=Emu(); o=e.malloc(24); e.wr(o,b'\x00'*24)
    e.call(fn,x0=e.mkstring(pt),x1=e.mkstring(key),x8=o,timeout=900*1000000)
    return e.getstring(o)
K=b'0123456789abcdef'
bad=0
for n in list(range(200,260))+[300,512,1024,4096,20000]:
    pt=bytes((i*7+3)&0xff for i in range(n))
    g=run(0x10c470,pt,K); r=aesref.ecb(pt,K).hex().encode()
    if g!=r:
        d=next((i for i in range(min(len(g),len(r))) if g[i]!=r[i]),None)
        print("  #85 MISMATCH n=%d firstdiv=%s"%(n,d//2 if d is not None else None)); bad+=1
print("func#85 exact for all tested lengths 200..20000:",bad==0)
# same for func#30 to confirm the exact boundary
for n in list(range(204,214)):
    pt=bytes((i*7+3)&0xff for i in range(n))
    g=run(0x38fa4,pt,b''); r=aesref.cbc_enc(pt,b'\x00'*16,b'\x00'*16).hex().encode()
    print("  #30 n=%4d exact=%s"%(n,g==r))
