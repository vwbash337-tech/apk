import sys;sys.path.insert(0,'analysis')
from emu import Emu
import json
fm=json.load(open('analysis/funcmap.json'))
F193=fm['193']['start']
def run(src_va,n):
    e=Emu(); out=e.malloc(96); e.wr(out,b'\x00'*96)
    r=e.call(F193,x0=src_va,x1=n,x8=out,timeout=int(60e6))
    return bytes(e.getstring(out)), r, e.logs
for va,n,lab in ((0x17428,32,'KEY'),(0x17448,16,'IV'),(0x17458,16,'IV2'),(0x17307,32,'func#86 blob'),(0x17240,16,'func#224')):
    o,r,l=run(va,n)
    print(f"  {lab:14s} @0x{va:x} n={n} -> str={o!r}  ret=0x{r:x}  calls={len(l)}")
print()
print("=== func#193 called with x1 = 0 / omitted ===")
for va,n in ((0x17428,0),(0x17428,1)):
    o,r,l=run(va,n); print(f"  @0x{va:x} n={n} -> {o!r}")
