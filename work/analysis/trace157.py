import sys;sys.path.insert(0,'analysis')
from emu import Emu
from unicorn import *
from unicorn.arm64_const import *
import json,struct
fm=json.load(open('analysis/funcmap.json'))
F157=fm['157']['start']
e=Emu()
pt=e.mkstring(b'hello world')
out=e.malloc(128); e.wr(out,b'\x00'*128)
print(f"pt object @0x{pt:x} -> {bytes(e.rd(pt,24)).hex(' ')}")
print(f"out      @0x{out:x}")
print(f"heap brk after allocs = 0x{e.brk:x}")
reads=[]
def hook(mu,acc,addr,sz,val,ud):
    if addr>=HEAP and addr<HEAP+HEAP_SZ:
        pc=mu.reg_read(UC_ARM64_REG_PC)
        reads.append((pc,addr,sz,'W' if acc&UC_MEM_WRITE else 'R'))
HEAP=0x10000000;HEAP_SZ=0x400000
e.mu.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,hook)
e.call(F157,x0=pt,x8=out,timeout=int(120e6))
print(f"\ntotal heap accesses: {len(reads)}")
# group by address
from collections import Counter,defaultdict
byaddr=defaultdict(list)
for pc,a,sz,k in reads: byaddr[a].append((pc,sz,k))
print("distinct heap addresses touched:",len(byaddr))
for a in sorted(byaddr)[:40]:
    lst=byaddr[a]
    print(f"  0x{a:08x} n={len(lst):3d} first_pc=0x{lst[0][0]:x} kinds={set(k for _,_,k in lst)} content={bytes(e.rd(a,8)).hex()}")
