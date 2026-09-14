import sys;sys.path.insert(0,'analysis')
from emu import Emu
import json,base64
fm=json.load(open('analysis/funcmap.json'))
F157=fm['157']['start'];F158=fm['158']['start'];F156=fm['156']['start']
def go(fn,regs,t=180):
    e=Emu();kw={}
    for k,v in regs.items():
        kw[k]= e.mkstring(v) if isinstance(v,(bytes,str)) else v
    out=e.malloc(128);e.wr(out,b'\x00'*128);kw['x8']=out
    try:
        e.call(fn,**kw,timeout=int(t*1e6))
        return bytes(e.getstring(out)),e.logs
    except Exception as ex: return None,[str(ex)]+e.logs[-6:]
PTS=[b'hello',b'hello world',b'ZZZZZZZZZZZZZZZZ',b'{"a":1}']
print("=== func#157 argument-position sweep ===")
for pt in PTS:
    print(f"\n-- pt={pt!r}")
    for regs in ({'x0':pt},{'x0':pt,'x1':pt},{'x1':pt},{'x0':pt,'x1':b'0123456789abcdef'},
                 {'x0':b'0123456789abcdef','x1':pt},{'x0':pt,'x2':pt},{'x1':pt,'x2':pt},
                 {'x0':pt,'x1':pt,'x2':pt,'x3':pt}):
        o,l=go(F157,regs,t=60)
        tag=','.join(sorted(regs))
        if o is None: print(f"   {tag:22s} EXC {l[0][:50]}");continue
        nz=any(c for c in o)
        print(f"   {tag:22s} -> len={len(o):3d} nonzero={nz} {o[:36]!r}")
print("\n=== func#158 argument-position sweep (pt='hello world') ===")
pt=b'hello world'
for regs in ({'x0':pt},{'x0':pt,'x1':pt},{'x1':pt},{'x0':pt,'x1':b'0123456789abcdef'},{'x1':pt,'x2':pt}):
    o,l=go(F158,regs,t=60)
    tag=','.join(sorted(regs))
    print(f"   {tag:22s} -> {o[:40]!r}" if o is not None else f"   {tag} EXC {l[0][:50]}")
