import sys;sys.path.insert(0,'analysis')
from emu import Emu
import struct,json,hashlib,base64
fm=json.load(open('analysis/funcmap.json'))
e=Emu()
F85=fm['85']['start']; F94=fm['94']['start']; F30=fm['30']['start']; F36=fm['36']['start']
def try_call(fn,pt,key,x2=0,label=''):
    e2=Emu()
    s=e2.mkstring(pt); k=e2.mkstring(key); out=e2.malloc(64)
    e2.wr(out,b'\x00'*64)
    try:
        r=e2.call(fn,x0=s,x1=k,x2=x2,x8=out,timeout=120*1000000)
        ob=bytes(e2.getstring(out))
        print(f"[{label}] fn=0x{fn:x} pt={pt!r} key={key!r} x2={x2}")
        print(f"   -> out({len(ob)}B) hex={ob.hex()}")
        print(f"   -> out ascii={''.join(chr(c) if 32<=c<127 else '.' for c in ob)!r}")
        print(f"   x0=0x{r:x}")
        try:
            print(f"   b64decode(out)={base64.b64decode(ob).hex()}")
        except Exception: pass
        print(f"   last 12 shim logs: {e2.logs[-12:]}")
        return ob
    except Exception as ex:
        print(f"[{label}] FAILED {ex}")
        print(f"   logs tail: {e2.logs[-25:]}")
        return None
try_call(F85,b'hello',b'0123456789abcdef',0,'func#85 key16')
