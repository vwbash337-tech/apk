import sys;sys.path.insert(0,'analysis')
from emu import Emu
import struct,json,hashlib,base64,itertools
fm=json.load(open('analysis/funcmap.json'))
raw=open('apk_extracted/lib/arm64-v8a/libtopfollow.so','rb').read()
print("=== .rodata 0x16c10 (16 bytes memcpy'd twice inside func#85) ===")
print("  raw:",raw[0x16c10:0x16c30].hex(' '))
print("  ascii:",''.join(chr(c) if 32<=c<127 else '.' for c in raw[0x16c10:0x16c30]))
print("  xor5a:",bytes(c^0x5a for c in raw[0x16c10:0x16c20]).hex(' '))
print("  as str xor5a:",bytes(c^0x5a for c in raw[0x16c10:0x16c20]))

def call(fn,pt,key,x2=0,x3=0):
    e=Emu(); s=e.mkstring(pt); k=e.mkstring(key); out=e.malloc(64); e.wr(out,b'\x00'*64)
    e.call(fn,x0=s,x1=k,x2=x2,x3=x3,x8=out,timeout=120*1000000)
    return bytes(e.getstring(out)),e.logs

F85=fm['85']['start'];F94=fm['94']['start'];F30=fm['30']['start'];F36=fm['36']['start']
print("\n=== func#85 behaviour matrix ===")
for pt,key,x2 in ((b'hello',b'0123456789abcdef',0),
                  (b'hello',b'XXXXXXXXXXXXXXXX',0),
                  (b'hello',b'',0),
                  (b'hello',b'0123456789abcdef',1),
                  (b'hello',b'0123456789abcdef',2),
                  (b'hellohellohelloh',b'0123456789abcdef',0),
                  (b'AAAAAAAAAAAAAAAA',b'0123456789abcdef',0),
                  (b'',b'0123456789abcdef',0),
                  (b'A',b'0123456789abcdef',0)):
    try:
        o,l=call(F85,pt,key,x2)
        print(f"  pt={pt!r:22s} key={key!r:22s} x2={x2} -> {o!r}")
    except Exception as ex: print(f"  pt={pt!r} x2={x2} FAIL {ex}")
print("\n=== func#94 (decrypt?) on func#85 output ===")
ct,_=call(F85,b'hello',b'0123456789abcdef',0)
for inp in (ct, bytes.fromhex(ct.decode()) if all(c in b'0123456789abcdef' for c in ct) else ct):
    try:
        o,l=call(F94,inp,b'0123456789abcdef',0); print(f"  #94({inp!r}) -> {o!r}")
    except Exception as ex: print(f"  #94({inp!r}) FAIL {ex}")
print("\n=== func#30 / func#36 ===")
for pt in (b'hello',b'{"a":1}'):
    try:
        o,l=call(F30,pt,b'0123456789abcdef',0); print(f"  #30({pt!r}) -> {o!r}")
    except Exception as ex: print(f"  #30({pt!r}) FAIL {ex}")
    try:
        o,l=call(F36,pt,b'0123456789abcdef',0); print(f"  #36({pt!r}) -> {o!r}")
    except Exception as ex: print(f"  #36({pt!r}) FAIL {ex}")
