import sys;sys.path.insert(0,'analysis')
from emu import Emu
from aesref import enc_block,ecb,cbc_enc,pkcs7
import json,hashlib
fm=json.load(open('analysis/funcmap.json'))
F85=fm['85']['start'];F94=fm['94']['start'];F30=fm['30']['start'];F36=fm['36']['start']
def call(fn,*args,x3=0):
    e=Emu();regs=[e.mkstring(a) for a in args]
    out=e.malloc(64);e.wr(out,b'\x00'*64)
    kw=dict(x0=regs[0],x1=regs[1] if len(regs)>1 else 0,x2=regs[2] if len(regs)>2 else 0,x3=x3,x8=out)
    e.call(fn,**kw,timeout=180*1000000)
    return bytes(e.getstring(out))
K16=b'0123456789abcdef';K24=b'0123456789abcdef01234567';K32=b'0123456789abcdef0123456789abcdef'
tests=[b'hello', b'0123456789abcde', b'0123456789abcdef', b'A'*31, b'A'*32, b'A'*33,
       b'{"user":"abc","pass":"defghijklmnopqrstuvwxyz"}']
print("=== func#85 mode determination ===")
for pt in tests:
    nat=call(F85,pt,K16)
    if nat==b'null': print(f"  pt={pt!r} -> null");continue
    nb=bytes.fromhex(nat.decode())
    e=ecb(pt,K16); c=cbc_enc(pt,K16,b'\x00'*16)
    m='ECB' if nb==e else ('CBC/iv=0' if nb==c else 'OTHER')
    print(f"  len={len(pt):3d} pt={pt[:24]!r:28s} -> {m:9s} ct={nb.hex()[:48]}...")
print()
print("=== func#85 with AES-192 / AES-256 keys ===")
for K,lab in ((K24,'AES-192'),(K32,'AES-256')):
    for pt in (b'hello',b'A'*32):
        nat=call(F85,pt,K);nb=bytes.fromhex(nat.decode())
        e=ecb(pt,K);c=cbc_enc(pt,K,b'\x00'*16)
        print(f"  {lab} len={len(pt):2d} -> {'ECB' if nb==e else ('CBC/iv0' if nb==c else 'OTHER '+nb.hex())}")
print()
print("=== func#94 = decrypt inverse? ===")
for pt in (b'hello',b'A'*32,b'{"a":1,"b":[2,3]}'):
    ct=call(F85,pt,K16)
    back=call(F94,ct,K16)
    print(f"  pt={pt!r:24s} ct={ct.decode()[:40]}... -> #94 -> {back!r}   {'OK' if back==pt else 'MISMATCH'}")
print()
print("=== func#30 / func#36 (small AES pair) ===")
for pt in (b'hello',b'A'*32):
    a=call(F30,pt,K16); print(f"  #30({pt!r}) = {a!r}")
    for cand in (a, a+a):
        try:
            b=call(F36,cand,K16); print(f"     #36({cand!r}) = {b!r}")
        except Exception as ex: print(f"     #36 FAIL {ex}")
    e=ecb(pt,K16)
    print(f"     ECB(pt,K16)={e.hex()}  match={a==e.hex().encode()}")
