import sys;sys.path.insert(0,'analysis')
from emu import Emu
from aesref import enc_block,ecb,cbc_enc,pkcs7
import json,hashlib,base64
fm=json.load(open('analysis/funcmap.json'))
raw=open('apk_extracted/lib/arm64-v8a/libtopfollow.so','rb').read()
F85=fm['85']['start'];F94=fm['94']['start'];F30=fm['30']['start'];F36=fm['36']['start']
def call(fn,*args,x3=0,x2raw=None):
    e=Emu();regs=[e.mkstring(a) if isinstance(a,(bytes,str)) else a for a in args]
    out=e.malloc(64);e.wr(out,b'\x00'*64)
    kw=dict(x0=regs[0],x1=regs[1] if len(regs)>1 else 0,x2=regs[2] if len(regs)>2 else 0,x3=x3,x8=out)
    e.call(fn,**kw,timeout=180*1000000)
    return bytes(e.getstring(out))
def pstr(va,n=48):
    m=raw[va:va+n].split(b'\x00')[0]; return m
print("=== plaintext strings referenced by func#30 ===")
for va in (0x1606a,0x17123,0x1716e,0x1719e):
    print(f"  0x{va:06x}: plain={pstr(va)!r}  xor5a={bytes(c^0x5a for c in raw[va:va+40]).split(bytes([0x5a]))[0]!r}")
K16=b'0123456789abcdef'
print("\n=== does #30 use a fixed key? test candidates ===")
tgt=call(F30,b'hello',K16); print("  native #30('hello',K16) =",tgt)
tb=bytes.fromhex(tgt.decode())
cands={}
for va,ln in ((0x17123,16),(0x1716e,16),(0x1719e,16),(0x17428,32),(0x17448,16),(0x17458,16),(0x1606a,16)):
    cands[f'plain@0x{va:x}']=pstr(va,ln)
    cands[f'xor5a@0x{va:x}']=bytes(c^0x5a for c in raw[va:va+ln])
cands['b64decode(xor5a@0x17428)']=base64.b64decode(bytes(c^0x5a for c in raw[0x17428:0x17448]))
cands['zeros16']=b'\x00'*16
cands['K16']=K16
cands['md5(K16)']=hashlib.md5(K16).digest()
cands['sha256(K16)[:16]']=hashlib.sha256(K16).digest()[:16]
for n,k in cands.items():
    if len(k) not in (16,24,32): k=(k+b'\x00'*32)[:16]
    for mode,o in (('ECB',ecb(b'hello',k)),('CBC0',cbc_enc(b'hello',k,b'\x00'*16))):
        if o==tb: print(f"  *** MATCH #30 = {mode} key={n} = {k!r}")
print("\n=== is #36 the inverse of #30? ===")
for pt in (b'hello',b'A'*32,b'test123'):
    a=call(F30,pt,K16)
    b=call(F36,a,K16)
    print(f"  pt={pt!r:12s} #30->{a.decode()[:40]} #36->{b!r}  {'OK' if b==pt else 'no'}")
print("\n=== does #30 depend on its key arg at all? ===")
for k in (K16,b'XXXXXXXXXXXXXXXX',b'A'*16,b'Z'*24):
    print(f"  key={k!r:22s} #30('hello')->{call(F30,b'hello',k)!r}")
print("\n=== #30 vs #85 on same input, key varied ===")
for k in (K16,b'A'*16):
    print(f"  key={k!r}: #85={call(F85,b'hello',k).decode()}  #30={call(F30,b'hello',k).decode()}")
