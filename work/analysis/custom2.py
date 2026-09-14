import sys;sys.path.insert(0,'analysis')
from emu import Emu
from aesref import ecb,cbc_enc,pkcs7,enc_block
import json,hashlib,base64
fm=json.load(open('analysis/funcmap.json'))
raw=open('apk_extracted/lib/arm64-v8a/libtopfollow.so','rb').read()
K=0x5a
def call(fn,x0=None,x1=None,x2=None,x3=None,x8=None,t=240,mkstr=(0,)):
    e=Emu()
    kw={}
    for i,v in enumerate((x0,x1,x2,x3)):
        if v is None: continue
        kw[f'x{i}']= e.mkstring(v) if i in mkstr else v
    out=e.malloc(96); e.wr(out,b'\x00'*96)
    kw['x8']= x8 if x8 is not None else out
    try:
        r=e.call(fn,**kw,timeout=int(t*1e6))
        return bytes(e.getstring(out)), out, e, r
    except Exception as ex:
        return None,out,e,str(ex)
F193=fm['193']['start'];F157=fm['157']['start'];F158=fm['158']['start']
F85=fm['85']['start'];F94=fm['94']['start'];F156=fm['156']['start']
print("=== func#193 sanity: decode(0x17428 blob) ===")
o,out,e,r=call(F193,x0=0x17428,x8=None,mkstr=())
print("  raw x8 string ->",bytes(e.getstring(out))[:40], " x0 ret=0x%x"%r if isinstance(r,int) else r)
print("  expected       -> At91IxVnRSbFppV0UxNFdUSnplTW5ONA")
print()
print("=== func#157 ENCRYPT  (x0=std::string* plaintext, x8=std::string* out) ===")
for pt in (b'hello',b'hello world',b'A'*16,b'A'*32,b'{"user":"a","pass":"b"}',b'\x00\x01\x02\x03'):
    o,out,e,r=call(F157,x0=pt,t=180)
    print(f"  pt={pt!r:26s} -> len={len(o) if o else -1:3d} raw={o!r}")
    if o:
        try:
            b=base64.b64decode(o+b'='*((4-len(o)%4)%4))
            print(f"      b64-decoded ({len(b)}B): {b.hex()}")
        except Exception as ex: print("      b64 fail",ex)
        print(f"      hex-ish: {o.hex()}")
print()
print("=== func#158 DECRYPT on func#157 output ===")
o,_,_,_=call(F157,x0=b'hello world',t=180)
print("  #157('hello world') =",o)
d,_,_,_=call(F158,x0=o,t=180)
print("  #158(that)          =",d)
d2,_,_,_=call(F158,x0=b'hello world',t=180)
print("  #158('hello world') =",d2)
