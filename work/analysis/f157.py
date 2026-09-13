import sys;sys.path.insert(0,'analysis')
from emu import Emu
from aesref import enc_block,ecb,cbc_enc,pkcs7
import json,hashlib,base64
fm=json.load(open('analysis/funcmap.json'))
raw=open('apk_extracted/lib/arm64-v8a/libtopfollow.so','rb').read()
K=0x5a
KEYB64=bytes(c^K for c in raw[0x17428:0x17448]).decode()
IVB64 =bytes(c^K for c in raw[0x17448:0x17458]).decode()
IV2B64=bytes(c^K for c in raw[0x17458:0x17468]).decode()
print("KEY b64 str:",KEYB64,"->",base64.b64decode(KEYB64).hex(),len(base64.b64decode(KEYB64)),"B")
print("IV  b64 str:",IVB64,"->",base64.b64decode(IVB64).hex(),len(base64.b64decode(IVB64)),"B")
print("IV2 b64 str:",IV2B64,"->",base64.b64decode(IV2B64).hex(),len(base64.b64decode(IV2B64)),"B")

def callX(fn,nstr,x8=True,extra=(),timeout=300):
    e=Emu();regs=[e.mkstring(a) for a in nstr]
    out=e.malloc(64);e.wr(out,b'\x00'*64)
    kw={}
    for i,r in enumerate(regs): kw[f'x{i}']=r
    for k2,v in extra: kw[k2]=v
    if x8: kw['x8']=out
    try:
        e.call(fn,**kw,timeout=int(timeout*1e6))
        return (bytes(e.getstring(out)) if x8 else None), e.logs
    except Exception as ex:
        return None, [f"EXC {ex}"]+e.logs[-20:]
F157=fm['157']['start'];F158=fm['158']['start'];F156=fm['156']['start'];F85=fm['85']['start'];F94=fm['94']['start']
print("\n=== func#157 arg-count probe ===")
for n in range(0,4):
    args=[b'hello world']+[b'x'*16]*(n-1) if n>=1 else []
    o,l=callX(F157,args,timeout=60)
    print(f"  nargs={n} -> {o!r}   logs={len(l)} tail={l[-4:]}")
print("\n=== func#158 arg-count probe ===")
for n in range(1,4):
    args=[b'hello world']+[b'x'*16]*(n-1)
    o,l=callX(F158,args,timeout=60)
    print(f"  nargs={n} -> {o!r}   tail={l[-4:]}")
