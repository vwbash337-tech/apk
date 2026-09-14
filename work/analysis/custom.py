import sys;sys.path.insert(0,'analysis')
from emu import Emu
from aesref import ecb,cbc_enc,pkcs7,enc_block
import json,hashlib,base64
fm=json.load(open('analysis/funcmap.json'))
raw=open('apk_extracted/lib/arm64-v8a/libtopfollow.so','rb').read()
F={'30':fm['30']['start'],'36':fm['36']['start'],'85':fm['85']['start'],'94':fm['94']['start'],
   '156':fm['156']['start'],'157':fm['157']['start'],'158':fm['158']['start'],'159':fm['159']['start'],
   '160':fm['160']['start'],'161':fm['161']['start']}
def callX(fn,args,x8=True,t=180):
    e=Emu();regs=[e.mkstring(a) for a in args]
    out=e.malloc(80);e.wr(out,b'\x00'*80)
    kw={f'x{i}':r for i,r in enumerate(regs)}
    if x8: kw['x8']=out
    try:
        e.call(fn,**kw,timeout=int(t*1e6))
        ob=bytes(e.getstring(out)) if x8 else b''
        rawb=bytes(e.rd(out,24))
        return ob,rawb,e.logs
    except Exception as ex: return None,None,[str(ex)]+e.logs[-8:]
K16=b'0123456789abcdef'
print("=== #30 mode test (16/32-byte pt, zero key) ===")
for pt in (b'hello',b'A'*15,b'A'*16,b'A'*31,b'A'*32,b'A'*33):
    o,_,_=callX(F['30'],[pt,K16])
    if o and o!=b'null':
        nb=bytes.fromhex(o.decode())
        m='ECB' if nb==ecb(pt,b'\x00'*16) else ('CBC/iv0' if nb==cbc_enc(pt,b'\x00'*16,b'\x00'*16) else 'OTHER')
        print(f"  len={len(pt):2d} -> {m:8s} {o.decode()[:64]}")
print("\n=== #30 vs #36 inverse (both zero-key) ===")
for pt in (b'hello',b'A'*16,b'A'*32):
    a,_,_=callX(F['30'],[pt,K16]); b,_,_=callX(F['36'],[a,K16])
    print(f"  pt={pt!r:20s} #30={a.decode()[:36]}... #36={b!r}")
print("\n=== custom-cipher family probes (#156..#161) ===")
for nm in ('156','157','158','159','160','161'):
    for args in ([b'hello'],[b'hello',K16],[b'hello',K16,K16],[b'hello world'],[b'hello world',K16]):
        o,rawb,l=callX(F[nm],args,t=60)
        if o is None: print(f"  #{nm} args={len(args)} EXC {l[0][:60]}"); continue
        nz=any(c for c in o)
        print(f"  #{nm} nargs={len(args)} -> len={len(o):3d} nz={nz} {o[:40]!r}")
    print()
