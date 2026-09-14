import sys;sys.path.insert(0,'analysis')
from emu import Emu
from aesref import ecb,enc_block
import json,hashlib,base64
fm=json.load(open('analysis/funcmap.json'))
raw=open('apk_extracted/lib/arm64-v8a/libtopfollow.so','rb').read()
def call(fn,args=(),regs=None,t=120,x8=True):
    e=Emu();kw={}
    for i,a in enumerate(args): kw[f'x{i}']=e.mkstring(a)
    for k,v in (regs or {}).items(): kw[k]=e.mkstring(v) if isinstance(v,(bytes,str)) else v
    out=e.malloc(256);e.wr(out,b'\x00'*256)
    if x8: kw['x8']=out
    try:
        r=e.call(fn,**kw,timeout=int(t*1e6));return bytes(e.getstring(out)) if x8 else r,e.logs
    except Exception as ex:return f"EXC:{ex}".encode()
F={k:fm[k]['start'] for k in ('86','87','84','88','89','90','54','55','36','85','94','49','81','92','93','95','96','101')}
print("### func#86 / #87 : key getters (blob @0x17307 / 0x16df1)")
for n,args in (('86',()),('87',()),('86',(b'abc',)),('87',(b'abc',))):
    o=call(F[n],args,t=60)
    print(f"  #{n}{args} -> {o[:64]!r}")
print("\n### func#84 (7868B) : called by #54")
for args in ((b'hello',),(b'hello',b'key'),()):
    o=call(F['84'],args,t=90); print(f"  #84{tuple(type(a).__name__ for a in args)} -> {o[:64]!r}")
print("\n### func#88/#89 (called by #84)")
for n in ('88','89'):
    for args in ((b'hello',),(b'hello',b'0123456789abcdef')):
        o=call(F[n],args,t=60);print(f"  #{n} nargs={len(args)} -> {o[:48]!r}")
print("\n### func#92/#93/#95/#96/#101 (called by #67 response path)")
for n in ('92','93','95','96','101'):
    for args in ((b'hello',),(b'hello',b'0123456789abcdef')):
        try: o=call(F[n],args,t=60)
        except Exception as ex: o=str(ex).encode()
        print(f"  #{n} nargs={len(args)} -> {o[:48]!r}")
print("\n### blobs")
for va,n in ((0x17307,32),(0x16df1,32),(0x16c10,16),(0x172d0,61),(0x172f4,19),(0x17290,16),(0x17280,16),(0x17250,16),(0x17240,16),(0x17210,17),(0x172a0,48)):
    r=raw[va:va+n]; x=bytes(c^0x5a for c in r)
    print(f"  0x{va:06x} len={n:2d} raw={r[:24].hex()} xor5a={x[:40]!r}")
