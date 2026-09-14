import sys;sys.path.insert(0,'analysis')
from emu import Emu
from aesref import ecb,cbc_enc,pkcs7,enc_block
import json,hashlib,base64
fm=json.load(open('analysis/funcmap.json'))
raw=open('apk_extracted/lib/arm64-v8a/libtopfollow.so','rb').read()
def call(fn,args,regs=None,t=180):
    e=Emu();kw={}
    for i,a in enumerate(args): kw[f'x{i}']=e.mkstring(a)
    for k,v in (regs or {}).items(): kw[k]=e.mkstring(v) if isinstance(v,(bytes,str)) else v
    out=e.malloc(128);e.wr(out,b'\x00'*128);kw['x8']=out
    try:
        e.call(fn,**kw,timeout=int(t*1e6)); return bytes(e.getstring(out))
    except Exception as ex: return f"EXC:{ex}".encode()
F={k:fm[k]['start'] for k in ('30','36','85','94','157','158','159','160','161','26','28','156')}
Z16=b'\x00'*16
print("### 1. func#30 = AES-128-CBC(key=0,iv=0)+hex  -- exhaustive mode proof")
for pt in (b'A',b'A'*15,b'A'*16,b'A'*17,b'A'*31,b'A'*32,b'A'*48):
    o=call(F['30'],[pt,b'ignoredkey'])
    if o.startswith(b'EXC') or o==b'null': print(f"  len={len(pt):2d} -> {o!r}");continue
    nb=bytes.fromhex(o.decode())
    ecbm=nb==ecb(pt,Z16); cbcm=nb==cbc_enc(pt,Z16,Z16)
    print(f"  len={len(pt):2d} ctlen={len(nb):2d} ECB={ecbm} CBC/iv0={cbcm}  {'=> CBC' if cbcm and not ecbm else ''}")
print("\n### 2. func#36 -- feed it AES-128-CBC(0,0) hex of a known plaintext")
for pt in (b'hello',b'A'*16,b'topfollow'):
    h=cbc_enc(pt,Z16,Z16).hex().encode()
    o=call(F['36'],[h,b'k'])
    print(f"  #36(cbc_hex({pt!r})) = {o!r}   {'*** EXACT INVERSE ***' if o==pt else ''}")
    o2=call(F['36'],[h])
    print(f"  #36(cbc_hex, 1 arg)  = {o2!r}")
print("\n### 3. func#85 / #94 round-trip with real key lengths")
for K in (b'0123456789abcdef',b'0123456789abcdef01234567',b'0123456789abcdef0123456789abcdef'):
    for pt in (b'hello',b'A'*32,b'{"pk":123,"sig":"x"}'):
        c=call(F['85'],[pt,K]); b=call(F['94'],[c,K])
        exp=ecb(pt,K).hex().encode()
        print(f"  key{len(K)*8:4d} pt={pt!r:22s} ct==AES-ECB:{c==exp} rt_ok:{b==pt}")
print("\n### 4. constant getters #159/#160/#161 (arg-independent)")
for n in ('159','160','161'):
    vals={call(F[n],[a]) for a in (b'',b'x',b'hello world',b'A'*64)}
    for v in vals:
        try: dec=base64.b64decode(v)
        except Exception: dec=b''
        print(f"  #{n} -> {v!r}  b64->{dec.hex()} ({len(dec)} bytes)")
print("\n### 5. func#26 base64 alphabet @0x1501a")
print("  raw:",raw[0x1501a:0x1501a+66])
print("\n### 6. decoded key material (func#193 = XOR 0x5A, verified by emulation)")
for va,n,lab in ((0x17428,32,'KEY  (func#157)'),(0x17448,16,'IV   (func#157)'),
                 (0x17458,16,'IV2  (func#158)'),(0x17307,32,'func#86 blob'),
                 (0x17317,16,'func#54/#55 blob'),(0x17240,16,'func#224 blob')):
    s=bytes(c^0x5a for c in raw[va:va+n])
    extra=''
    try:
        dd=base64.b64decode(s); extra=f"  b64->{dd.hex()} ({len(dd)}B)"
    except Exception: pass
    print(f"  0x{va:06x} {lab:18s} = {s!r}{extra}")
