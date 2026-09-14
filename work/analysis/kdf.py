import sys;sys.path.insert(0,'analysis')
from emu import Emu
from aesref import enc_block,ecb,cbc_enc,pkcs7,SBOX
import json,hashlib,base64,itertools
fm=json.load(open('analysis/funcmap.json'))
raw=open('apk_extracted/lib/arm64-v8a/libtopfollow.so','rb').read()
F85=fm['85']['start'];F94=fm['94']['start'];F30=fm['30']['start']
def call(fn,*args,x3=0):
    e=Emu();regs=[e.mkstring(a) for a in args]
    out=e.malloc(64);e.wr(out,b'\x00'*64)
    kw=dict(x0=regs[0],x1=regs[1] if len(regs)>1 else 0,x2=regs[2] if len(regs)>2 else 0,x3=x3,x8=out)
    e.call(fn,**kw,timeout=180*1000000)
    return bytes(e.getstring(out))
KEY=b'0123456789abcdef'; PT=b'hello'
tgthex=call(F85,PT,KEY); tgt=bytes.fromhex(tgthex.decode())
print("native #85(pt,key) =",tgt.hex())
print("native #30(pt,key) =",call(F30,PT,KEY))
print()
cands={}
def add(n,v):
    if len(v) in (16,24,32): cands[n]=v
add('raw16',KEY)
add('md5(key)',hashlib.md5(KEY).digest())
add('sha1(key)[:16]',hashlib.sha1(KEY).digest()[:16])
add('sha256(key)[:16]',hashlib.sha256(KEY).digest()[:16])
add('sha256(key)',hashlib.sha256(KEY).digest())
add('sha1(key)[:24]',hashlib.sha1(KEY).digest()[:24])
add('key+key',KEY+KEY)
add('md5(key)+md5(key)',hashlib.md5(KEY).digest()*2)
add('md5(key).hex()[:16]',hashlib.md5(KEY).hexdigest()[:16].encode())
add('sha256(key).hex()[:32]',hashlib.sha256(KEY).hexdigest()[:32].encode())
add('sha256(key).hex()',hashlib.sha256(KEY).hexdigest().encode())
add('md5(md5(key))',hashlib.md5(hashlib.md5(KEY).digest()).digest())
add('md5(key.hex)',hashlib.md5(KEY.hex().encode()).digest())
add('sha256(key.hex())[:16]',hashlib.sha256(KEY.hex().encode()).digest()[:16])
add('key padded 0',KEY)
add('sha1(key)',hashlib.sha1(KEY).digest()+b'\x00'*12)
print("=== ECB / CBC(zero IV) match test ===")
found=[]
for name,k in cands.items():
    for mode,fn in (('ECB',lambda p,kk:ecb(p,kk)),
                    ('CBC-iv0',lambda p,kk:cbc_enc(p,kk,b'\x00'*16)),
                    ('ECB-raw-nopad',lambda p,kk:enc_block(pkcs7(p)[:16],kk)),
                    ('CBC-iv=key[:16]',lambda p,kk:cbc_enc(p,kk,kk[:16]))):
        try: o=fn(PT,k)
        except Exception: continue
        if o==tgt or o[:16]==tgt[:16]:
            print(f"  *** MATCH: {name} + {mode} -> {o.hex()}"); found.append((name,mode))
print("  matches:",found if found else "NONE")
print()
print("=== Is the FIRST native block stable across key? derive K from a single block ===")
# brute force: assume AES-128-ECB, recover key by testing structured keys
tests={b'A'*16:b'A'*16, b'0'*16:b'0'*16}
for k in tests:
    print(f"  key={k!r} -> {call(F85,PT,k).decode()}")
print()
print("=== check whether output = AES-ECB(K) with K = md5/sha of key CONCATENATED with something in .rodata ===")
# common .rodata 16-byte constants referenced by #85: 0x16c10 -> "exposed" area. try salts
salts=[b'', b'\x00'*16, raw[0x16c10:0x16c20]]
for salt in salts:
    for h in ('md5','sha1','sha256'):
        k=hashlib.new(h,KEY+salt).digest()
        for kk in (k[:16],k[:24],k[:32]):
            if ecb(PT,kk)==tgt: print(f"  *** MATCH {h}(key+{salt.hex()[:16]}) [{len(kk)*8}]")
print("done")
