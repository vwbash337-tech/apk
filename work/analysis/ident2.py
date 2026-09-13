import sys;sys.path.insert(0,'analysis')
from emu import Emu
import json,hashlib,base64,itertools
fm=json.load(open('analysis/funcmap.json'))
F85=fm['85']['start'];F94=fm['94']['start'];F30=fm['30']['start'];F36=fm['36']['start']
def call(fn,*args,x8=True,x3=0):
    e=Emu()
    regs=[]
    for a in args:
        regs.append(e.mkstring(a) if isinstance(a,(bytes,str)) else a)
    out=e.malloc(64); e.wr(out,b'\x00'*64)
    kw=dict(x0=regs[0] if regs else 0,x1=regs[1] if len(regs)>1 else 0,x2=regs[2] if len(regs)>2 else 0,x3=x3)
    if x8: kw['x8']=out
    e.call(fn,**kw,timeout=180*1000000)
    return bytes(e.getstring(out)) if x8 else bytes(e.rd(out,64))

# ---- reference AES (pure python, no deps) ----
SBOX=[];INV=[]
def _init():
    p=1;q=1;sbox=[0]*256
    while True:
        p=p^((p<<1)&0xff)^(0x1b if p&0x80 else 0)
        q^=q<<1;q^=q<<2;q^=q<<4;q&=0xff
        if q&0x80: q^=0x09
        x=q^((q<<1)|(q>>7))^((q<<2)|(q>>6))^((q<<3)|(q>>5))^((q<<4)|(q>>4))
        sbox[p]=x&0xff
        if p==1: break
    sbox[0]=0x63
    globals()['SBOX']=sbox
_init()
RCON=[0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d]
def xt(a): return ((a<<1)^0x1b)&0xff if a&0x80 else a<<1
def expand(key):
    nk=len(key)//4; nr=nk+6
    w=[list(key[4*i:4*i+4]) for i in range(nk)]
    for i in range(nk,4*(nr+1)):
        t=list(w[i-1])
        if i%nk==0:
            t=t[1:]+t[:1]; t=[SBOX[b] for b in t]; t[0]^=RCON[i//nk-1]
        elif nk>6 and i%nk==4: t=[SBOX[b] for b in t]
        w.append([w[i-nk][j]^t[j] for j in range(4)])
    return w,nr
def aes_enc_block(pt,key):
    w,nr=expand(key)
    s=[list(pt[i::4]) for i in range(4)]  # column-major
    def addrk(rnd):
        for c in range(4):
            for r in range(4): s[r][c]^=w[rnd*4+c][r]
    addrk(0)
    for rnd in range(1,nr+1):
        for r in range(4):
            for c in range(4): s[r][c]=SBOX[s[r][c]]
        for r in range(1,4): s[r]=s[r][r:]+s[r][:r]
        if rnd!=nr:
            for c in range(4):
                a=[s[r][c] for r in range(4)]
                s[0][c]=xt(a[0])^(xt(a[1])^a[1])^a[2]^a[3]
                s[1][c]=a[0]^xt(a[1])^(xt(a[2])^a[2])^a[3]
                s[2][c]=a[0]^a[1]^xt(a[2])^(xt(a[3])^a[3])
                s[3][c]=(xt(a[0])^a[0])^a[1]^a[2]^xt(a[3])
        addrk(rnd)
    return bytes(s[r][c] for c in range(4) for r in range(4))
def pkcs7(b):
    n=16-len(b)%16; return b+bytes([n])*n
def ecb_enc(pt,key):
    p=pkcs7(pt); return b''.join(aes_enc_block(p[i:i+16],key) for i in range(0,len(p),16))

KEY=b'0123456789abcdef'
ct,_=call(F85,b'hello',KEY),None
ct=call(F85,b'hello',KEY)
print("native  #85('hello',key) =",ct)
print()
print("=== candidate key derivations vs native ciphertext ===")
cands={
 'raw key (16B) AES-128':KEY,
 'MD5(key)':hashlib.md5(KEY).digest(),
 'SHA1(key)[:16]':hashlib.sha1(KEY).digest()[:16],
 'SHA256(key)[:16]':hashlib.sha256(KEY).digest()[:16],
}
tgt=bytes.fromhex(ct.decode())
for name,k in cands.items():
    o=ecb_enc(b'hello',k)
    print(f"  {name:24s} -> {o.hex()}   {'*** MATCH ***' if o==tgt else ''}")
print()
print("=== verify my AES impl with FIPS-197 vector ===")
print("  AES-128 ECB(00112233445566778899aabbccddeeff, key=000102...0f) =",
      aes_enc_block(bytes.fromhex('00112233445566778899aabbccddeeff'),bytes(range(16))).hex())
print("  expected                                              = 69c4e0d86a7b0430d8cdb78070b4c55a")
print()
print("=== longer key strings (AES-192/256) ===")
for K in (b'0123456789abcdef01234567', b'0123456789abcdef0123456789abcdef', b'0123456789abcde'):
    try:
        o=call(F85,b'hello',K); print(f"  keylen={len(K):2d} -> {o!r}")
    except Exception as ex: print(f"  keylen={len(K)} FAIL {ex}")
