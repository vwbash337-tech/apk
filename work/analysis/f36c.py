import sys;sys.path.insert(0,'analysis')
from emu import Emu
from aesref import SBOX,enc_block
import json,hashlib
fm=json.load(open('analysis/funcmap.json'))
inv=[0]*256
for i,v in enumerate(SBOX): inv[v]=i
INV=bytes(inv)
def gmul(a,b):
    r=0
    for _ in range(8):
        if b&1:r^=a
        hi=a&0x80;a=(a<<1)&0xff
        if hi:a^=0x1b
        b>>=1
    return r
RCON=[0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]
def expand(key):
    nk=len(key)//4;nr=nk+6
    w=[list(key[4*i:4*i+4]) for i in range(nk)]
    for i in range(nk,4*(nr+1)):
        t=list(w[i-1])
        if i%nk==0: t=t[1:]+t[:1];t=[SBOX[b] for b in t];t[0]^=RCON[i//nk-1]
        elif nk>6 and i%nk==4: t=[SBOX[b] for b in t]
        w.append([w[i-nk][j]^t[j] for j in range(4)])
    return w,nr
def dec_block(c,key):
    w,nr=expand(key)
    s=[[c[r+4*i] for i in range(4)] for r in range(4)]
    def addrk(r):
        for cc in range(4):
            for rr in range(4): s[rr][cc]^=w[r*4+cc][rr]
    addrk(nr)
    for rnd in range(nr-1,-1,-1):
        for r in range(1,4): s[r]=s[r][-r:]+s[r][:-r]
        for r in range(4):
            for cc in range(4): s[r][cc]=INV[s[r][cc]]
        addrk(rnd)
        if rnd:
            for cc in range(4):
                a=[s[r][cc] for r in range(4)]
                s[0][cc]=gmul(a[0],14)^gmul(a[1],11)^gmul(a[2],13)^gmul(a[3],9)
                s[1][cc]=gmul(a[0],9)^gmul(a[1],14)^gmul(a[2],11)^gmul(a[3],13)
                s[2][cc]=gmul(a[0],13)^gmul(a[1],9)^gmul(a[2],14)^gmul(a[3],11)
                s[3][cc]=gmul(a[0],11)^gmul(a[1],13)^gmul(a[2],9)^gmul(a[3],14)
    return bytes(s[r][cc] for cc in range(4) for r in range(4))
def call(fn,args,t=120):
    e=Emu();kw={f'x{i}':e.mkstring(a) for i,a in enumerate(args)}
    out=e.malloc(512);e.wr(out,b'\x00'*512);kw['x8']=out
    try:
        e.call(fn,**kw,timeout=int(t*1e6));return bytes(e.getstring(out))
    except Exception as ex:return f"EXC:{ex}".encode()
F36=fm['36']['start'];F30=fm['30']['start']
Z=b'\0'*16
print("### DEFINITIVE: is #36 = hex-decode -> AES-128-ECB-decrypt(key=0) -> strip trailing NULs ?")
ok=True
for K in (Z, b'0123456789abcdef', hashlib.md5(b'topfollow').digest()):
    for pt in (b'hello',b'A'*16,b'topfollow-secret',b'\x01\x02\x03\x04\x05\x06\x07\x08'):
        p=pk=(pt+bytes([16-len(pt)%16])*(16-len(pt)%16)) if len(pt)%16 else pt+bytes([16])*16
        ct=b''.join(enc_block(p[i:i+16],K) for i in range(0,len(p),16))
        h=ct.hex().encode()
        o=call(F36,[h,b'whatever'])
        exp_ecb_zero=b''.join(dec_block(ct[i:i+16],Z) for i in range(0,len(ct),16))
        exp_ecb_K=b''.join(dec_block(ct[i:i+16],K) for i in range(0,len(ct),16))
        m0 = o==exp_ecb_zero.rstrip(b'\x00') or o==exp_ecb_zero
        mK = o==exp_ecb_K.rstrip(b'\x00') or o==exp_ecb_K
        print(f"  K={K.hex()[:16]:16s} pt={pt!r:20s} ctlen={len(ct):2d} outlen={len(o):2d} match_zero_key_ECB={m0} match_K_ECB={mK}")
        print(f"      out        = {o.hex()}")
        print(f"      ECBdec(K=0)= {exp_ecb_zero.hex()}")
        if K!=Z: print(f"      ECBdec(K)  = {exp_ecb_K.hex()}")
    print()
