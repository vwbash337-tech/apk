import sys;sys.path.insert(0,'analysis')
from emu import Emu
from aesref import SBOX
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
def cbc_dec(ct,key,iv):
    out=b'';prev=iv
    for i in range(0,len(ct),16):
        blk=ct[i:i+16];d=dec_block(blk,key)
        out+=bytes(a^b for a,b in zip(d,prev));prev=blk
    return out
def call(fn,args,t=120):
    e=Emu();kw={f'x{i}':e.mkstring(a) for i,a in enumerate(args)}
    out=e.malloc(256);e.wr(out,b'\x00'*256);kw['x8']=out
    try:
        e.call(fn,**kw,timeout=int(t*1e6));return bytes(e.getstring(out))
    except Exception as ex:return f"EXC:{ex}".encode()
F36=fm['36']['start']
pt=b'hello'
from aesref import cbc_enc
ct=cbc_enc(pt,b'\0'*16,b'\0'*16)
h=ct.hex().encode()
o=call(F36,[h,b'k'])
print("native #36(hex) =",o.hex(),len(o))
print("ct              =",ct.hex())
# try many candidate fixed keys with ECB and CBC, compare first 8 bytes
cands={
 'zeros':b'\0'*16,
 'K16':b'0123456789abcdef',
 'b64KEY(24)':bytes.fromhex('02df752315674526c5a695745313457544a7a654d6e4e340'),
 'b64KEY[:16]':bytes.fromhex('02df752315674526c5a695745313457544a7a654d6e4e340')[:16],
 'asciiKEY32':b'At91IxVnRSbFppV0UxNFdUSnplTW5ONA',
 'asciiIV16' :b'WMVEwVG02eGFlVmR',
 'asciiIV2'  :b'M0VEwVGt0aVJuQjF',
 'md5(K16)':hashlib.md5(b'0123456789abcdef').digest(),
 'sha256(K16)[:16]':hashlib.sha256(b'0123456789abcdef').digest()[:16],
 'md5("")':hashlib.md5(b'').digest(),
 'sha256("")[:16]':hashlib.sha256(b'').digest()[:16],
 'md5("topfollow")':hashlib.md5(b'topfollow').digest(),
 'md5("instagram")':hashlib.md5(b'instagram').digest(),
}
for n,k in cands.items():
    kk=k if len(k) in (16,24,32) else (k+b'\0'*32)[:16]
    for mode,f in (('ECB',lambda c,K:b''.join(dec_block(c[i:i+16],K) for i in range(0,len(c),16))),
                   ('CBC0',lambda c,K:cbc_dec(c,K,b'\0'*16)),
                   ('CBC-iv=ct[:0]',lambda c,K:cbc_dec(c,K,K[:16]))):
        try: dd=f(ct,kk)
        except Exception: continue
        if dd[:8]==o or dd[:len(o)]==o: print(f"  *** MATCH #36 = AES-{mode}-decrypt key={n}={kk!r} -> {dd.hex()}")
else: print("  no match among candidates")
print("\n=== #36 length behaviour ===")
for L in (16,32,48,64):
    hh=('41'*L)
    r=call(F36,[hh.encode(),b'k'])
    print(f"  input hexlen={len(hh)} (={L} bytes) -> out {len(r)} bytes: {r[:24].hex()}")
