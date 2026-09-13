import sys;sys.path.insert(0,'analysis')
from emu import Emu
from aesref import ecb,cbc_enc,pkcs7,enc_block
import json,hashlib,base64,itertools
fm=json.load(open('analysis/funcmap.json'))
def call(fn,args,t=120):
    e=Emu();kw={f'x{i}':e.mkstring(a) for i,a in enumerate(args)}
    out=e.malloc(256);e.wr(out,b'\x00'*256);kw['x8']=out
    try:
        e.call(fn,**kw,timeout=int(t*1e6));return bytes(e.getstring(out))
    except Exception as ex:return f"EXC:{ex}".encode()
F36=fm['36']['start'];F30=fm['30']['start'];F94=fm['94']['start'];F85=fm['85']['start']
print("### func#36 input-format sensitivity")
tests={
 'cbc_hex(hello)':cbc_enc(b'hello',b'\0'*16,b'\0'*16).hex().encode(),
 'cbc_HEX_UPPER' :cbc_enc(b'hello',b'\0'*16,b'\0'*16).hex().upper().encode(),
 'ecb_hex(hello,K16)':ecb(b'hello',b'0123456789abcdef').encode() if False else ecb(b'hello',b'0123456789abcdef').hex().encode(),
 'b64(cbc(hello))':base64.b64encode(cbc_enc(b'hello',b'\0'*16,b'\0'*16)),
 'raw cbc bytes'  :cbc_enc(b'hello',b'\0'*16,b'\0'*16),
 'plain hello'    :b'hello',
}
for k,v in tests.items():
    print(f"  {k:22s} ({len(v):3d}B) -> {call(F36,[v,b'k'])!r}")
print("\n### is #36 output = AES-ECB-decrypt(cbc_ct, K) for some K? try K=zeros / K16")
ct=cbc_enc(b'hello',b'\0'*16,b'\0'*16)
o=call(F36,[ct.hex().encode(),b'k'])
print("  #36 out:",o.hex(),len(o),"B")
# AES-128-ECB decrypt reference
INV_SBOX=bytes([0]*256)
from aesref import SBOX
inv=[0]*256
for i,v in enumerate(SBOX): inv[v]=i
INV=bytes(inv)
def inv_xt(a):
    # multiply by 0x0e etc via GF
    return a
def gmul(a,b):
    r=0
    for _ in range(8):
        if b&1: r^=a
        hi=a&0x80; a=(a<<1)&0xff
        if hi: a^=0x1b
        b>>=1
    return r
def expand(key):
    nk=len(key)//4;nr=nk+6
    w=[list(key[4*i:4*i+4]) for i in range(nk)]
    RCON=[0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]
    for i in range(nk,4*(nr+1)):
        t=list(w[i-1])
        if i%nk==0:
            t=t[1:]+t[:1];t=[SBOX[b] for b in t];t[0]^=RCON[i//nk-1]
        elif nk>6 and i%nk==4: t=[SBOX[b] for b in t]
        w.append([w[i-nk][j]^t[j] for j in range(4)])
    return w,nr
def dec_block(c,key):
    w,nr=expand(key)
    s=[[c[r+4*i] for i in range(4)] for r in range(4)]
    def addrk(rnd):
        for cc in range(4):
            for r in range(4): s[r][cc]^=w[rnd*4+cc][r]
    addrk(nr)
    for rnd in range(nr-1,-1,-1):
        for r in range(1,4): s[r]=s[r][-r:]+s[r][:-r]
        for r in range(4):
            for cc in range(4): s[r][cc]=INV[s[r][cc]]
        addrk(rnd)
        if rnd!=0:
            for cc in range(4):
                a=[s[r][cc] for r in range(4)]
                s[0][cc]=gmul(a[0],14)^gmul(a[1],11)^gmul(a[2],13)^gmul(a[3],9)
                s[1][cc]=gmul(a[0],9)^gmul(a[1],14)^gmul(a[2],11)^gmul(a[3],13)
                s[2][cc]=gmul(a[0],13)^gmul(a[1],9)^gmul(a[2],14)^gmul(a[3],11)
                s[3][cc]=gmul(a[0],11)^gmul(a[1],13)^gmul(a[2],9)^gmul(a[3],14)
    return bytes(s[r][cc] for cc in range(4) for r in range(4))
for K,lab in ((b'\0'*16,'zeros'),(b'0123456789abcdef','K16')):
    d=b''.join(dec_block(ct[i:i+16],K) for i in range(0,len(ct),16))
    print(f"  AES-ECB-decrypt(ct,{lab}) = {d.hex()}  match={d[:len(o)]==o}")
print("\n### does #36 depend on its key arg?")
for k in (b'k',b'0123456789abcdef',b'X'*16,b''):
    print(f"  key={k!r:20s} -> {call(F36,[tests['cbc_hex(hello)'],k])!r}")
print("\n### #36 twice / nested")
o1=call(F36,[tests['cbc_hex(hello)'],b'k'])
print("  #36(#36(x)) =",call(F36,[o1,b'k'])[:32])
print("  #30(#36(x)) =",call(F30,[o1,b'k'])[:64])
