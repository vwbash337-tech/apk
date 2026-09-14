SBOX=bytes.fromhex(
"637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
"b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
"09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
"d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
"cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
"e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
"ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
"e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
RCON=[0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d]
def xt(a): return ((a<<1)^0x1b)&0xff if a&0x80 else (a<<1)
def expand(key):
    nk=len(key)//4;nr=nk+6
    w=[list(key[4*i:4*i+4]) for i in range(nk)]
    for i in range(nk,4*(nr+1)):
        t=list(w[i-1])
        if i%nk==0:
            t=t[1:]+t[:1];t=[SBOX[b] for b in t];t[0]^=RCON[i//nk-1]
        elif nk>6 and i%nk==4: t=[SBOX[b] for b in t]
        w.append([w[i-nk][j]^t[j] for j in range(4)])
    return w,nr
def enc_block(pt,key):
    w,nr=expand(key)
    s=[[pt[r+4*c] for c in range(4)] for r in range(4)]
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
    n=16-len(b)%16;return b+bytes([n])*n
def ecb(pt,key): 
    p=pkcs7(pt);return b''.join(enc_block(p[i:i+16],key) for i in range(0,len(p),16))
def cbc_enc(pt,key,iv):
    p=pkcs7(pt);prev=iv;out=b''
    for i in range(0,len(p),16):
        blk=bytes(a^b for a,b in zip(p[i:i+16],prev));out+=enc_block(blk,key);prev=out[-16:]
    return out
if __name__=='__main__':
    print("FIPS-197 vector:",enc_block(bytes.fromhex('00112233445566778899aabbccddeeff'),bytes(range(16))).hex())
    print("expected       : 69c4e0d86a7b0430d8cdb78070b4c55a")
    print("AES-256 vector:",enc_block(bytes.fromhex('00112233445566778899aabbccddeeff'),bytes(range(32))).hex())
    print("expected       : 8ea2b7ca516745bfeafc49904b496089")
