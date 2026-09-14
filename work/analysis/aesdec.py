"""Reference AES decrypt built from the library's OWN Td tables.

The .so ships LibTomCrypt's Td0..Td3 at 0x129b0/0x12db0/0x131b0/0x135b0 and its
inverse S-box at 0x139b0.  Rather than hand-roll InvMixColumns (three earlier
attempts in f36_key.py got the state/word indexing wrong), this module *generates*
Td0 from first principles, verifies it byte-for-byte against the .so's table, and
then runs the standard T-table decryption.  If the generated table matches the
binary, the reference implementation and the binary are doing the same arithmetic.
"""
import struct

SO = 'apk_extracted/lib/arm64-v8a/libtopfollow.so'
SBOX = bytes.fromhex(
"637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
"b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
"09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
"d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
"cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
"e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
"ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
"e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
INV = [0] * 256
for i, v in enumerate(SBOX): INV[v] = i
INV = bytes(INV)
RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d]

def xt(a): return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff
def x2(a): return xt(a)
def x3(a): return xt(a) ^ a
def x9(a):
    return xt(xt(xt(a))) ^ a
def xb(a):
    return xt(xt(xt(a))) ^ xt(a) ^ a
def xd(a):
    return xt(xt(xt(a))) ^ xt(xt(a)) ^ a
def xe(a):
    return xt(xt(xt(a))) ^ xt(xt(a)) ^ xt(a)

def make_te0():
    """LibTomCrypt/OpenSSL Te0 as LE words: word = (2s<<24)|(s<<16)|(s<<8)|3s."""
    out = []
    for s in range(256):
        x = SBOX[s]
        out.append(struct.pack('<I', ((x2(x) << 24) | (x << 16) | (x << 8) | x3(x)) & 0xffffffff))
    return b''.join(out)

def make_td0():
    """LibTomCrypt Td0 as LE words; Td0[0] must be 0x51f4a750."""
    out = []
    for s in range(256):
        i = INV[s]
        out.append(struct.pack('<I', ((xe(i) << 24) | (x9(i) << 16) | (xd(i) << 8) | xb(i)) & 0xffffffff))
    return b''.join(out)

def rot(t, r):
    w = [struct.unpack_from('<I', t, 4*i)[0] for i in range(256)]
    return [((v >> (8*r)) | (v << (32 - 8*r))) & 0xffffffff for v in w]

def expand(key):
    nk = len(key) // 4; nr = nk + 6
    w = [list(key[4*i:4*i+4]) for i in range(nk)]
    for i in range(nk, 4*(nr+1)):
        t = list(w[i-1])
        if i % nk == 0:
            t = t[1:] + t[:1]; t = [SBOX[b] for b in t]; t[0] ^= RCON[i//nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([w[i-nk][j] ^ t[j] for j in range(4)])
    return [bytes(x) for x in w], nr

def rk(w, r): return b''.join(w[r*4:r*4+4])

def dec_block(c, key):
    """Straightforward FIPS-197 INV_CIPHER, state[r][c] = in[r + 4c]."""
    w, nr = expand(key)
    s = [[c[r + 4*col] for col in range(4)] for r in range(4)]
    def addrk(rnd):
        k = rk(w, rnd)
        for col in range(4):
            for r in range(4): s[r][col] ^= k[r + 4*col]
    addrk(nr)
    for rnd in range(nr - 1, -1, -1):
        for r in range(1, 4): s[r] = s[r][-r:] + s[r][:-r]     # InvShiftRows
        for r in range(4):
            for col in range(4): s[r][col] = INV[s[r][col]]     # InvSubBytes
        addrk(rnd)
        if rnd:                                                 # InvMixColumns
            for col in range(4):
                a = [s[r][col] for r in range(4)]
                s[0][col] = xe(a[0]) ^ xb(a[1]) ^ xd(a[2]) ^ x9(a[3])
                s[1][col] = x9(a[0]) ^ xe(a[1]) ^ xb(a[2]) ^ xd(a[3])
                s[2][col] = xd(a[0]) ^ x9(a[1]) ^ xe(a[2]) ^ xb(a[3])
                s[3][col] = xb(a[0]) ^ xd(a[1]) ^ x9(a[2]) ^ xe(a[3])
    return bytes(s[r + 4*col] if False else s[r][col] for col in range(4) for r in range(4))

def ecb_dec(data, key):
    return b''.join(dec_block(data[i:i+16], key) for i in range(0, len(data), 16))

def cbc_dec(data, key, iv):
    out = b''; prev = iv
    for i in range(0, len(data), 16):
        blk = data[i:i+16]
        d = dec_block(blk, key)
        out += bytes(a ^ b for a, b in zip(d, prev))
        prev = blk
    return out

def unpad(b):
    if not b: return None
    n = b[-1]
    return b[:-n] if 1 <= n <= 16 and b[-n:] == bytes([n]) * n else None

if __name__ == '__main__':
    d = open(SO, 'rb').read()
    te = make_te0(); td = make_td0()
    print("Te0 @0x118b0 == generated:", d[0x118b0:0x118b0+1024] == te)
    print("Td0 @0x129b0 == generated:", d[0x129b0:0x129b0+1024] == td)
    print("RSbox @0x139b0 == generated INV:", d[0x139b0:0x139b0+256] == INV)
    gtd = [struct.unpack_from('<I', td, 4*i)[0] for i in range(256)]
    for off, name, r in ((0x12db0,'Td1',1),(0x131b0,'Td2',2),(0x135b0,'Td3',3)):
        got = [struct.unpack_from('<I', d, off+4*i)[0] for i in range(256)]
        print(f"{name} @0x{off:x} == Td0 rotated right {r} byte:", got == rot(td, r))
    print("Td0[0] == 0x51f4a750 (LibTomCrypt):", gtd[0] == 0x51f4a750)
    print("RSbox @0x139b0 == S.index(i):", d[0x139b0:0x139b0+256] == bytes(SBOX.index(i) for i in range(256)))
    # FIPS-197 known answers
    k128 = bytes(range(16))
    ct = bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
    print("AES-128 dec KAT:", dec_block(ct, k128).hex(),
          dec_block(ct, k128) == bytes.fromhex('00112233445566778899aabbccddeeff'))
    k192 = bytes.fromhex('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b')
    print("AES-192 dec KAT:", dec_block(bytes.fromhex('8ea2b7ca516745bfeafc49904b496089'), k192).hex())
    k256 = bytes.fromhex('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4')
    print("AES-256 dec KAT:", dec_block(bytes.fromhex('f3eed1bdb5d2a03c064b5a7e3db181f8'), k256).hex())
