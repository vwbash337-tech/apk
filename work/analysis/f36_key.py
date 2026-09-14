"""func#36: the key is DERIVED FROM THE INPUT, not fixed.

keyrec36b.py hooked func#14 (rijndael_setup) during a func#36 call and found
keylen=32 with the user-key buffer = 23 zero bytes, 0x20, then the first 8 bytes of
the hex-decoded input.  Every earlier "fixed internal key" hypothesis therefore had
to fail.  This script maps the derivation over input lengths and proves the cipher.
"""
import sys, json, struct
sys.path.insert(0, 'analysis')
from keyrec36b import Probe, run, F36, F14
from aesref import SBOX, pkcs7

# ---- reference AES decrypt (ECB, single block) ---------------------------------
def gmul(a, b):
    r = 0
    for _ in range(8):
        if b & 1: r ^= a
        hi = a & 0x80; a = (a << 1) & 0xff
        if hi: a ^= 0x1b
        b >>= 1
    return r
def expand(key):
    nk = len(key)//4; nr = nk+6
    w = [list(key[4*i:4*i+4]) for i in range(nk)]
    RC = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d]
    for i in range(nk, 4*(nr+1)):
        t = list(w[i-1])
        if i % nk == 0:
            t = t[1:]+t[:1]; t = [SBOX[b] for b in t]; t[0] ^= RC[i//nk-1]
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([w[i-nk][j]^t[j] for j in range(4)])
    return w, nr
INV = [0]*256
for i, v in enumerate(SBOX): INV[v] = i
def dec_block(c, key):
    w, nr = expand(key)
    def rk(r): return bytes(sum(w[r*4:r*4+4], []))
    def xt(a): return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff
    def x9(a): return gmul(a, 0x09)
    def xb(a): return gmul(a, 0x0b)
    def xd(a): return gmul(a, 0x0d)
    def xe(a): return gmul(a, 0x0e)
    # flat state: st[4*col + row] == state[row][col] == input[row + 4*col]
    st = [c[i] for i in range(16)]
    def addrk(k):
        b = rk(k)
        return [st[i] ^ b[i] for i in range(16)]
    def invshift(v):
        return [v[4*((col + row) % 4) + row] for col in range(4) for row in range(4)]
    def invmix(v):
        t = list(v)
        for col in range(4):
            a = v[4*col:4*col+4]
            t[4*col+0] = xe(a[0]) ^ xb(a[1]) ^ xd(a[2]) ^ x9(a[3])
            t[4*col+1] = x9(a[0]) ^ xe(a[1]) ^ xb(a[2]) ^ xd(a[3])
            t[4*col+2] = xd(a[0]) ^ x9(a[1]) ^ xe(a[2]) ^ xb(a[3])
            t[4*col+3] = xb(a[0]) ^ xd(a[1]) ^ x9(a[2]) ^ xe(a[3])
        return t
    def invsub(v): return [INV[b] for b in v]
    def xork(st, k):
        b = rk(k)
        return [st[i] ^ b[i] for i in range(16)]
    st = xork(list(c), nr)
    for rnd in range(nr, 0, -1):          # FIPS-197 CIPHER: rnd = Nr-1 step -1 downto 0
        k = rnd - 1
        st = invshift(st)
        st = invsub(st)
        st = xork(st, k)
        if k: st = invmix(st)             # InvMixColumns skipped on the last round (k==0)
    return bytes(st)

def ecb_dec(data, key):
    return b''.join(dec_block(data[i:i+16], key) for i in range(0, len(data), 16))

def unpad(b):
    if not b: return None
    n = b[-1]
    return b[:-n] if 1 <= n <= 16 and b[-n:] == bytes([n])*n else None

# ---- probe --------------------------------------------------------------------
def probe(hexin, keyarg=b'k'):
    p, res, err = run(F36, [hexin, keyarg])
    ks = [h for h in p.hits if h['fn'] == 'KEYSETUP#14']
    keys = []
    for h in ks:
        kl = h['x3'] & 0xff
        keys.append((kl, h['x1_ctx'][16:16+kl]))
    return res, err, keys, p

if __name__ == '__main__':
    cases = {
      16: b'9834ed518cbc8fbe9af3c6ecb75eb8c0',
      32: b'00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
      48: bytes(range(24)).hex().encode(),
      64: bytes(range(32)).hex().encode(),
    }
    for n, hx in cases.items():
        raw = bytes.fromhex(hx.decode())
        res, err, keys, p = probe(hx)
        print(f"\n### input {n} hex chars = {len(raw)} raw bytes")
        print(f"    raw    : {raw.hex()}")
        print(f"    out    : {res.hex()}  ({len(res)} B)  err={err}")
        for kl, kb in keys:
            print(f"    KEYSETUP keylen={kl} key={kb.hex()}")
            if kl in (16,24,32) and len(raw) >= 16:
                pt = ecb_dec(raw, kb)
                print(f"    ref AES-{kl*8}-ECB-dec(raw, key) = {pt.hex()}")
                print(f"    PKCS#7 unpad -> {unpad(pt)!r}")
                print(f"    == emulated output? {unpad(pt) == res if res else 'n/a'}")
    # does the 2nd arg matter?
    print("\n### 2nd-arg sensitivity (input = 16 raw bytes)")
    hx = cases[16]
    for ka in (b'k', b'key', b'0123456789abcdef', b'', b'A'*40):
        res, err, keys, p = probe(hx, ka)
        print(f"    arg2={ka!r:24s} -> out={res.hex()} keys={[(k[0],k[1].hex()[-20:]) for k in keys]} err={err}")
