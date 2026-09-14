"""func#36 SOLVED: it is a *self-keying* AES-256-ECB decrypt with a PKCS#7 oracle.

Method
------
func#14 @0x32158 is LibTomCrypt's rijndael_setup (it is the only function in the
library that references setup_Sbox @0x128b0 and setup_rc @0x13b10, and it is called
by func#30, func#36, func#85 and func#94).  Hooking its entry tells us *when* a key
schedule is built, but x1 there is a pointer into the caller's stack frame and is
ambiguous.  The unambiguous evidence is the schedule ITSELF: round key 0 of AES is
verbatim the first 16 bytes of the user key, and for AES-256 the first 32 bytes of
the struct are the whole key.  So we read rk0 back out of the symmetric_key struct
after the call and compare it with the input.

Result
------
    data    = hexdecode(arg0)                       (arg1 is ignored completely)
    if len(data) % 16 or len(data) == 0: return data unchanged
    key     = data[:32]                             (self-keying)
    plain   = AES-256-ECB-decrypt(data, key)
    if PKCS#7 valid: return unpad(plain) else return plain
"""
import sys, json, struct
sys.path.insert(0, 'analysis')
from keyrec36b import Probe, run, F36
from aesdec import ecb_dec, unpad, expand, SBOX

def rk0_from_struct(p, skey_addr):
    b = bytes(p.rd(skey_addr, 64))
    return b

def model(data):
    if not data or len(data) % 16: return data, None
    if len(data) < 32:
        return None, None                      # observed separately below
    key = data[:32]
    pt = ecb_dec(data, key)
    u = unpad(pt)
    return (u if u is not None else pt), key

print("### A. hexdecode gate")
for bad in (b'hello', b'ZZ'*16, bytes(range(16)), b'00112233445566778899aabbccdeefgg'):
    p, res, err = run(F36, [bad, b'k'])
    ks = [h for h in p.hits if h['fn'] == 'KEYSETUP#14']
    print(f"   in={bad!r:38s} -> out={res[:24]!r} ({len(res)}B) keysetup={len(ks)}")

print("\n### B. self-keying model, len(data) >= 32 and % 16 == 0")
ok = 0; tot = 0
for n in (32, 48, 64, 80, 96, 128):
    for trial in range(3):
        data = bytes((0xa0 + 7*trial + i) % 256 for i in range(n))
        p, res, err = run(F36, [data.hex().encode(), b'k'])
        exp, key = model(data)
        tot += 1; hit = (exp == res); ok += hit
        if trial == 0 or not hit:
            print(f"   n={n:3d} trial={trial} out={len(res):3d}B  model={len(exp) if exp is not None else '-'}B  MATCH={hit}")
        if trial == 0 and key is not None:
            h = [x for x in p.hits if x['fn'] == 'KEYSETUP#14']
            if h:
                sk = bytes(p.rd(h[0]['x0'], 64))
                print(f"        key(model) = {key.hex()}")
                print(f"        skey[0:32] = {sk[:32].hex()}   keylen(x3)={h[0]['x3']&0xff}")
                w, nr = expand(key)
                print(f"        rk0(model) = {b''.join(w[:4]).hex()}   nr={nr}")
                print(f"        rk0 appears in skey struct: {b''.join(w[:4]).hex() in sk.hex()}")
print(f"   --> {ok}/{tot} exact matches")

print("\n### C. the PKCS#7 oracle: build a valid ciphertext and watch it unpad")
from aesref import enc_block
for n in (32, 48):
    pt = b'{"order_id":12345}'[:n-32] or b'{"order_id":12345}'
    m = len(pt) % 16; pt_pad = pt + (bytes([16-m])*(16-m) if m else bytes([16])*16)
    key = bytes((0x11*i+n) % 256 for i in range(32))
    ct = b''.join(enc_block(pt_pad[i:i+16], key) for i in range(0, len(pt_pad), 16))
    data = key + ct
    p, res, err = run(F36, [data.hex().encode(), b'ignored'])
    print(f"   plaintext  = {pt!r}")
    print(f"   key        = {key.hex()}")
    print(f"   data(key+ct)= {data.hex()}")
    print(f"   func#36 out = {res!r}")
    print(f"   == plaintext? {res == pt}")

print("\n### D. len(data) < 32 and % 16 == 0")
for n in (16,):
    data = bytes((0xa0+i) % 256 for i in range(n))
    p, res, err = run(F36, [data.hex().encode(), b'k'])
    h = [x for x in p.hits if x['fn'] == 'KEYSETUP#14']
    sk = bytes(p.rd(h[0]['x0'], 64)) if h else b''
    w, nr = expand(b'\x00'*16)
    print(f"   n=16 out={res.hex()}")
    print(f"   rk0(zero AES-128) = {b''.join(w[:4]).hex()}   present in skey struct: {b''.join(w[:4]).hex() in sk.hex()}")
    z16 = bytes(16)
    print(f"   AES-128-ECB-dec(data, 0^16) = {ecb_dec(data, z16).hex()}   == out? {ecb_dec(data, z16) == res}")
