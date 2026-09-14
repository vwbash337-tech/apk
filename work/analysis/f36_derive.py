"""func#36: map the key derivation and prove the cipher.

Hooks func#14 (LibTomCrypt rijndael_setup) inside a func#36 call and reads the user
key out of x1 with x3 = keylen.  Then checks the hypothesis
    out = PKCS7-unpad( AES-<bits>-ECB-decrypt( hexdecode(in), K(in) ) )
against the emulated output, using the reference decryptor in aesdec.py (which is
itself validated against the .so's own Te0/Td0 tables).
"""
import sys, json
sys.path.insert(0, 'analysis')
from keyrec36b import Probe, run, F36
from aesdec import dec_block, ecb_dec, unpad, INV

def probe(hexin, keyarg=b'k'):
    p, res, err = run(F36, [hexin, keyarg])
    ks = [h for h in p.hits if h['fn'] == 'KEYSETUP#14']
    keys = []
    for h in ks:
        kl = h['x3'] & 0xff
        keys.append((kl, h['x1_buf'][:kl], h['x1_kind']))
    return res, err, keys

CASES = []
for n in (8, 16, 24, 32, 48, 64):
    raw = bytes((0xa0 + i) % 256 for i in range(n))
    CASES.append((n, raw))

print("### derivation of the key from the input")
for n, raw in CASES:
    hx = raw.hex().encode()
    res, err, keys = probe(hx)
    print(f"\n-- in = {n} raw bytes ({2*n} hex chars): {raw.hex()}")
    print(f"   out = {res.hex()}  ({len(res)} B)   err={err}")
    if not keys:
        print("   no KEYSETUP call -> func#36 bailed before reaching the cipher")
        continue
    for kl, kb, kind in keys:
        print(f"   KEYSETUP: keylen={kl} ({kind})")
        print(f"             key = {kb.hex()}")
        nz = kb[:len(kb)-8] if len(kb) >= 8 else kb
        print(f"             key[:-8] all zero? {set(nz) == {0}}    key[-8:] == in[:8]? {kb[-8:] == raw[:8]}")
        if kl in (16, 24, 32) and len(raw) >= 16 and len(raw) % 16 == 0:
            pt = ecb_dec(raw, kb)
            print(f"             AES-{kl*8}-ECB-dec(in, key) = {pt.hex()}")
            print(f"             unpad -> {unpad(pt)!r}   == emulated out? {unpad(pt) == res}")

print("\n### does the 2nd argument influence the key?")
raw = bytes((0xa0 + i) % 256 for i in range(16)); hx = raw.hex().encode()
for ka in (b'k', b'key', b'', b'0123456789abcdef', b'A'*40, bytes(range(16))):
    res, err, keys = probe(hx, ka)
    ks = [(k[0], k[1].hex()) for k in keys]
    print(f"   arg2={ka!r:22s} out={res.hex():20s} keys={ks} err={err}")

print("\n### non-hex input (does the hex decode gate everything?)")
for bad in (b'hello', b'ZZZZ'*8, bytes(range(16)), b'00112233445566778899aabbccdeefgg'):
    res, err, keys = probe(bad)
    print(f"   in={bad!r:40s} -> out={res[:32]!r} ({len(res)}B) keysetup={len(keys)} err={err}")
