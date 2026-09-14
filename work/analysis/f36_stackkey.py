"""func#36: prove the AES key comes from an UNINITIALISED stack buffer.

Three experiments:
  1. determinism  -- same input, same emulator build, run twice;
  2. stack control -- pre-fill the stack region func#36 uses with a marker pattern
     and see whether the marker becomes the AES key (i.e. whether the key buffer is
     ever written before rijndael_setup consumes it);
  3. key recovery -- derive the effective key from the produced round-key schedule
     by brute-forcing the 32 bytes that reproduce rk0..rk1.
"""
import sys, json, struct
sys.path.insert(0, 'analysis')
from keyrec36b import Probe, run, F36
from aesdec import ecb_dec, unpad, expand, SBOX
from aesref import enc_block

DATA = bytes((0xa0 + i) % 256 for i in range(32))
HEXIN = DATA.hex().encode()

def schedule_at(p, addr, n=512):
    return bytes(p.rd(addr, n))

def first_keysetup(p):
    for h in p.hits:
        if h['fn'] == 'KEYSETUP#14': return h
    return None

print("### 1. determinism (same input, three independent emulator instances)")
outs = []
for i in range(3):
    p, res, err = run(F36, [HEXIN, b'k'])
    h = first_keysetup(p)
    sk = schedule_at(p, h['x0']) if h else b''
    outs.append(res)
    print(f"   run{i}: out={res.hex()}")
    if h: print(f"          skey@0x{h['x0']:x} [0:64]={sk[:64].hex()}")
print("   identical:", all(o == outs[0] for o in outs))

print("\n### 2. does pre-filling the stack change the key?")
base = []
p0, r0, e0 = run(F36, [HEXIN, b'k'])
base.append(r0)
MARK_A = bytes((0xC0 + i) % 256 for i in range(0x200))
MARK_B = bytes((0x11 * (i % 7)) % 256 for i in range(0x200))
for tag, mark in (('A', MARK_A), ('B', MARK_B)):
    class P2(Probe):
        pass
    p = P2()
    # func#36's frame lives just below SP; SP is set to STACK+STACK_SZ-0x10000.
    sp = 0x8000000 + 0x200000 - 0x10000
    p.wr(sp - 0x400, mark * 4)
    out = p.malloc(1024); p.wr(out, b'\x00' * 1024)
    x0 = p.mkstring(HEXIN); x1 = p.mkstring(b'k')
    err = None
    try:
        p.call(F36, x0=x0, x1=x1, x8=out, timeout=int(240e6))
        res = bytes(p.getstring(out))
    except Exception as ex:
        res = b''; err = str(ex)
    h = first_keysetup(p)
    print(f"   mark {tag}: out={res.hex()}  same-as-baseline={res == base[0]}  keyptr=0x{h['x1']:x}" if h else f"   mark {tag}: out={res.hex()} no keysetup")
    if h:
        around = bytes(p.rd(h['x1'] - 32, 96))
        print(f"            bytes around keyptr: {around.hex()}")
        print(f"            contains mark A? {MARK_A[:16] in around}   mark B? {MARK_B[:16] in around}")

print("\n### 3. recover the effective key from the schedule")
p, res, err = run(F36, [HEXIN, b'k'])
h = first_keysetup(p)
sk = schedule_at(p, h['x0'], 1024)
# find a 16-byte window that is a plausible rk0: expanding it (as AES-128) must
# reproduce the following rows if the schedule is stored contiguously.
found = None
for off in range(0, len(sk) - 176, 4):
    cand = sk[off:off+16]
    w, nr = expand(cand)
    want = b''.join(w[:11])
    if want == sk[off:off+176]:
        found = (off, cand, 128); break
if found:
    print(f"   AES-128 schedule found at struct+0x{found[0]:x}, key = {found[1].hex()}")
else:
    # AES-256: rk0||rk1 = key.  Search for a 32-byte window whose AES-256
    # expansion reproduces the next rows.
    for off in range(0, len(sk) - 240, 4):
        cand = sk[off:off+32]
        w, nr = expand(cand)
        want = b''.join(w[:15])
        if want == sk[off:off+240]:
            found = (off, cand, 256); break
    if found:
        print(f"   AES-256 schedule found at struct+0x{found[0]:x}, key = {found[1].hex()}")
    else:
        print("   no contiguous schedule located; dumping candidate windows")
        for off in range(0, 160, 16):
            print(f"     +0x{off:02x}: {sk[off:off+16].hex()}")
if found:
    off, key, bits = found
    pt = ecb_dec(DATA, key)
    print(f"   AES-{bits}-ECB-dec(input, recovered key) = {pt.hex()}")
    print(f"   emulated func#36 output                  = {res.hex()}")
    print(f"   MATCH: {pt == res}")
    print(f"   unpad(pt) = {unpad(pt)!r}")
