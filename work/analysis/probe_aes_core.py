"""Identify the 6 AES-table-referencing primitives (#10,#11,#12,#13,#14,#21) and
the two drivers (#15,#16) by emulating them and comparing against FIPS-197."""
import sys, struct, json
sys.path.insert(0,'analysis')
from emu import Emu

F = {i: 0x2dc00 for i in ()}
ADDR = {7:0x2d334, 10:0x2dc00, 11:0x2eb94, 12:0x2fdcc, 13:0x30f18, 14:0x32158,
        15:0x34424, 16:0x35518, 21:0x3712c, 30:0x38fa4, 36:0x3a838,
        85:0x10c470, 94:0x110b70}

PT128 = bytes.fromhex('00112233445566778899aabbccddeeff')
K128  = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
CT128 = bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')   # FIPS-197 C.1
PT256 = bytes.fromhex('00112233445566778899aabbccddeeff')
K256  = bytes(range(32))
CT256 = bytes.fromhex('8ea2b7ca516745bfeafc49904b496089')   # FIPS-197 C.3
PT192 = bytes.fromhex('00112233445566778899aabbccddeeff')
K192  = bytes(range(24))
CT192 = bytes.fromhex('dda97ca4864cdfe06eaf70a0ec0d7191')   # FIPS-197 C.2

def setup(e, key):
    """call func#14 rijndael_setup(skey*, userkey*, unused, keylen) -> skey"""
    skey = e.malloc(0x400); e.wr(skey, b'\x00'*0x400)
    uk   = e.malloc(64);    e.wr(uk, key)
    junk = e.malloc(32);    e.wr(junk, b'\x00'*32)
    e.call(ADDR[14], x0=skey, x1=uk, x2=junk, x3=len(key), timeout=60*1000000)
    return skey

def block(fnid, pt, key, label):
    e = Emu()
    skey = setup(e, key)
    buf  = e.malloc(64); e.wr(buf, pt + b'\x00'*48)
    try:
        e.call(ADDR[fnid], x0=buf, x1=skey, timeout=60*1000000)
    except Exception as ex:
        print('  func#%-3d %-22s CRASH %s' % (fnid, label, ex)); return None
    out = bytes(e.rd(buf, 16))
    return out

print('=== block-level primitives: (buf, skey) ===')
for fnid in (12, 13, 10, 11):
    for klen, key, pt, ct in ((16,K128,PT128,CT128), (24,K192,PT192,CT192), (32,K256,PT256,CT256)):
        out = block(fnid, pt, key, 'AES-%d' % (klen*8))
        if out is None: continue
        tag = []
        if out == ct: tag.append('== FIPS-197 CIPHERTEXT  (ENCRYPT)')
        if out == pt and False: tag.append('identity')
        print('  func#%-3d AES-%d  out=%s   %s' % (fnid, klen*8, out.hex(), ' '.join(tag) or ''))
    # decrypt direction: feed the ciphertext, expect the plaintext back
    for klen, key, pt, ct in ((16,K128,PT128,CT128), (24,K192,PT192,CT192), (32,K256,PT256,CT256)):
        out = block(fnid, ct, key, 'AES-%d rev' % (klen*8))
        if out is None: continue
        if out == pt:
            print('  func#%-3d AES-%d  ct->pt MATCH  (DECRYPT)' % (fnid, klen*8))

print()
print('=== drivers: std::string in / sret out ===')
def sdriver(fnid, pt, key, label):
    e = Emu()
    o = e.malloc(24); e.wr(o, b'\x00'*24)
    try:
        e.call(ADDR[fnid], x0=e.mkstring(pt), x1=e.mkstring(key), x8=o, timeout=300*1000000)
        return e.getstring(o)
    except Exception as ex:
        return 'CRASH %s' % ex
for fnid in (15, 16, 21, 7):
    for pt, key in ((PT128, K128), (b'hello', K128), (CT128.hex().encode(), K128)):
        r = sdriver(fnid, pt, key, '')
        print('  func#%-3d in=%-34r key=%-18r -> %r' % (fnid, pt[:24], key[:16], (r[:80] if isinstance(r,bytes) else r)))
