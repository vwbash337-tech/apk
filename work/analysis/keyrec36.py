"""Recover func#36's internal AES key by hooking the key-schedule setup (func#14 @0x32158).

func#14 is LibTomCrypt's rijndael_setup, CFF-flattened: its prologue does the
obfuscated keylen check (w3/w4 in {16,24,32}) and it is the ONLY function in the
library that references setup_Sbox @0x128b0 and setup_rc @0x13b10.  It is called by
func#30, func#36, func#85 and func#94 -- i.e. every cipher goes through it.
Hooking it therefore yields the *user key bytes verbatim* (x1) for any cipher call.
"""
import sys, json, struct
sys.path.insert(0, 'analysis')
from emu import Emu
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *
from aesref import expand, enc_block, pkcs7

fm = json.load(open('analysis/funcmap.json'))
F14 = fm['14']['start']; F36 = fm['36']['start']; F30 = fm['30']['start']
F85 = fm['85']['start']; F94 = fm['94']['start']
NAME = {F14: 'KEYSETUP#14', F85: 'ECB_ENC#85', F94: 'ECB_DEC#94', F36: 'F36', F30: 'CBC0#30'}

INV = [0] * 256
SBOX = None

class Probe(Emu):
    def __init__(self):
        super().__init__()
        self.hits = []
        self.mu.hook_add(UC_HOOK_CODE, self._watch)
    def _watch(self, mu, addr, sz, ud):
        if addr not in NAME: return
        x = lambda r: mu.reg_read(r)
        rec = {'fn': NAME[addr], 'x0': x(UC_ARM64_REG_X0), 'x1': x(UC_ARM64_REG_X1),
               'x2': x(UC_ARM64_REG_X2), 'x3': x(UC_ARM64_REG_X3), 'x4': x(UC_ARM64_REG_X4)}
        for k in ('x1', 'x2'):
            try: rec[k + '_bytes'] = bytes(self.rd(rec[k], 32))
            except Exception: rec[k + '_bytes'] = b''
        self.hits.append(rec)

def run(fn, args, t=180):
    p = Probe()
    kw = {f'x{i}': p.mkstring(a) for i, a in enumerate(args)}
    out = p.malloc(512); p.wr(out, b'\x00' * 512); kw['x8'] = out
    try:
        p.call(fn, **kw, timeout=int(t * 1e6))
        res = bytes(p.getstring(out))
    except Exception as ex:
        res = b'EXC:' + str(ex).encode()
    return p, res

def show(tag, args):
    p, res = run(F36, args)
    print(f"\n===== {tag} =====")
    print(f"  in  : {args}")
    print(f"  out : {res[:80]!r}{'...' if len(res)>80 else ''}  ({len(res)} B)")
    ks = [h for h in p.hits if h['fn'] == 'KEYSETUP#14']
    print(f"  KEYSETUP#14 calls: {len(ks)}   ECB_ENC#85: {sum(1 for h in p.hits if h['fn']=='ECB_ENC#85')}"
          f"   ECB_DEC#94: {sum(1 for h in p.hits if h['fn']=='ECB_DEC#94')}")
    seen = set()
    for h in ks:
        klen = h['x3'] & 0xff
        kb = h['x1_bytes'][:klen] if klen in (16, 24, 32) else h['x1_bytes']
        key = kb.hex()
        if key in seen: continue
        seen.add(key)
        print(f"    userkey @0x{h['x1']:x} len={klen}  skey @0x{h['x0']:x}  ->  {key}")
        if klen in (16, 24, 32):
            try:
                w, nr = expand(kb)
                print(f"      expands to {nr} rounds; rk0 = {bytes(w[0]+w[1]+w[2]+w[3]).hex()}")
            except Exception as ex:
                print(f"      expand failed: {ex}")
        print(f"      ascii: {kb!r}")
    return p, res, ks

if __name__ == '__main__':
    show('A: #36(hex-of-CBC(hello)) ', [enc_block.__module__ and b'6b1d1c7b7f4a1a1e'.hex().encode()])
    show('B: #36(b"hello")          ', [b'hello'])
    show('C: #36(32 hex chars)      ', [b'00112233445566778899aabbccddeeff'])
    show('D: #36(16 raw bytes)      ', [bytes(range(16))])
