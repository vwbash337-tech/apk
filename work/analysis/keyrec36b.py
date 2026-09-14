"""func#36 key recovery, take 2.

Differences from keyrec36.py:
 * two string args (data, key) exactly like the previously-working f36.py harness;
 * unmapped READS are satisfied by mapping the page on demand, so the run completes
   instead of aborting mid-way (the abort was masking the real key);
 * every func#14 (rijndael_setup) call is recorded, and the resulting round-key
   schedule is validated against FIPS-197 so the recovered user key is *proven*,
   not just observed.
"""
import sys, json, struct
sys.path.insert(0, 'analysis')
import emu as EMU
from emu import Emu
from unicorn import UC_HOOK_CODE, UC_MEM_READ_UNMAPPED, UC_MEM_WRITE_UNMAPPED, UC_MEM_FETCH_UNMAPPED
from unicorn.arm64_const import *
from aesref import expand

fm = json.load(open('analysis/funcmap.json'))
F14 = fm['14']['start']; F36 = fm['36']['start']; F85 = fm['85']['start']; F94 = fm['94']['start']
NAME = {F14: 'KEYSETUP#14', F85: 'ECB_ENC#85', F94: 'ECB_DEC#94'}

class Probe(Emu):
    def __init__(self):
        super().__init__()
        self.hits = []
        self.autopages = 0
        self.mu.hook_add(UC_HOOK_CODE, self._watch)
        # NOTE: Emu.__init__ already registers UC_HOOK_MEM_UNMAPPED (all access
        # types) and maps the faulting page on demand, so unmapped reads no longer
        # abort the run.  Unicorn 2.1.4 rejects the per-type mem hooks with
        # UC_ERR_ARG, so do not add them here.
        self._base_unmapped = self._unmapped
        self._unmapped = self._count_unmapped
    def _count_unmapped(self, mu, acc, addr, sz, val):
        self.autopages += 1
        return self._base_unmapped(mu, acc, addr, sz, val)
    def _watch(self, mu, addr, sz, ud):
        if addr not in NAME: return
        x = lambda r: mu.reg_read(r)
        rec = {'fn': NAME[addr], 'x0': x(UC_ARM64_REG_X0), 'x1': x(UC_ARM64_REG_X1),
               'x2': x(UC_ARM64_REG_X2), 'x3': x(UC_ARM64_REG_X3), 'x4': x(UC_ARM64_REG_X4)}
        # x1 may be a libc++ std::string OBJECT (long form) rather than a raw
        # buffer; resolve it so long keys are read from the heap buffer, not from
        # the struct's cap/size fields.
        try:
            raw1 = bytes(self.rd(rec['x1'], 24))
            if raw1 and (raw1[0] & 1):
                cap, size, dptr = struct.unpack('<QQQ', raw1)
                rec['x1_kind'] = 'std::string(long)'
                rec['x1_size'] = size
                rec['x1_buf'] = bytes(self.rd(dptr, min(size, 64)))
            else:
                rec['x1_kind'] = 'raw/inline'
                rec['x1_size'] = None
                rec['x1_buf'] = bytes(self.rd(rec['x1'], 64))
        except Exception:
            rec['x1_kind'] = '?'; rec['x1_buf'] = b''
        try: rec['x1_ctx'] = bytes(self.rd(rec['x1'] - 16, 96))
        except Exception: rec['x1_ctx'] = b''
        try: rec['rk'] = bytes(self.rd(rec['x0'], 256))
        except Exception: rec['rk'] = b''
        self.hits.append(rec)

def runsched(key):
    w, nr = expand(key)
    return nr, [bytes(sum(w[r * 4:r * 4 + 4], [])) for r in range(nr + 1)]

def check(skey_mem, key):
    """skey_mem = bytes of the symmetric_key struct. LTC AES: {data:{Nr, ek[4][4], dk[4][4]}}."""
    nr, rows = runsched(key)
    try:
        n = struct.unpack_from('<i', skey_mem, 0)[0]
    except Exception:
        return None
    if n != nr: return None
    got = skey_mem[0xc:0xc + 16 * (nr + 1)]
    want = b''.join(rows)
    return (got == want), got.hex(), want.hex()

def run(fn, args, t=240):
    p = Probe()
    kw = {f'x{i}': p.mkstring(a) for i, a in enumerate(args)}
    out = p.malloc(1024); p.wr(out, b'\x00' * 1024); kw['x8'] = out
    err = None
    try:
        p.call(fn, **kw, timeout=int(t * 1e6))
        res = bytes(p.getstring(out))
    except Exception as ex:
        res = b''; err = str(ex)
    return p, res, err

def report(tag, args):
    p, res, err = run(F36, args)
    print(f"\n===== {tag} =====")
    print(f"  args: {args}")
    print(f"  out : {res[:96]!r}  ({len(res)} B)   err={err}   auto-mapped pages={p.autopages}")
    ks = [h for h in p.hits if h['fn'] == 'KEYSETUP#14']
    print(f"  KEYSETUP#14 x{len(ks)}   ECB_ENC#85 x{sum(1 for h in p.hits if h['fn']=='ECB_ENC#85')}"
          f"   ECB_DEC#94 x{sum(1 for h in p.hits if h['fn']=='ECB_DEC#94')}")
    for i, h in enumerate(ks):
        kl = h['x3'] & 0xff
        print(f"   [{i}] skey=0x{h['x0']:x} userkey=0x{h['x1']:x} keylen={kl}")
        print(f"       x1-16..x1+80 = {h['x1_ctx'].hex()}")
        if kl in (16, 24, 32):
            kb = h['x1_ctx'][16:16 + kl]
            print(f"       userkey bytes  = {kb.hex()}   ascii={kb!r}")
            c = check(h['rk'], kb)
            if c is None:
                print(f"       struct Nr mismatch: got {struct.unpack_from('<i',h['rk'],0)[0]} want {expand(kb)[1]}")
            else:
                ok, got, want = c
                print(f"       FIPS-197 schedule match: {ok}" + ("" if ok else f"\n         got ={got}\n         want={want}"))
    return p, res, ks

if __name__ == '__main__':
    from aesref import cbc_enc
    ct = cbc_enc(b'hello', b'\0' * 16, b'\0' * 16).hex().encode()
    report('A: #36(cbc_hex(hello), b"k")', [ct, b'k'])
    report('B: #36(32hex, b"key")       ', [b'00112233445566778899aabbccddeeff', b'key'])
    report('C: #36(b"hello", b"k")      ', [b'hello', b'k'])
