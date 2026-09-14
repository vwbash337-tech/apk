"""func#30 (AES-128-CBC, key=0, IV=0 as proven in 11.2) also references a 16-char
Base64 string @0x1606a that decodes to 12 bytes -- the same shape as the GCM
nonces.  Find out what func#30 actually does with it."""
import sys, json, base64
sys.path.insert(0, 'analysis')
from emu import Emu
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *
fm = json.load(open('analysis/funcmap.json'))
raw = open('apk_extracted/lib/arm64-v8a/libtopfollow.so', 'rb').read()
F30 = fm['30']['start']; F14 = fm['14']['start']
blob = raw[0x1606a:0x1606a+16]
print("blob @0x1606a:", blob, "-> b64:", base64.b64decode(blob).hex(), len(base64.b64decode(blob)), "bytes")

class P(Emu):
    def __init__(self):
        super().__init__()
        self.keysetups = []
        self.mu.hook_add(UC_HOOK_CODE, self._w)
    def _w(self, mu, addr, sz, ud):
        if addr != F14: return
        x1 = mu.reg_read(UC_ARM64_REG_X1); kl = mu.reg_read(UC_ARM64_REG_X3) & 0xff
        try: kb = bytes(self.rd(x1, kl if kl in (16,24,32) else 32))
        except Exception: kb = b''
        self.keysetups.append((kl, x1, kb))

for pt in (b'', b'a', b'hello', b'0123456789abcde', b'0123456789abcdef', b'x'*221):
    p = P()
    x0 = p.mkstring(pt); x1 = p.mkstring(b'IGNORED-KEY-ARG')
    out = p.malloc(1024); p.wr(out, b'\x00'*1024)
    err = None
    try: p.call(F30, x0=x0, x1=x1, x8=out, timeout=int(180e6))
    except Exception as ex: err = str(ex)
    res = b''
    try: res = bytes(p.getstring(out))
    except Exception: pass
    heap = bytes(p.rd(0x10000000, p.brk - 0x10000000))
    print(f"\n  pt={pt!r} ({len(pt)}B) -> out={res.hex()[:64]} ({len(res)}B) err={err}")
    for kl, ka, kb in p.keysetups:
        print(f"     KEYSETUP keylen={kl} key={kb.hex()}")
    for tag, v in (('blob ascii', blob), ('blob b64-decoded', base64.b64decode(blob))):
        i = heap.find(v)
        print(f"     {tag:18s} on heap: {'yes @+0x%x' % i if i>=0 else 'no'}")
