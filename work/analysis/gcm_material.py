"""Prove the double-Base64 key/nonce chain for the GCM builders (func#157/#158)
by running them under emulation and searching the resulting heap for each stage.

Stages for the key blob @0x17428 (64 bytes total, three sub-blobs):
  raw .rodata            1b2e636b...                     (XOR 0x5A packed)
  XOR 0x5A               'At91IxVnRSbFppV0UxNFdUSnplTW5ONA' + 2 x 16-char nonces
  Base64 layer 1         'Xt91I...' -> actually the 24-char inner Base64
  Base64 layer 2         02df7523...  (24 bytes = AES-192 key)
"""
import sys, json, base64, struct
sys.path.insert(0, 'analysis')
from emu import Emu
fm = json.load(open('analysis/funcmap.json'))
raw = open('apk_extracted/lib/arm64-v8a/libtopfollow.so', 'rb').read()
F157 = fm['157']['start']; F158 = fm['158']['start']; F193 = fm['193']['start']

def stages(blob):
    x = bytes(b ^ 0x5a for b in blob)
    out = [('raw .rodata', blob), ('XOR 0x5A', x)]
    cur = x
    for i in range(3):
        try:
            if len(cur) % 4 or not cur: break
            nxt = base64.b64decode(cur, validate=True)
        except Exception: break
        out.append((f'Base64 layer {i+1}', nxt)); cur = nxt
    return out

print("### static decode of the three sub-blobs")
for a, n, name in ((0x17428, 32, 'key   @0x17428'), (0x17448, 16, 'nonce1@0x17448'), (0x17458, 16, 'nonce2@0x17458')):
    print(f"\n  {name} ({n} B)")
    for tag, v in stages(raw[a:a+n]):
        pr = all(32 <= c < 127 for c in v)
        print(f"     {tag:16s} len={len(v):3d} {v.hex()}")
        if pr: print(f"     {'':16s}          ascii={v.decode()!r}")

print("\n### run func#157 / func#158 and look for each stage on the heap")
for tag, fn, arg in (('func#157', F157, b'hello world'), ('func#158', F158, b'hello world')):
    e = Emu()
    p = e.mkstring(arg)
    out = e.malloc(256); e.wr(out, b'\x00' * 256)
    err = None
    try: e.call(fn, x0=p, x8=out, timeout=int(120e6))
    except Exception as ex: err = str(ex)
    heap = bytes(e.rd(0x10000000, e.brk - 0x10000000))
    print(f"\n  {tag}: err={err}  heap={len(heap)} B  out={bytes(e.getstring(out))[:40]!r}")
    for a, n, name in ((0x17428, 32, 'key'), (0x17448, 16, 'nonce1'), (0x17458, 16, 'nonce2')):
        for st, v in stages(raw[a:a+n]):
            if len(v) < 6: continue
            i = heap.find(v)
            print(f"     {name:6s} {st:16s} {'FOUND @heap+0x%x' % i if i >= 0 else 'absent'}")
    # the known-answer values from the report
    for name, v in (('AES-192 key', bytes.fromhex('02df7523')), ('nonce1 head', bytes.fromhex('58c544c1')), ('nonce2 head', bytes.fromhex('334544c1'))):
        i = heap.find(v)
        print(f"     {name:16s} prefix {v.hex()} {'FOUND @heap+0x%x' % i if i >= 0 else 'absent'}")
