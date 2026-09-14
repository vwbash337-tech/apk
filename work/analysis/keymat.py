import re,base64,json,collections
raw=open('apk_extracted/lib/arm64-v8a/libtopfollow.so','rb').read()
B64=re.compile(rb'[A-Za-z0-9+/]{8,}={0,2}')
hits=[]
for m in B64.finditer(raw[0x10000:0x18000]):
    va=0x10000+m.start(); s=m.group(0)
    if len(s)%4: continue
    try: dd=base64.b64decode(s,validate=True)
    except Exception: continue
    if len(dd) not in (12,16,24,32): continue
    hits.append((va,s,dd))
print(f"=== plaintext Base64 strings in .rodata decoding to 12/16/24/32 bytes : {len(hits)} ===")
for va,s,dd in hits:
    kind={12:'GCM-96bit-nonce/IV',16:'AES-128 key or CBC-IV',24:'AES-192 key',32:'AES-256 key'}[len(dd)]
    print(f"  0x{va:06x} b64={s.decode():46s} len={len(s):3d} -> {len(dd):2d}B {dd.hex()}  [{kind}]")
print()
print("=== XOR-0x5A-encoded Base64 strings (same filter) ===")
x=bytes(c^0x5a for c in raw[0x10000:0x18000])
for m in B64.finditer(x):
    va=0x10000+m.start(); s=m.group(0)
    if len(s)%4: continue
    try: dd=base64.b64decode(s,validate=True)
    except Exception: continue
    if len(dd) not in (12,16,24,32): continue
    print(f"  0x{va:06x} b64={s.decode():46s} len={len(s):3d} -> {len(dd):2d}B {dd.hex()}")
print()
print("=== which functions reference each plaintext key-material VA? ===")
xr=json.load(open('analysis/xrefs.json'))
fm=json.load(open('analysis/funcmap.json'))
inv=collections.defaultdict(list)
for t,v in fm.items():
    for a in v['data_refs']: inv[a].append(t)
for va,s,dd in hits:
    owners=[]
    for delta in range(-4,5):
        owners+= [(va+delta,t) for t in inv.get(va+delta,[])]
    print(f"  0x{va:06x} {s.decode()[:28]:30s} refs={sorted(set(t for _,t in owners))}")
