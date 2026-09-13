import re,json,collections,base64
raw=open('apk_extracted/lib/arm64-v8a/libtopfollow.so','rb').read()
fm=json.load(open('analysis/funcmap.json'))
K=0x5a
x=bytes(c^K for c in raw)
inv=collections.defaultdict(set)
for t,v in fm.items():
    for a in v['data_refs']: inv[a].add(int(t))
def owners(va,w=6):
    s=set()
    for d in range(-w,w+1): s|=inv.get(va+d,set())
    return sorted(s)
# only look in the string region 0x14000-0x17500 and require an owner
runs=[]
i=0x14000
while i<0x17500:
    if 32<=x[i]<127:
        j=i
        while j<0x17500 and 32<=x[j]<127: j+=1
        s=x[i:j].decode('latin1')
        o=owners(i)
        if j-i>=4 and o:
            runs.append((i,s,o))
        i=j
    else: i+=1
print(f"=== {len(runs)} XOR-0x5A strings in 0x14000-0x17500 that ARE referenced ===")
seen=set()
for va,s,o in runs:
    if s in seen: continue
    seen.add(s)
    tag=''
    if re.fullmatch(r'[A-Za-z0-9+/]+={0,2}',s) and len(s)%4==0:
        try:
            dd=base64.b64decode(s,validate=True)
            tag=f"  =>b64 {dd.decode()!r}" if all(32<=c<127 for c in dd) else f"  =>b64 {dd.hex()}"
        except Exception: pass
    print(f"  0x{va:06x} f{str(o)[:34]:36s} {s[:110]!r}{tag}")
