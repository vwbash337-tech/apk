import json,collections,re
secs=json.load(open('analysis/model_arm64.json'))['sections']
data=open('apk_extracted/lib/arm64-v8a/libtopfollow.so','rb').read()
ROA=secs['.rodata']['addr']; ROS=secs['.rodata']['size']; ROO=secs['.rodata']['off']
def va2off(va): return ROO+(va-ROA)
ro=data[ROO:ROO+ROS]
OK=set(range(0x20,0x7f))
def printable(b): return len(b)>0 and all(x in OK for x in b)
# Segment .rodata into NUL-delimited units; for each unit try all 256 xor keys
units=[]; i=0
while i<len(ro):
    j=ro.find(b'\x00',i)
    if j<0: j=len(ro)
    if j>i: units.append((ROA+i, ro[i:j]))
    i=j+1
print("total NUL-delimited units in .rodata:",len(units))
enc=[]
for va,u in units:
    if len(u)<4: continue
    if printable(u):      # already plaintext
        continue
    hits=[]
    for k in range(1,256):
        d=bytes(x^k for x in u)
        if printable(d): hits.append((k,d.decode()))
    if hits:
        enc.append((va,len(u),u,hits))
print(f"\n=== UNITS DECODABLE BY SINGLE-BYTE XOR: {len(enc)} ===")
for va,ln,u,hits in enc:
    ks=[k for k,_ in hits]
    best=hits[0]
    print(f"0x{va:06x} len={ln:3d} keys={[hex(k) for k in ks]}  -> {best[1]!r}")
