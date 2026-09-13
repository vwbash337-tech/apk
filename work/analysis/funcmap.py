import json, bisect, re, collections
model=json.load(open('analysis/model_arm64.json'))
funcs=model['functions']; starts=[f['start'] for f in funcs]
def fidx(va):
    i=bisect.bisect_right(starts,va)-1
    return i if i>=0 and va<starts[i]+funcs[i]['size'] else None
# parse annotated disasm into per-function structures
cur=None
F=collections.OrderedDict()
pat_xref=re.compile(r'; ->0x([0-9a-f]+)')
pat_plt=re.compile(r'; PLT (\S+)')
pat_sub=re.compile(r'; sub_([0-9a-f]+) \(func#(\d+)\)')
hdr=re.compile(r'; ===== FUNC #(\d+) @ 0x([0-9a-f]+) size=(\d+) =====')
for line in open('analysis/annotated_arm64.txt'):
    m=hdr.match(line)
    if m:
        cur=int(m.group(1))
        F[cur]={"start":int(m.group(2),16),"size":int(m.group(3)),
                "insns":0,"data_refs":set(),"plt":collections.Counter(),
                "calls":collections.Counter(),"mnem":collections.Counter(),
                "branches":0,"cmp":0,"mov_imm":0,"csel":0,"cond_b":0,"uncond_b":0,
                "dispatcher_like":0}
        continue
    if cur is None or not line.startswith('0x'): continue
    parts=line.split(None,3)
    if len(parts)<3: continue
    f=F[cur]; f["insns"]+=1
    mn=parts[1]
    f["mnem"][mn]+=1
    if mn.startswith('b.'): f["cond_b"]+=1; f["branches"]+=1
    elif mn=='b': f["uncond_b"]+=1; f["branches"]+=1
    elif mn in ('cbz','cbnz','tbz','tbnz'): f["cond_b"]+=1; f["branches"]+=1
    if mn in ('cmp','tst','cmn','ccmp'): f["cmp"]+=1
    if mn in ('mov','movz','movk','movn') : f["mov_imm"]+=1
    if mn=='csel' or mn=='csinc' or mn=='csinv' or mn=='csneg': f["csel"]+=1
    for t in pat_xref.findall(line): f["data_refs"].add(int(t,16))
    for p in pat_plt.findall(line): f["plt"][p]+=1
    for s,i in pat_sub.findall(line): f["calls"][int(i)]+=1
json.dump({str(k):{"start":v["start"],"size":v["size"],"insns":v["insns"],
   "data_refs":sorted(v["data_refs"]),"plt":dict(v["plt"]),"calls":dict(v["calls"]),
   "mnem":dict(v["mnem"]),"branches":v["branches"],"cmp":v["cmp"],
   "mov_imm":v["mov_imm"],"csel":v["csel"],"cond_b":v["cond_b"],"uncond_b":v["uncond_b"]}
   for k,v in F.items()}, open('analysis/funcmap.json','w'))
print("functions parsed:",len(F))
# report helper
def owner(va):
    i=fidx(va)
    return i, (F[i]["start"] if i in F else None)
targets={
 "access()":0x13bac4,"clock()":0x114ff0,"syscall()#1":0x196ca4,"syscall()#2":0x196cfc,
 "dl_iterate_phdr()":0x1ae5a8,"base64 alphabet":0x38984,"SHA-256 K table":0x15192c,
 "AES Te0 a":0x2e440,"AES Te0 b":0x30d08,"AES SBOX a":0x2dc9c,"AES SBOX b":0x307ec,
 "AES SBOX c":0x32834,"AES SBOX d":0x33834,"AES Td0 a":0x2f7f8,"AES Td0 b":0x319c8,
 "AES RSBOX a":0x2ec5c,"AES RSBOX b":0x31aa8,"Rcon":0x33e04,
}
print("\n=== CALL/DATA SITE -> OWNING FUNCTION ===")
for k,v in targets.items():
    i,st=owner(v)
    print(f"  {k:20s} site=0x{v:06x} -> func#{i} @0x{st:x} size={funcs[i]['size']}" if i is not None else f"  {k}: unmapped")
str_targets={
 "/proc/self/maps":0x15db5,"re.frida.server":0x1607f,"substrate":0x15dd4,"lsposed":0x167a9,
 "xposed":0x16c11,"edxposed":0x16204,"libfrida-gadget":0x16d97,"gum-js-loop":0x161eb,
 "libcso_substrate":0x156e8,"libbridge.so":0x15541,"libart.so (deleted)":0x16b75,
 "libc.so (deleted)":0x16f69,"pin-sha256 blob":0x15084,"helper/q":0x14da2,
}
print("\n=== STRING -> REFERENCING FUNCTIONS ===")
inv=collections.defaultdict(list)
for k,v in F.items():
    for d in v["data_refs"]:
        inv[d].append(k)
for name,va in str_targets.items():
    owners=sorted(inv.get(va,[]))
    print(f"  {name:22s} 0x{va:06x} -> funcs {[(o,hex(F[o]['start'])) for o in owners]}")
