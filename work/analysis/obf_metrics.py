import json, collections, statistics, math
fm=json.load(open('analysis/funcmap.json'))
rows=[]
for k,v in fm.items():
    ins=v["insns"]
    if ins<20: continue
    # cyclomatic complexity approx = cond_b + uncond_b(calls excluded) + 1
    cc=v["cond_b"]+v["uncond_b"]+1
    ratio=v["cmp"]/max(1,ins)
    movr=v["mov_imm"]/max(1,ins)
    rows.append({"idx":int(k),"start":v["start"],"size":v["size"],"insns":ins,
        "cc":cc,"cc_per_kinsn":cc/max(1,ins)*1000,"cmp":v["cmp"],"cmp_ratio":ratio,
        "mov_imm":v["mov_imm"],"mov_ratio":movr,"csel":v["csel"],
        "cond_b":v["cond_b"],"uncond_b":v["uncond_b"],
        "mnem":v["mnem"]})
def summarize(name,pred):
    sel=[r for r in rows if pred(r)]
    if not sel: print(name,"none"); return
    print(f"\n### {name}  (n={len(sel)})")
    for f in ["insns","cc","cmp_ratio","mov_ratio","csel","uncond_b"]:
        vals=[r[f] for r in sel]
        print(f"   {f:11s} mean={statistics.mean(vals):8.3f} median={statistics.median(vals):8.3f} max={max(vals):8.3f}")
summarize("ALL functions >=20 insns", lambda r: True)
# baseline: libc++/libunwind-ish funcs = the ones with no data refs into app rodata? approximate by size buckets
big=[r for r in rows if r["insns"]>=1000]
print(f"\n### functions with >=1000 insns: {len(big)}")
big.sort(key=lambda r:-r["cc"])
for r in big[:25]:
    print(f"   func#{r['idx']:4d} @0x{r['start']:06x} insns={r['insns']:5d} cc={r['cc']:4d} cmp={r['cmp']:4d} mov_imm={r['mov_imm']:5d} csel={r['csel']:3d} uncond_b={r['uncond_b']:4d} cmp_ratio={r['cmp_ratio']:.3f}")
# Distribution of "obfuscation score": high uncond_b + high mov_imm + high cmp
print("\n### TOP 30 by obfuscation score (uncond_b*2 + cmp + mov_imm/4 + csel)")
for r in sorted(rows,key=lambda r:-(r["uncond_b"]*2+r["cmp"]+r["mov_imm"]/4+r["csel"]))[:30]:
    sc=r["uncond_b"]*2+r["cmp"]+r["mov_imm"]/4+r["csel"]
    print(f"   func#{r['idx']:4d} @0x{r['start']:06x} score={sc:8.1f} insns={r['insns']:5d} cc={r['cc']:4d} cmp={r['cmp']:4d} mov_imm={r['mov_imm']:5d} uncond_b={r['uncond_b']:4d} cond_b={r['cond_b']:4d} csel={r['csel']:3d}")
# mnemonic histogram overall
mh=collections.Counter()
for r in rows: mh.update(r["mnem"])
print("\n### global mnemonic histogram (top 30)")
for m,c in mh.most_common(30): print(f"   {m:12s} {c}")
print("\n   total insns:",sum(r['insns'] for r in rows))
json.dump(rows,open('analysis/obf_rows.json','w'))
