import lief, json, sys, re
from capstone import *
from capstone.arm64 import *

path='apk_extracted/lib/arm64-v8a/libtopfollow.so'
b=lief.parse(path); data=open(path,'rb').read()
secs={s.name:(s.virtual_address,s.offset,s.size) for s in b.sections}
model=json.load(open('analysis/model_arm64.json'))
funcs=model['functions']
TA,TO,TS=secs['.text']

# PLT map: parse .rela.plt to map plt slot -> import name
rela_plt_A,rela_plt_O,rela_plt_S=secs['.rela.plt']
plt_A,plt_O,plt_S=secs['.plt']
dynsym={s.value:s.name for s in b.imported_symbols}
plt_map={}
# .plt layout on arm64: header 32 bytes then 16 bytes per entry
n_entries=rela_plt_S//24
sym_names=[s.name for s in b.symbols]
for i in range(n_entries):
    ent=data[rela_plt_O+i*24:rela_plt_O+i*24+24]
    r_off,r_info,r_add=[int.from_bytes(ent[j:j+8],'little') for j in (0,8,16)]
    sym_idx=r_info>>32
    name=sym_names[sym_idx] if sym_idx<len(sym_names) else '?'
    slot=plt_A+32+i*16
    plt_map[slot]=name
json.dump({hex(k):v for k,v in plt_map.items()},open('analysis/plt_map.json','w'),indent=1)
print("PLT entries:",len(plt_map))

md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True

# function lookup
starts=[f['start'] for f in funcs]
import bisect
def func_of(va):
    i=bisect.bisect_right(starts,va)-1
    if i>=0 and va<starts[i]+funcs[i]['size']: return i
    return None

# Pass 1: collect adrp/add|ldr pairs -> resolved data addresses ; collect calls
xrefs={}      # target va -> list of (site va, kind)
calls={}      # site va -> target
ann_lines=[]  # (funcidx, addr, text)
adrp_reg={}
for idx,f in enumerate(funcs):
    st,sz=f['start'],f['size']
    if st<TA or st+sz>TA+TS: continue
    code=data[TO+(st-TA):TO+(st-TA)+sz]
    pending={}   # reg -> adrp base
    for ins in md.disasm(code,st):
        extra=''
        m=ins.mnemonic; ops=list(ins.operands)
        if m=='adrp' and len(ops)==2 and ops[0].type==ARM64_OP_REG and ops[1].type==ARM64_OP_IMM:
            pending[ins.reg_name(ops[0].reg)]=ops[1].imm
        elif m in ('add','ldr') and len(ops)>=3 and ops[0].type==ARM64_OP_REG:
            rn=ins.reg_name(ops[1].reg) if ops[1].type==ARM64_OP_REG else None
            if rn in pending and ops[2].type==ARM64_OP_IMM:
                tgt=pending[rn]+ops[2].imm
                dst=ins.reg_name(ops[0].reg)
                if m=='add': pending[dst]=tgt; extra=f'  ; ->0x{tgt:x}'
                else: extra=f'  ; [0x{tgt:x}]'
                if m=='add':
                    xrefs.setdefault(tgt,[]).append((ins.address,'adrp+add'))
        elif m=='blr' and ops and ops[0].type==ARM64_OP_REG:
            pass
        elif m=='bl' and ops and ops[0].type==ARM64_OP_IMM:
            t=ops[0].imm
            calls[ins.address]=t
            if t in plt_map: extra=f'  ; PLT {plt_map[t]}'
            else:
                fi=func_of(t)
                if fi is not None: extra=f'  ; sub_{t:x} (func#{fi})'
            xrefs.setdefault(t,[]).append((ins.address,'bl'))
        ann_lines.append((idx,ins.address,f"0x{ins.address:08x}: {ins.bytes.hex():<10s} {ins.mnemonic:<10s} {ins.op_str}{extra}"))
with open('analysis/annotated_arm64.txt','w') as o:
    cur=None
    for idx,a,t in ann_lines:
        if idx!=cur:
            cur=idx
            o.write(f"\n; ===== FUNC #{idx} @ 0x{funcs[idx]['start']:x} size={funcs[idx]['size']} =====\n")
        o.write(t+"\n")
json.dump({hex(k):[[s,kind] for s,kind in v] for k,v in xrefs.items()},open('analysis/xrefs.json','w'))
json.dump({hex(k):hex(v) for k,v in calls.items()},open('analysis/calls.json','w'))
print("annotated lines:",len(ann_lines),"xref targets:",len(xrefs),"calls:",len(calls))
