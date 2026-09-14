"""ELF model + FDE-based function recovery for libtopfollow.so"""
import lief, json, sys, bisect

def build(path, out):
    b = lief.parse(path)
    secs = {}
    for s in b.sections:
        secs[s.name] = {"addr": s.virtual_address, "off": s.offset, "size": s.size,
                        "flags": str(s.flags_list)}
    info = {
        "path": path, "file_size": len(open(path,'rb').read()),
        "type": str(b.header.file_type), "machine": str(b.header.machine_type),
        "entry": b.header.entrypoint,
        "sections": secs,
        "exported": [{"name": s.name, "value": s.value, "size": s.size}
                     for s in b.exported_symbols],
        "imported": sorted(set(s.name for s in b.imported_symbols if s.name)),
        "libraries": b.libraries,
        "build_id": b.get_section(".note.gnu.build-id").content.hex() if b.get_section(".note.gnu.build-id") else None,
    }
    # ---- FDE walk over .eh_frame ----
    eh = b.get_section(".eh_frame")
    data = bytes(eh.content)
    base = eh.virtual_address
    fdes = []
    cies = {}
    i = 0
    n = len(data)
    while i + 4 <= n:
        length = int.from_bytes(data[i:i+4], 'little')
        if length == 0:
            break
        start = i
        body = i + 4
        end = body + length
        if end > n: break
        cid = int.from_bytes(data[body:body+4], 'little')
        if cid == 0:                      # CIE
            cies[start] = body
            i = end
            continue
        cie_ptr_field = body
        cie_start = cie_ptr_field - cid
        if cie_start in cies:
            pc_begin = int.from_bytes(data[cie_start+4+ (0):cie_start+4], 'little')  # placeholder
            # CIE: length(4) CIE_id(4) version(1) augstr(...) 
            j = cie_start + 4 + 4
            version = data[j]; j += 1
            aug = b''
            while data[j] != 0:
                aug += bytes([data[j]]); j += 1
            j += 1
            augstr = aug.decode('latin1')
            # uleb128 code_align, sleb128 data_align, return reg
            def uleb(k):
                r=0;s=0
                while True:
                    by=data[k];k+=1;r|=(by&0x7f)<<s
                    if not by&0x80: break
                    s+=7
                return r,k
            def sleb(k):
                r=0;s=0
                while True:
                    by=data[k];k+=1;r|=(by&0x7f)<<s;s+=7
                    if not by&0x80:
                        if by&0x40: r-= (1<<s)
                        break
                return r,k
            code_align,j = uleb(j)
            data_align,j = sleb(j)
            if version >= 3:
                _,j = uleb(j)          # return address register (uleb in v3)
            else:
                j += 1
            if 'z' in augstr:
                _,j = uleb(j)
            for c in augstr[1:]:
                if c=='L': j+=1
                elif c=='R': j+=1
                elif c=='P':
                    enc=data[j]; j+=1
                    # skip personality: assume udata/sdata 4
                    j+=4
                elif c=='S': pass
            # FDE parse
            k = body + 4
            pc_begin = int.from_bytes(data[k:k+4],'little'); k+=4
            pc_range = int.from_bytes(data[k:k+4],'little'); k+=4
            real_pc = (start + 4 + (k-4-4) - 4)  # not used; PC is relative to FDE's pc_begin field location
            fde_pc_field_off = base + (body + 4)
            func_start = fde_pc_field_off + pc_begin if pc_begin else None
            fdes.append({"pc_begin_field_vaddr": fde_pc_field_off,
                         "rel": pc_begin, "range": pc_range,
                         "cie_off": cie_start, "aug": augstr})
        i = end
    # For 'R' encoding = DW_EH_PE_pcrel|sdata4 (0x1b) typical -> function start = pc_begin_field_vaddr + rel
    funcs = []
    for f in fdes:
        if f["range"] > 0:
            funcs.append({"start": f["pc_begin_field_vaddr"] + f["rel"], "size": f["range"]})
    funcs.sort(key=lambda x: x["start"])
    # merge duplicates
    merged=[]
    for f in funcs:
        if merged and merged[-1]["start"]==f["start"]:
            merged[-1]["size"]=max(merged[-1]["size"],f["size"]); continue
        merged.append(dict(f))
    info["fde_count"]=len(fdes)
    info["cie_count"]=len(cies)
    info["functions"]=merged
    json.dump(info, open(out,'w'), indent=1)
    print("sections:", len(secs))
    print("CIEs:", len(cies), "FDEs:", len(fdes), "functions:", len(merged))
    tot=sum(f['size'] for f in merged)
    print("total func bytes:", tot, "of .text", secs.get('.text',{}).get('size'))
    print("augs:", sorted(set(f['aug'] for f in fdes)))
    return info

if __name__=="__main__":
    build(sys.argv[1], sys.argv[2])
