"""Full linear-sweep + function-scoped disassembly using LIEF + Capstone."""
import lief, json, sys
from capstone import *

def load(path):
    b = lief.parse(path)
    data = open(path,'rb').read()
    secs = {s.name:(s.virtual_address, s.offset, s.size) for s in b.sections}
    return b, data, secs

def va_to_off(va, secs, name='.text'):
    a,o,s = secs[name]
    return o + (va-a)

if __name__ == "__main__":
    path = sys.argv[1]
    model = json.load(open(sys.argv[2]))
    b,data,secs = load(path)
    funcs = model["functions"]
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    ta,to,ts = secs['.text']
    out = open(sys.argv[3],'w')
    for idx,f in enumerate(funcs):
        st,sz = f["start"], f["size"]
        if st < ta or st+sz > ta+ts: continue
        off = to + (st-ta)
        code = data[off:off+sz]
        out.write(f"\n; ===== FUNC #{idx} @ 0x{st:x} size={sz} =====\n")
        try:
            for ins in md.disasm(code, st):
                out.write(f"0x{ins.address:08x}: {ins.bytes.hex():<10s} {ins.mnemonic:<10s} {ins.op_str}\n")
        except Exception as e:
            out.write(f"; disasm error {e}\n")
    out.close()
    print("wrote", sys.argv[3], "funcs:", len(funcs))
