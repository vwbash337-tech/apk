from capstone import *
import re,json,sys
d=open('apk_extracted/lib/arm64-v8a/libtopfollow.so','rb').read()
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
fm=json.load(open('analysis/funcmap.json'))

JUNK_CMP=re.compile(r'^cmp w\d+, (#0xa|#9|w\d+)$')
def is_junk(mn,op):
    if mn=='movk': return True
    if mn=='mov' and re.match(r'^w\d+, #0x[0-9a-f]+$',op): return True   # dispatcher state
    if mn=='mov' and re.match(r'^w\d+, w\d+$',op): return True
    if mn in ('cset','csel','adrp','cmn'): return True
    if mn=='cmp' and JUNK_CMP.match(op): return True
    if mn=='tst' and re.match(r'^w\d+, #1$',op): return True
    if mn=='ldr' and re.match(r'^w\d+, \[x\d+\]$',op): return True         # opaque var load
    if mn=='ldr' and re.match(r'^x\d+, \[x\d+, #0x[0-9a-f]+\]$',op) and int(op.split('#0x')[1].rstrip(']'),16)>0x600: return True
    if mn in ('sub','add','mul','mvn','eor','orr','and','orn','bic') and re.match(r'^w\d+, w\d+, (#0xfffffffe|#1|#0x[0-9a-f]{4,})$',op): return True
    if mn in ('strb','sturb') and re.search(r'w\d+, \[(x29|sp), #-?0x[0-9a-f]*\d*\]$',op) and False: return True
    return False

def analyze(t, maxtrace=4000, verbose_blocks=None):
    v=fm[str(t)]; lo=v['start']; sz=v['size']
    insns=list(md.disasm(d[lo:lo+sz],lo))
    by={i.address:i for i in insns}
    # find dispatcher: the block that ends with a compare-ladder on a single wreg
    # heuristic: most common b.eq/b.ne/b.le/b.gt target == dispatcher head
    tg={}
    for i in insns:
        if i.mnemonic in ('b.eq','b.ne','b.le','b.gt','b.lt','b.ge'):
            m=re.search(r'#(0x[0-9a-f]+)',i.op_str)
            if m: tg[int(m.group(1),16)]=tg.get(int(m.group(1),16),0)+1
    disp=max(tg,key=tg.get) if tg else None
    # state register = register compared in dispatcher ladder
    sreg=None
    if disp:
        for a in range(disp,min(disp+0x120,lo+sz),4):
            i=by.get(a)
            if i and i.mnemonic=='cmp':
                m=re.match(r'^(w\d+), ',i.op_str)
                if m: sreg=m.group(1); break
    # map state-value -> block for the ladder
    ladder={}
    if disp and sreg:
        a=disp
        while a<lo+sz:
            i=by.get(a)
            if not i: break
            if i.mnemonic=='cmp' and i.op_str.startswith(sreg+', #'):
                val=int(i.op_str.split('#')[1],0); nxt=None; cc=None
                j=by.get(a+4)
                if j and j.mnemonic.startswith('b.'):
                    m=re.search(r'#(0x[0-9a-f]+)',j.op_str)
                    if m: nxt=int(m.group(1),16); cc=j.mnemonic
                j2=by.get(a+8)
                if j2 and j2.mnemonic=='mov' and re.match(rf'^{sreg}, #',j2.op_str):
                    m=re.search(r'#(0x[0-9a-f]+)',j2.op_str); ladder[val]=(nxt,int(m.group(1),16),cc)
                    a+=12; continue
                if nxt is not None: ladder[val]=(nxt,None,cc); a+=8; continue
            a+=4
    # block starts = any branch target + disp
    starts=set([lo,disp] if disp else [lo])
    for i in insns:
        m=re.search(r'#(0x[0-9a-f]+)',i.op_str) if i.mnemonic.startswith('b') else None
        if m:
            t2=int(m.group(1),16)
            if lo<=t2<lo+sz: starts.add(t2)
    starts=sorted(s for s in starts if s in by)
    # for each block: its terminal and, if it sets sreg then jumps to disp, the state value
    blocks={}
    for bi,s in enumerate(starts):
        e=starts[bi+1] if bi+1<len(starts) else lo+sz
        body=[by[a] for a in range(s,e,4) if a in by]
        if not body: continue
        term=body[-1]
        st=None
        for i in body:
            if i.mnemonic=='mov' and re.match(rf'^{sreg}, #0x',i.op_str):
                st=int(i.op_str.split('#')[1],16)
        blocks[s]={'body':body,'term':term,'state':st,'end':e}
    return dict(lo=lo,sz=sz,disp=disp,sreg=sreg,ladder=ladder,blocks=blocks,by=by,insns=insns)

def clean(b):
    out=[]
    for i in b['body']:
        if i.mnemonic.startswith('b') or i.mnemonic=='ret': continue
        if is_junk(i.mnemonic,i.op_str): continue
        out.append(f"{i.mnemonic:8s} {i.op_str}")
    return out

if __name__=='__main__':
    t=int(sys.argv[1])
    A=analyze(t)
    print(f"func#{t} @0x{A['lo']:x} size={A['sz']} dispatcher=0x{(A['disp'] or 0):x} state-reg={A['sreg']}")
    print(f"ladder entries: {len(A['ladder'])}   blocks: {len(A['blocks'])}")
    # successor graph
    def succ(s):
        b=A['blocks'][s]; tm=b['term']
        if tm.mnemonic=='ret': return None
        if tm.mnemonic=='b' and not tm.op_str.startswith('#')==False:
            m=re.search(r'#(0x[0-9a-f]+)',tm.op_str)
            if not m: return None
            tgt=int(m.group(1),16)
            if tgt==A['disp']:
                st=b['state']
                if st in A['ladder']:
                    nxt,newst,cc=A['ladder'][st]
                    return nxt
                return ('STATE?',st)
            return tgt
        return ('COND',tm.mnemonic,tm.op_str)
    print("\n=== block successors ===")
    for s in sorted(A['blocks']):
        print(f"  0x{s:06x} state={A['blocks'][s]['state']} term={A['blocks'][s]['term'].mnemonic} {A['blocks'][s]['term'].op_str[:40]} -> {succ(s)}")
