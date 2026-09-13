from capstone import *
import re,json,sys
d=open('apk_extracted/lib/arm64-v8a/libtopfollow.so','rb').read()
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
fm=json.load(open('analysis/funcmap.json'))
plt=json.load(open('analysis/plt_map.json'))
PLT={int(a,16):n for a,n in plt.items()}
BR=re.compile(r'#(0x[0-9a-f]+)')
def imm(s):
    m=re.match(r'^#(-?0x[0-9a-f]+|-?\d+)$',s);return int(m.group(1),0) if m else None
K=0x5a
def dstr(va,n=64):
    if not (0x10000<=va<0x1b000): return None
    s=bytes(c^K for c in d[va:va+n])
    m=re.match(rb'^[\x20-\x7e]{3,}',s)
    return m.group(0).decode() if m else None
def pstr(va,n=64):
    if not (0x10000<=va<0x1b000): return None
    m=re.match(rb'^[\x20-\x7e]{3,}',d[va:va+n])
    return m.group(0).decode() if m else None

JUNK=re.compile(r'^(cmp w\d+, (#0xa|#9|w\d+)|cset .*|csel .*|cmn w\d+, #1|tst w\d+, #1)$')
OPAQUE=re.compile(r'^(sub w\d+, w\d+, #1|mul w\d+, w\d+, w\d+|mvn w\d+, w\d+|orr w\d+, w\d+, #0xfffffffe|eor w\d+, w\d+, #0xfffffffe|and w\d+, w\d+, w\d+|eor w\d+, w\d+, w\d+|orr w\d+, w\d+, w\d+|orn w\d+, w\d+, w\d+|bic w\d+, w\d+, w\d+)$')
class FN:
    def __init__(s,t):
        s.t=t;v=fm[str(t)];s.lo=v['start'];s.sz=v['size']
        s.ins=list(md.disasm(d[s.lo:s.lo+s.sz],s.lo));s.by={i.address:i for i in s.ins}
        s.nx={s.ins[k].address:s.ins[k+1].address for k in range(len(s.ins)-1)}
        tg={}
        for i in s.ins:
            if i.mnemonic in ('b.eq','b.ne','b.le','b.gt','b.lt','b.ge'):
                m=BR.search(i.op_str)
                if m and s.lo<=int(m.group(1),16)<s.lo+s.sz: tg[int(m.group(1),16)]=tg.get(int(m.group(1),16),0)+1
        s.disp=max(tg,key=tg.get) if tg else None
        s.sreg=None
        if s.disp:
            a=s.disp
            for _ in range(8):
                i=s.by.get(a)
                if not i:break
                if i.mnemonic=='cmp':
                    m=re.match(r'^(w\d+),',i.op_str)
                    if m:s.sreg=m.group(1);break
                if i.mnemonic=='b':break
                a=s.nx.get(a)
        starts={s.lo}
        for i in s.ins:
            if i.mnemonic.startswith('b'):
                m=BR.search(i.op_str)
                if m and s.lo<=int(m.group(1),16)<s.lo+s.sz: starts.add(int(m.group(1),16))
                n=s.nx.get(i.address)
                if n: starts.add(n)
        starts=sorted(x for x in starts if x in s.by)
        s.blocks={}
        for k,st in enumerate(starts):
            e=starts[k+1] if k+1<len(starts) else s.lo+s.sz
            body=[];a=st
            while a is not None and a<e and a in s.by:
                body.append(s.by[a])
                if body[-1].mnemonic=='ret' or body[-1].mnemonic.startswith('b'):break
                a=s.nx.get(a)
            if body:s.blocks[st]=body
        s.dend=None
        if s.disp:
            a=s.disp
            while a in s.by:
                i=s.by[a]
                if i.mnemonic=='b':
                    m=BR.search(i.op_str);tt=int(m.group(1),16)
                    if tt!=s.disp: s.dend=tt;break
                if i.mnemonic=='ret':break
                a=s.nx.get(a)
    def wmap(s,body,W0=None):
        W=dict(W0 or {})
        for i in body:
            if i.mnemonic=='mov':
                m=re.match(r'^(w\d+), #(0x[0-9a-f]+|\d+)$',i.op_str)
                if m:W[m.group(1)]=int(m.group(2),0)&0xffffffff;continue
                m=re.match(r'^(w\d+), (w\d+)$',i.op_str)
                if m:W[m.group(1)]=W.get(m.group(2));continue
                m=re.match(r'^(x\d+), (x\d+)$',i.op_str)
                if m:W.pop(m.group(1).replace('x','w'),None);continue
            elif i.mnemonic=='movk':
                m=re.match(r'^(w\d+), #(0x[0-9a-f]+|\d+), lsl #(\d+)$',i.op_str)
                if m:
                    r=m.group(1);sh=int(m.group(3));b=W.get(r) or 0
                    W[r]=(b&~(0xffff<<sh))|(int(m.group(2),0)<<sh);continue
            if re.match(r'^(w\d+)$',i.op_str.split(',')[0]):
                W.pop(i.op_str.split(',')[0],None)
        return W
    def resolve(s,W,st,rounds=0):
        if st is None or s.disp is None:return None
        W=dict(W);W[s.sreg]=st;a=s.disp;g=0
        def sgn(x):return x-(1<<32) if x>=1<<31 else x
        while a in s.by and g<5000:
            g+=1;i=s.by[a]
            if i.mnemonic=='mov':
                m=re.match(r'^(w\d+), (w\d+)$',i.op_str)
                if m:W[m.group(1)]=W.get(m.group(2))
                else:
                    m=re.match(r'^(w\d+), #(0x[0-9a-f]+|\d+)$',i.op_str)
                    if m:W[m.group(1)]=int(m.group(2),0)&0xffffffff
            elif i.mnemonic=='movk':
                m=re.match(r'^(w\d+), #(0x[0-9a-f]+|\d+), lsl #(\d+)$',i.op_str)
                if m:
                    r=m.group(1);sh=int(m.group(3));b=W.get(r) or 0
                    W[r]=(b&~(0xffff<<sh))|(int(m.group(2),0)<<sh)
            elif i.mnemonic=='cmp':
                m=re.match(r'^(w\d+), (w\d+|#-?0x[0-9a-f]+|#-?\d+)$',i.op_str)
                if not m:a=s.nx.get(a);continue
                lhs=W.get(m.group(1));rhs=imm(m.group(2)) if m.group(2).startswith('#') else W.get(m.group(2))
                j=s.by.get(s.nx.get(a))
                if lhs is None or rhs is None or not j or not j.mnemonic.startswith('b.'):a=s.nx.get(a);continue
                cc=j.mnemonic;mt=BR.search(j.op_str);tgt=int(mt.group(1),16) if mt else None
                L,R=sgn(lhs),sgn(rhs)
                taken={'b.eq':L==R,'b.ne':L!=R,'b.le':L<=R,'b.gt':L>R,'b.lt':L<R,'b.ge':L>=R}[cc]
                if taken:
                    if tgt==s.disp:
                        rounds+=1;ns=W.get(s.sreg)
                        if ns is None or ns==st or rounds>16:return s.dend
                        st=ns;W[s.sreg]=st;a=s.disp;continue
                    return tgt
                a=s.nx.get(j.address);continue
            elif i.mnemonic=='b':
                mt=BR.search(i.op_str);tgt=int(mt.group(1),16) if mt else None
                if tgt is None:return None
                if tgt==s.disp:
                    rounds+=1;ns=W.get(s.sreg)
                    if ns is None or ns==st or rounds>16:return s.dend
                    st=ns;W[s.sreg]=st;a=s.disp;continue
                return tgt
            elif i.mnemonic=='ret':return 'RET'
            a=s.nx.get(a)
        return s.dend
    def succs(s,b,W0):
        body=s.blocks[b];tm=body[-1];W=s.wmap(body,W0);st=W.get(s.sreg)
        if tm.mnemonic=='ret':return [('ret',None)],W
        if tm.mnemonic=='b':
            m=BR.search(tm.op_str);tgt=int(m.group(1),16) if m else None
            if tgt==s.disp:return [('go',s.resolve(W,st))],W
            return [('go',tgt)],W
        if tm.mnemonic.startswith('b.'):
            m=BR.search(tm.op_str);tt=int(m.group(1),16) if m else None
            fall=s.nx.get(tm.address);out=[]
            out.append((tm.mnemonic, s.resolve(W,st) if tt==s.disp else tt))
            fb=s.blocks.get(fall)
            if fb:
                Wf=s.wmap(fb,W);stf=Wf.get(s.sreg);tf=fb[-1]
                if tf.mnemonic=='b' and BR.search(tf.op_str) and int(BR.search(tf.op_str).group(1),16)==s.disp:
                    out.append(('else',s.resolve(Wf,stf if stf is not None else st)))
                else:out.append(('else',fall))
            else:out.append(('else',fall))
            return out,W
        return [('fall',s.nx.get(tm.address))],W
    def name(s,tgt):
        if tgt in PLT:return f"<{PLT[tgt]}@plt>"
        for k,v in fm.items():
            if v['start']==tgt:return f"func#{k}"
            if v['start']<=tgt<v['start']+v['size']:return f"func#{k}+0x{tgt-v['start']:x}"
        return f"0x{tgt:x}"
def emit(t,maxb=4000):
    f=FN(t)
    out=[f"// ===== func#{t}  @0x{f.lo:x}  size={f.sz}  dispatcher=0x{(f.disp or 0):x} statereg={f.sreg} blocks={len(f.blocks)} ====="]
    order=[];seen=set();stack=[(f.lo,{})]
    while stack and len(order)<maxb:
        b,W=stack.pop(0)
        if b is None or b=='RET' or b in seen or b not in f.blocks:continue
        seen.add(b);order.append(b)
        ss,Wn=f.succs(b,W)
        for c,tg in ss:
            if tg and tg!='RET' and tg in f.blocks and tg not in seen: stack.append((tg,Wn))
    lab={b:f"L{i}" for i,b in enumerate(order)}
    for b in order:
        body=f.blocks[b]
        out.append(f"\n{lab[b]}:  // block 0x{b:06x}")
        W={}
        for i in body:
            s=f"{i.mnemonic} {i.op_str}"
            if JUNK.match(s):continue
            ann=''
            if i.mnemonic=='bl' or i.mnemonic=='b':
                m=BR.search(i.op_str)
                if m:
                    tgt=int(m.group(1),16)
                    if tgt in PLT:ann=f"   ; -> {PLT[tgt]}@plt"
                    elif tgt==f.disp:ann="   ; -> DISPATCHER"
                    elif tgt in lab:ann=f"   ; -> {lab[tgt]}"
                    else:
                        nm=f.name(tgt)
                        ann=f"   ; -> {nm}"
                        if nm.startswith('func#'):
                            try:
                                sub=FN(int(nm[5:].split('+')[0]))
                            except Exception:sub=None
            if i.mnemonic=='adrp':
                m=re.search(r'#(0x[0-9a-f]+)',i.op_str)
                if m:W['adrp']=int(m.group(1),16)
            if i.mnemonic in('ldr','add','ldrb') and 'adrp' in W:
                m=re.match(r'^(x\d+), (?:\[x\d+\], )?#?(0x[0-9a-f]+|\d+)$',i.op_str)
                m2=re.search(r'\[x\d+, #(0x[0-9a-f]+)\]',i.op_str)
                if m2:
                    va=W['adrp']+int(m2.group(1),16)
                    p=pstr(va);x=dstr(va)
                    if p or x: ann=f"   ; [0x{va:x}] plain={p!r} xor5a={x!r}"
                elif m and m.group(1).startswith('x'):
                    va=W['adrp']+int(m.group(2),0)
                    p=pstr(va);x=dstr(va)
                    if p or x: ann=f"   ; [0x{va:x}] plain={p!r} xor5a={x!r}"
            if OPAQUE.match(s) and not ann:continue
            if i.mnemonic=='movk':continue
            out.append(f"    {i.mnemonic:8s} {i.op_str}{ann}")
        ss,_=f.succs(b,{})
        txt=' , '.join(f"{c}->{lab.get(tg,'?') if tg in f.blocks else tg}" for c,tg in ss)
        out.append(f"    ; SUCC: {txt}")
    return '\n'.join(out)
if __name__=='__main__':
    print(emit(int(sys.argv[1])))
