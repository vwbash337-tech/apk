from capstone import *
import re,json,sys
d=open('apk_extracted/lib/arm64-v8a/libtopfollow.so','rb').read()
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
fm=json.load(open('analysis/funcmap.json'))
BR=re.compile(r'#(0x[0-9a-f]+)')
def imm(s):
    m=re.match(r'^#(-?0x[0-9a-f]+|-?\d+)$',s); return int(m.group(1),0) if m else None

class F:
    def __init__(s,t):
        s.t=t;v=fm[str(t)];s.lo=v['start'];s.sz=v['size']
        s.ins=list(md.disasm(d[s.lo:s.lo+s.sz],s.lo));s.by={i.address:i for i in s.ins}
        s.nx={s.ins[k].address:s.ins[k+1].address for k in range(len(s.ins)-1)}
        tg={}
        for i in s.ins:
            if i.mnemonic in ('b.eq','b.ne','b.le','b.gt','b.lt','b.ge'):
                m=BR.search(i.op_str)
                if m: tg[int(m.group(1),16)]=tg.get(int(m.group(1),16),0)+1
        s.disp=max(tg,key=tg.get)
        s.sreg=None;a=s.disp
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
                if body[-1].mnemonic=='ret' or body[-1].mnemonic.startswith('b'): break
                a=s.nx.get(a)
            if body: s.blocks[st]=body
    def wmap(s,body):
        """register -> constant value after executing body (mov/movk only)"""
        w={}
        for i in body:
            if i.mnemonic=='mov':
                m=re.match(r'^(w\d+), #(0x[0-9a-f]+|\d+)$',i.op_str)
                if m: w[m.group(1)]=int(m.group(2),0)&0xffffffff
                else:
                    m=re.match(r'^(w\d+), (w\d+)$',i.op_str)
                    if m: w[m.group(1)]=w.get(m.group(2))
            elif i.mnemonic=='movk':
                m=re.match(r'^(w\d+), #(0x[0-9a-f]+|\d+), lsl #(\d+)$',i.op_str)
                if m:
                    r=m.group(1);v=int(m.group(2),0)<<int(m.group(3));sh=int(m.group(3))
                    base=w.get(r,0) if w.get(r) is not None else 0
                    w[r]=(base&~(0xffff<<sh))|v
            elif i.mnemonic in ('sub','add','mul','eor','orr','and','mvn','orn','bic','lsl','lsr'):
                for r in re.findall(r'\bw\d+\b',i.op_str.split(',')[0]): w.pop(r,None)
        return w
    def resolve(s,W,st,depth=0):
        """walk dispatcher ladder with reg-map W and immutable state st -> target block"""
        if st is None: return None
        W=dict(W); W[s.sreg]=st
        a=s.disp; g=0; rounds=0
        def sgn(x): return x-(1<<32) if x>=1<<31 else x
        while a in s.by and g<4000:
            g+=1; i=s.by[a]
            if i.mnemonic=='mov':
                m=re.match(r'^(w\d+), (w\d+)$',i.op_str)
                if m: W[m.group(1)]=W.get(m.group(2))
                else:
                    m=re.match(r'^(w\d+), #(0x[0-9a-f]+|\d+)$',i.op_str)
                    if m: W[m.group(1)]=int(m.group(2),0)&0xffffffff
            elif i.mnemonic=='movk':
                m=re.match(r'^(w\d+), #(0x[0-9a-f]+|\d+), lsl #(\d+)$',i.op_str)
                if m:
                    r=m.group(1);sh=int(m.group(3));base=W.get(r) or 0
                    W[r]=(base&~(0xffff<<sh))|(int(m.group(2),0)<<sh)
            elif i.mnemonic=='cmp':
                m=re.match(r'^(w\d+), (w\d+|#-?0x[0-9a-f]+|#-?\d+)$',i.op_str)
                if not m: a=s.nx.get(a); continue
                lhs=W.get(m.group(1))
                rhs=imm(m.group(2)) if m.group(2).startswith('#') else W.get(m.group(2))
                j=s.by.get(s.nx.get(a))
                if lhs is None or rhs is None or not j or not j.mnemonic.startswith('b.'):
                    a=s.nx.get(a); continue
                cc=j.mnemonic; mt=BR.search(j.op_str); tgt=int(mt.group(1),16) if mt else None
                L,R=sgn(lhs),sgn(rhs)
                taken={'b.eq':L==R,'b.ne':L!=R,'b.le':L<=R,'b.gt':L>R,'b.lt':L<R,'b.ge':L>=R}[cc]
                if taken:
                    if tgt==s.disp:
                        rounds+=1
                        ns=W.get(s.sreg)
                        if ns is None or ns==st or rounds>12: return None
                        st=ns; W[s.sreg]=st; a=s.disp; continue
                    return tgt
                a=s.nx.get(j.address); continue
            elif i.mnemonic=='b':
                mt=BR.search(i.op_str); tgt=int(mt.group(1),16) if mt else None
                if tgt is None: return None
                if tgt==s.disp:
                    rounds+=1
                    ns=W.get(s.sreg)
                    if ns is None or ns==st or rounds>12: return None
                    st=ns; W[s.sreg]=st; a=s.disp; continue
                return tgt
            elif i.mnemonic=='ret': return 'RET'
            a=s.nx.get(a)
        return None
    def succ(s,b):
        body=s.blocks[b];tm=body[-1];W=s.wmap(body);st=W.get(s.sreg)
        if tm.mnemonic=='ret': return [('ret',None)]
        if tm.mnemonic=='b':
            m=BR.search(tm.op_str);tgt=int(m.group(1),16) if m else None
            if tgt==s.disp: return [('go',s.resolve(W,st))]
            return [('go',tgt)]
        if tm.mnemonic.startswith('b.'):
            m=BR.search(tm.op_str);tt=int(m.group(1),16) if m else None
            fall=s.nx.get(tm.address);out=[]
            if tt==s.disp: out.append((tm.mnemonic,s.resolve(W,st)))
            else: out.append((tm.mnemonic,tt))
            # for the else arm, find which state is live: look ahead into fall block
            if fall in s.blocks:
                fb=s.blocks[fall];Wf=s.wmap(fb);stf=Wf.get(s.sreg);tf=fb[-1]
                if tf.mnemonic=='b' and BR.search(tf.op_str) and int(BR.search(tf.op_str).group(1),16)==s.disp:
                    out.append(('else',s.resolve({**W,**Wf},stf if stf is not None else st)))
                else: out.append(('else',fall))
            return out
        return [('fall',s.nx.get(tm.address))]

if __name__=='__main__':
    t=int(sys.argv[1]);lim=int(sys.argv[2]) if len(sys.argv)>2 else 600
    f=F(t);print(f"# func#{t} @0x{f.lo:x} sz={f.sz} disp=0x{f.disp:x} sreg={f.sreg} blocks={len(f.blocks)}")
    seen=set();seq=[];cur=f.lo;n=0
    while cur in f.blocks and n<lim:
        n+=1
        if cur in seen: seq.append(f"<<LOOP back to 0x{cur:06x}>>");break
        seen.add(cur);seq.append(cur)
        ss=f.succ(cur)
        if not ss or ss[0][0]=='ret': seq.append('<<RET>>');break
        if ss[0][1] is None: seq.append(f"<<UNRESOLVED {ss}>>");break
        if len(ss)>1: seq.append(('BR',cur,ss))
        cur=ss[0][1]
    JUNK=re.compile(r'^(cmp w\d+, (#0xa|#9|w\d+)|cset |csel |adrp |movk |cmn w\d+, #1|tst w\d+, #1|mov w\d+, w\d+)$')
    for o in seq:
        if isinstance(o,int):
            b=f.blocks[o];keep=[i for i in b if not JUNK.match(f"{i.mnemonic} {i.op_str}".strip())]
            print(f"\n; ===== real block 0x{o:06x}  ({len(b)} insns -> {len(keep)} meaningful)")
            for i in keep: print(f"    {i.mnemonic:8s} {i.op_str}")
        elif isinstance(o,tuple): print(f"    ;; {o[0]} @{o[2]}")
        else: print(f"\n{o}")
