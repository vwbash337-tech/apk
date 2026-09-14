from capstone import *
import re,json,sys
d=open('apk_extracted/lib/arm64-v8a/libtopfollow.so','rb').read()
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
fm=json.load(open('analysis/funcmap.json'))
MOV=re.compile(r'^mov (w\d+), #(0x[0-9a-f]+|[0-9]+)$')
MOVK=re.compile(r'^movk (w\d+), #(0x[0-9a-f]+), lsl #16$')
BR=re.compile(r'#(0x[0-9a-f]+)')

class Func:
    def __init__(self,t):
        self.t=t; v=fm[str(t)]; self.lo=v['start']; self.sz=v['size']
        self.ins=list(md.disasm(d[self.lo:self.lo+self.sz],self.lo))
        self.by={i.address:i for i in self.ins}
        self.next={i.address:self.ins[k+1].address for k,i in enumerate(self.ins[:-1])}
        # dispatcher = most-targeted conditional branch destination
        tg={}
        for i in self.ins:
            if i.mnemonic in ('b.eq','b.ne','b.le','b.gt','b.lt','b.ge'):
                m=BR.search(i.op_str)
                if m: tg[int(m.group(1),16)]=tg.get(int(m.group(1),16),0)+1
        self.disp=max(tg,key=tg.get)
        # dispatcher tail: the fallthrough / default 'b' inside the ladder region
        self.dend=None
        a=self.disp
        while a in self.by:
            i=self.by[a]
            if i.mnemonic=='b':
                m=BR.search(i.op_str)
                if m and int(m.group(1),16)!=self.disp:
                    self.dend=int(m.group(1),16); break
            if i.mnemonic=='ret': break
            a=self.next.get(a)
        # state reg = reg of first cmp in dispatcher
        self.sreg=None
        a=self.disp
        for _ in range(6):
            i=self.by.get(a)
            if not i: break
            if i.mnemonic=='cmp':
                m=re.match(r'^(w\d+),',i.op_str)
                if m: self.sreg=m.group(1); break
            a=self.next.get(a)
        # basic blocks: split at branches and at any branch target
        starts={self.lo}
        for i in self.ins:
            if i.mnemonic.startswith('b'):
                m=BR.search(i.op_str)
                if m and self.lo<=int(m.group(1),16)<self.lo+self.sz: starts.add(int(m.group(1),16))
            if i.address in self.next and self.next[i.address] in self.by:
                if i.mnemonic.startswith('b') or i.mnemonic=='ret': starts.add(self.next[i.address])
        starts=sorted(s for s in starts if s in self.by)
        self.blocks={}
        for k,s in enumerate(starts):
            e=starts[k+1] if k+1<len(starts) else self.lo+self.sz
            body=[];a=s
            while a is not None and a<e and a in self.by:
                body.append(self.by[a])
                if body[-1].mnemonic=='ret' or body[-1].mnemonic.startswith('b'): break
                a=self.next.get(a)
            self.blocks[s]=body
    def setstate(self,body):
        """value assigned to self.sreg by mov/movk pair anywhere in body (last wins)"""
        val=None; partial=None
        for i in body:
            m=MOV.match(i.op_str) if i.mnemonic=='mov' else None
            if m and m.group(1)==self.sreg: partial=int(m.group(2),0); val=partial
            m2=MOVK.match(i.op_str) if i.mnemonic=='movk' else None
            if m2 and m2.group(1)==self.sreg and partial is not None:
                val=(partial&0xffff)|(int(m2.group(2),0)<<16); partial=val
        return val
    def term(self,s):
        b=self.blocks[s]; return b[-1] if b else None
    def succ_states(self,s):
        """returns list of (condition, target_block) resolving dispatcher"""
        b=self.blocks[s]; tm=self.term(s); out=[]
        if tm is None: return out
        if tm.mnemonic=='ret': return [('ret',None)]
        if tm.mnemonic=='b':
            m=BR.search(tm.op_str); tgt=int(m.group(1),16)
            if tgt==self.disp:
                st=self.setstate(b); return [('always', self.resolve(st))]
            return [('always',tgt)]
        if tm.mnemonic.startswith('b.'):
            m=BR.search(tm.op_str); tt=int(m.group(1),16)
            fall=self.next.get(tm.address)
            # state may have been set before the cond branch, or inside each arm
            st_taken=self.setstate(b)
            # look at target block's own setstate for the other arm
            st_fall=self.setstate(self.blocks.get(fall,[])) if fall in self.blocks else None
            if tt==self.disp: out.append((tm.mnemonic,self.resolve(st_taken)))
            else: out.append((tm.mnemonic,tt))
            if fall==self.disp: out.append(('else',self.resolve(st_fall)))
            elif fall in self.blocks: out.append(('else',fall))
            return out
        # block ends without terminator because next addr is a branch target -> fallthrough
        nxt=self.next.get(tm.address)
        return [('fall',nxt)]
    def resolve(self,st):
        """walk the dispatcher ladder from self.disp with state=st"""
        if st is None: return None
        a=self.disp; w8=None; guard=0
        while a in self.by and guard<400:
            guard+=1; i=self.by[a]
            if i.mnemonic=='mov':
                m=re.match(r'^(w\d+), (w\d+)$',i.op_str)
                if m: 
                    if m.group(1)=='w8' and m.group(2)==self.sreg: w8=st
                    elif m.group(1)==self.sreg:
                        mm=MOV.match(i.op_str)
            elif i.mnemonic=='cmp':
                m=re.match(r'^(w\d+), #(0x[0-9a-f]+|[0-9]+)$',i.op_str)
                if m:
                    reg=m.group(1); imm=int(m.group(2),0)
                    cur=st if reg==self.sreg else w8
                    if cur is not None:
                        j=self.by.get(self.next.get(a))
                        if j and j.mnemonic.startswith('b.'):
                            mm=BR.search(j.op_str); tgt=int(mm.group(1),16)
                            taken=False
                            if j.mnemonic=='b.eq': taken=(cur==imm)
                            elif j.mnemonic=='b.ne': taken=(cur!=imm)
                            elif j.mnemonic=='b.le': taken=(cur<=imm)
                            elif j.mnemonic=='b.gt': taken=(cur>imm)
                            elif j.mnemonic=='b.lt': taken=(cur<imm)
                            elif j.mnemonic=='b.ge': taken=(cur>=imm)
                            if taken:
                                if tgt==self.disp: return None
                                a=tgt; continue
                            else:
                                a=self.next.get(j.address); continue
            elif i.mnemonic=='b':
                m=BR.search(i.op_str); tgt=int(m.group(1),16)
                if tgt==self.disp: return None
                return tgt
            a=self.next.get(a)
        return None

def fmt(i): return f"0x{i.address:06x}: {i.mnemonic:8s} {i.op_str}"

if __name__=='__main__':
    t=int(sys.argv[1]); F=Func(t)
    print(f"func#{t} @0x{F.lo:x} sz={F.sz} disp=0x{F.disp:x} dend={hex(F.dend) if F.dend else None} sreg={F.sreg} blocks={len(F.blocks)}")
    # entry trace
    seen=set(); order=[]; cur=F.lo; depth=0
    while cur is not None and cur in F.blocks and depth<400:
        if cur in seen: order.append(('LOOP',cur)); break
        seen.add(cur); order.append(cur); depth+=1
        ss=F.succ_states(cur)
        if not ss: break
        if ss[0][0]=='ret': order.append(('RET',cur)); break
        if len(ss)==1: cur=ss[0][1]
        else:
            order.append(('BRANCH',cur,ss)); cur=ss[0][1]
    print("\n=== linearised execution order (first arm) ===")
    for o in order:
        if isinstance(o,int):
            body=F.blocks[o]
            keep=[i for i in body if not (i.mnemonic in('movk','cset','csel','adrp') or (i.mnemonic=='cmp' and re.match(r'^w\d+, (#0xa|#9|w\d+)$',i.op_str)))]
            print(f"-- block 0x{o:06x} ({len(body)} insns, {len(keep)} kept)")
            for i in keep: print("   ",fmt(i))
        else: print("  ",o)
