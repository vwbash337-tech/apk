import sys,struct,json
sys.path.insert(0,'analysis')
from emu import Emu,STUB,STUB_SZ
from unicorn.arm64_const import *
import aesref

e=Emu()
mu=e.mu
KEY=b'0123456789abcdef'
PT=b'hello'

pt_s=e.mkstring(PT); key_s=e.mkstring(KEY); out_s=e.mkstring(b'')
ks=e.malloc(0x400)
e.wr(ks,b'\xee'*0x400)

hits=[]
def hook(mu,addr,sz,ud):
    if addr==0x32158 and len(hits)<1:
        g=lambda r: mu.reg_read(r)
        regs=[g(x) for x in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4)]
        hits.append(('f14',regs))
        for i,r in enumerate(regs):
            try: print("  f14 x%d=0x%x mem=%s"%(i,r,bytes(mu.mem_read(r,8)).hex()))
            except Exception as ex: print("  f14 x%d=0x%x (unreadable)"%(i,r))
    if addr==0x32158+0:
        pass
mu.hook_add(__import__('unicorn').UC_HOOK_CODE,hook)
# also trace func#10 first hit from within f14
h2=[]
def hook2(mu,addr,sz,ud):
    if addr in (0x32158,) : return
mu.hook_add(__import__('unicorn').UC_HOOK_CODE,hook2)

out=e.call(0x10c470,x0=pt_s,x1=key_s,x2=0,x8=out_s,timeout=200*1000000)
res=e.getstring(out_s)
print("func#85('hello',K16) ->",res)
print("reference           ->",aesref.ecb(PT,KEY).hex().encode())

# now inspect ks / any 240-byte run matching expanded schedule
w,nr=aesref.expand(KEY)
sched=bytes(b for word in w for b in word)
print("expected expanded schedule (round keys):",sched.hex())
# scan the heap for it
heap=e.rd(0x10000000,0x400000)
idx=bytes(heap).find(sched[:64])
print("schedule prefix found at heap offset:",hex(idx) if idx>=0 else None)
if idx>=0:
    print("full match:",bytes(heap)[idx:idx+176]==sched[:176])
