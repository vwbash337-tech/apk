import sys,struct
sys.path.insert(0,'analysis')
from emu import Emu,STACK,STACK_SZ,HEAP,HEAP_SZ
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *
import aesref
e=Emu(); mu=e.mu
KEY=b'0123456789abcdef'; PT=b'hello'
pt_s=e.mkstring(PT); key_s=e.mkstring(KEY); out_s=e.mkstring(b'')
cap=[]
def hook(mu,addr,sz,ud):
    if addr==0x32158 and not cap:
        cap.append((mu.reg_read(UC_ARM64_REG_X0),mu.reg_read(UC_ARM64_REG_X2),mu.reg_read(UC_ARM64_REG_SP)))
    if addr==0x10c470+0 and cap and len(cap)==1:
        pass
mu.hook_add(UC_HOOK_CODE,hook)
e.call(0x10c470,x0=pt_s,x1=key_s,x8=out_s,timeout=200*1000000)
x0,x2,sp=cap[0]
w,nr=aesref.expand(KEY); sched=bytes(b for wd in w for b in wd)
print("x0=%#x x2=%#x sp=%#x"%(x0,x2,sp))
for tag,base,size in (('stack',STACK,STACK_SZ),('heap',HEAP,HEAP_SZ)):
    mem=bytes(mu.mem_read(base,size))
    for pat,name in ((sched[:16],'enc-sched'),(KEY,'rawkey'),(aesref.SBOX[:16],'sbox')):
        i=mem.find(pat); 
        if i>=0: print(tag,name,"found at",hex(base+i))
mem=bytes(mu.mem_read(sp,0x400))
print("sp dump head:",mem[:0x60].hex())
i=mem.find(sched[:16]); print("sched in sp frame:",hex(i) if i>=0 else None)
# also check x0 frame 0x800 bytes raw
raw=bytes(mu.mem_read(x0,0x600))
print("x0[0:0x40]  ",raw[:0x40].hex())
print("x0[0xb0:0x120]",raw[0xb0:0x120].hex())
print("find sched in x0 struct:",hex(raw.find(sched[:16])) if raw.find(sched[:16])>=0 else None)
print("find rawkey in x0 struct:",hex(raw.find(KEY)))
