import sys,struct
sys.path.insert(0,'analysis')
from emu import Emu
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *
import aesref
e=Emu(); mu=e.mu
KEY=b'0123456789abcdef'; PT=b'hello'
pt_s=e.mkstring(PT); key_s=e.mkstring(KEY); out_s=e.mkstring(b'')
cap=[]
def hook(mu,addr,sz,ud):
    if addr==0x32158 and len(cap)<2:
        cap.append((mu.reg_read(UC_ARM64_REG_X0),mu.reg_read(UC_ARM64_REG_X2)))
mu.hook_add(UC_HOOK_CODE,hook)
e.call(0x10c470,x0=pt_s,x1=key_s,x8=out_s,timeout=200*1000000)
w,nr=aesref.expand(KEY); sched=bytes(b for wd in w for b in wd)
print("cap",[(hex(a),hex(b)) for a,b in cap])
for x0,x2 in cap:
    for base,tag in ((x0,'x0'),(x2,'x2')):
        try: mem=bytes(mu.mem_read(base,0x800))
        except Exception as ex: print(tag,"unreadable",ex); continue
        i=mem.find(sched[:16])
        print(tag,hex(base),"find sched[:16] ->",hex(i) if i>=0 else None,
              "| find key ->",hex(mem.find(KEY)) if mem.find(KEY)>=0 else None)
        if i>=0:
            print("   full:",mem[i:i+176]==sched)
            print("   head:",mem[:0x30].hex())
