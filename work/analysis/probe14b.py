import sys,struct,json
sys.path.insert(0,'analysis')
from emu import Emu
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *
import aesref

e=Emu(); mu=e.mu
KEY=b'0123456789abcdef'; PT=b'hello'
pt_s=e.mkstring(PT); key_s=e.mkstring(KEY); out_s=e.mkstring(b'')
scheds=[]
def hook(mu,addr,sz,ud):
    if addr==0x32158 and len(scheds)<3:
        x0=mu.reg_read(UC_ARM64_REG_X0); x2=mu.reg_read(UC_ARM64_REG_X2)
        scheds.append((x0,x2))
mu.hook_add(UC_HOOK_CODE,hook)
e.call(0x10c470,x0=pt_s,x1=key_s,x8=out_s,timeout=200*1000000)
w,nr=aesref.expand(KEY)
sched=bytes(b for word in w for b in word)
for x0,x2 in scheds:
    for base,tag in ((x0,'x0'),(x2,'x2')):
        for off in range(0,0x80,4):
            try: mem=bytes(mu.mem_read(base+off,176))
            except Exception: continue
            if mem[:32]==sched[:32]:
                print("MATCH struct=%s off=0x%x full176=%s"%(tag,off,mem==sched))
                print("  Nr/rounds field candidates:",
                      [ (o,struct.unpack('<I',bytes(mu.mem_read(base+o,4)))[0]) for o in range(0,0x30,4)])
                break
