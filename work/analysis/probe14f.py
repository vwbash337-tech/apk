import sys,struct
sys.path.insert(0,'analysis')
from emu import Emu
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *
import aesref
e=Emu(); mu=e.mu
out={}
for KEY,exp_nr in ((b'0123456789abcdef',10),(b'At91IxVnRSbFppV0',12),(b'0'*32,14)):
    pass
def run(KEY,PT):
    e2=Emu(); m=e2.mu
    pt_s=e2.mkstring(PT); key_s=e2.mkstring(KEY); out_s=e2.mkstring(b'')
    cap=[]
    def hook(mu,addr,sz,ud):
        if addr==0x32158 and not cap: cap.append(mu.reg_read(UC_ARM64_REG_X0))
    m.hook_add(UC_HOOK_CODE,hook)
    r=e2.call(0x10c470,x0=pt_s,x1=key_s,x8=out_s,timeout=200*1000000)
    x0=cap[0]; raw=bytes(m.mem_read(x0,0x400))
    w,nr=aesref.expand(KEY); sched=bytes(b for wd in w for b in wd)
    le=b''.join(sched[i:i+4][::-1] for i in range(0,len(sched),4))
    i=raw.find(le[:16])
    rows=[raw[i+32*r:i+32*r+16] for r in range(nr+1)]
    exp=[le[16*r:16*r+16] for r in range(nr+1)]
    print("key=%-34s len=%2d  Nr_field@+0x08=%d  eK@+0x%x stride32 rows=%d match=%s"%(
        KEY.decode()[:34],len(KEY),struct.unpack('<I',raw[8:12])[0],i,nr+1,rows==exp))
    print("   func#85 out:",e2.getstring(out_s).decode())
    print("   reference  :",aesref.ecb(PT,KEY).hex())
run(b'0123456789abcdef',b'hello')
run(bytes.fromhex('000102030405060708090a0b0c0d0e0f1011121314151617'),b'A'*16)
run(bytes(range(32)),b'The quick brown fox jumps over the lazy dog')
