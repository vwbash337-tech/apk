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
    if addr==0x32158 and not cap:
        cap.append((mu.reg_read(UC_ARM64_REG_X0),mu.reg_read(UC_ARM64_REG_X2)))
mu.hook_add(UC_HOOK_CODE,hook)
e.call(0x10c470,x0=pt_s,x1=key_s,x8=out_s,timeout=200*1000000)
x0,x2=cap[0]
raw=bytes(mu.mem_read(x0,0x600))
# locate the key copy
ki=raw.find(KEY)
print("key copy inside struct at +0x%x"%ki)
# find first round word
w,nr=aesref.expand(KEY); sched=bytes(b for wd in w for b in wd)
le=b''.join(sched[i:i+4][::-1] for i in range(0,len(sched),4))
# struct may pad each 16B row; try stride 32 and 16
for stride in (16,32):
    ok=True; got=b''
    for r in range(11):
        seg=raw[ki+ (r*stride):ki+(r*stride)+16]
        got+=seg
    print("stride",stride,"first16",got[:16].hex(),"expect",le[:16].hex(),got[:16]==le[:16])
# precise: scan for the first row
i=raw.find(le[:16])
print("LE round0 found at +0x%x"%i if i>=0 else "not contiguous")
if i>=0:
    rows=[raw[i+32*r:i+32*r+16] for r in range(11)]
    exp=[le[16*r:16*r+16] for r in range(11)]
    print("all 11 rows match with stride 32:",rows==exp)
    rows16=[raw[i+16*r:i+16*r+16] for r in range(11)]
    print("all 11 rows match with stride 16:",rows16==exp)
print("struct +0x00 word:",hex(struct.unpack('<I',raw[:4])[0]))
print("struct +0x20 word:",hex(struct.unpack('<I',raw[0x20:0x24])[0]))
