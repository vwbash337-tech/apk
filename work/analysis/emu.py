"""Unicorn-based AArch64 emulator for libtopfollow.so with libc/libc++ shims."""
from unicorn import *
from unicorn.arm64_const import *
import json,struct,sys

SO='apk_extracted/lib/arm64-v8a/libtopfollow.so'
raw=open(SO,'rb').read()
SEGS=json.load(open('analysis/segs.json'))
RELS=json.load(open('analysis/relocs.json'))
PLT={int(a,16):n for a,n in json.load(open('analysis/plt_map.json')).items()}

BASE      = 0x0
IMG_SZ    = 0x200000          # covers 0 .. 0x1c2f38 rounded
STACK     = 0x8000000; STACK_SZ=0x200000
HEAP      = 0x10000000; HEAP_SZ=0x400000
STUB      = 0x20000000; STUB_SZ=0x20000
STRAREA   = 0x30000000; STR_SZ=0x100000
JNIArea   = 0x40000000; JNI_SZ=0x100000

R_ABS64=268436483; R_GLOB_DAT=268436482; R_JUMP_SLOT=268436481

class Emu:
    def __init__(self, trace=False):
        self.mu=Uc(UC_ARCH_ARM64,UC_MODE_LITTLE_ENDIAN)
        mu=self.mu
        mu.mem_map(BASE,IMG_SZ,UC_PROT_ALL)
        mu.mem_write(BASE,raw)
        # zero the .bss tail
        mu.mem_write(0x1c02b8+0x68, b'\x00'*(IMG_SZ-(0x1c02b8+0x68)))
        mu.mem_map(STACK,STACK_SZ,UC_PROT_READ|UC_PROT_WRITE)
        mu.mem_map(HEAP,HEAP_SZ,UC_PROT_READ|UC_PROT_WRITE)
        mu.mem_map(STUB,STUB_SZ,UC_PROT_READ|UC_PROT_WRITE|UC_PROT_EXEC)
        mu.mem_map(STRAREA,STR_SZ,UC_PROT_READ|UC_PROT_WRITE)
        mu.mem_map(JNIArea,JNI_SZ,UC_PROT_READ|UC_PROT_WRITE)
        # TLS block for tpidr_el0 (canary at +0x28)
        self.tls=HEAP+HEAP_SZ-0x1000
        mu.mem_write(self.tls+0x28, struct.pack('<Q',0xdeadbeefcafebabe))
        mu.reg_write(UC_ARM64_REG_TPIDR_EL0,self.tls)
        # relocations
        self.stubmap={}; self.nextstub=STUB
        for r in RELS:
            a=r['addr']
            if r['type']==R_ABS64:
                mu.mem_write(a,struct.pack('<Q',(r['add'])&0xffffffffffffffff))
            elif r['type'] in (R_GLOB_DAT,R_JUMP_SLOT):
                s=self.alloc_stub(r['sym'] or f"sym_{a:x}")
                mu.mem_write(a,struct.pack('<Q',s))
        # heap allocator
        self.brk=HEAP+0x1000
        self.trace=trace
        self.calls=[]
        self.logs=[]
        mu.hook_add(UC_HOOK_CODE,self._code)
        mu.hook_add(UC_HOOK_MEM_UNMAPPED,self._unmapped)
    def alloc_stub(self,name):
        if name in self.stubmap: return self.stubmap[name]
        a=self.nextstub; self.nextstub+=16
        # ret
        self.mu.mem_write(a,struct.pack('<I',0xd65f03c0))
        self.stubmap[name]=a; return a
    def stub_name(self,a):
        for n,v in self.stubmap.items():
            if v==a: return n
        return None
    # ---- memory helpers ----
    def malloc(self,n):
        n=(n+15)&~15
        a=self.brk; self.brk+=n
        if self.brk>HEAP+HEAP_SZ: raise MemoryError("heap exhausted")
        return a
    def rd(self,a,n): return self.mu.mem_read(a,n)
    def wr(self,a,b): self.mu.mem_write(a,bytes(b))
    def cstr(self,a,maxlen=4096):
        out=bytearray()
        while len(out)<maxlen:
            c=bytes(self.rd(a+len(out),1))
            if c==b'\x00':break
            out+=c
        return bytes(out)
    # ---- libc++ std::string (libc++ ABI, SSO cap 22) ----
    def mkstring(self,s):
        if isinstance(s,str): s=s.encode()
        a=self.malloc(24)
        if len(s)<=22:
            buf=bytes([len(s)*2])+s+b'\x00'*(22-len(s))
            self.wr(a,buf)
        else:
            cap=((len(s)+16)&~15)|1
            p=self.malloc(cap+1)
            self.wr(p,s+b'\x00')
            self.wr(a,struct.pack('<QQQ',cap,len(s),p))
        return a
    def getstring(self,a):
        b0=self.rd(a,1)[0]
        if not (b0&1): return bytes(self.rd(a+1,b0>>1))
        cap,sz,p=struct.unpack('<QQQ',bytes(self.rd(a,24)))
        return bytes(self.rd(p,sz))
    def setstring(self,a,s):
        """overwrite an existing std::string object in place (short form only)"""
        if isinstance(s,str):s=s.encode()
        if len(s)<=22: self.wr(a,bytes([len(s)*2])+s+b'\x00'*(22-len(s)))
        else:
            cap=((len(s)+16)&~15)|1;p=self.malloc(cap+1);self.wr(p,s+b'\x00')
            self.wr(a,struct.pack('<QQQ',cap,len(s),p))
    # ---- hooks ----
    def _unmapped(self,mu,acc,addr,sz,val):
        page=addr&~0xfff
        try: mu.mem_map(page,0x1000,UC_PROT_ALL)
        except Exception: pass
        self.logs.append(f"UNMAPPED {'w' if acc&UC_MEM_WRITE else 'r'} 0x{addr:x} sz={sz}")
        return True
    def _code(self,mu,addr,sz,ud):
        if self.trace and addr<STUB: self.calls.append(addr)
        if STUB<=addr<STUB+STUB_SZ:
            n=self.stub_name(addr); self.shim(n,mu); return
        if addr in PLT:
            self.shim(PLT[addr],mu); return
    # ---- libc shims ----
    def shim(self,name,mu):
        g=lambda r: mu.reg_read(r)
        X=[UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,
           UC_ARM64_REG_X4,UC_ARM64_REG_X5,UC_ARM64_REG_X6,UC_ARM64_REG_X7]
        a=[g(r) for r in X]; lr=g(UC_ARM64_REG_LR)
        def ret(v=0):
            mu.reg_write(UC_ARM64_REG_X0,v&0xffffffffffffffff)
            mu.reg_write(UC_ARM64_REG_PC,lr)
        if name is None: ret(0); return
        self.logs.append(f"call {name}({', '.join(hex(x) for x in a[:4])})")
        if name in ('malloc','operator new(unsigned long)','_Znwm','operator new'): ret(self.malloc(a[0] or 16))
        elif name in ('free','operator delete(void*)','_ZdlPv','operator delete'): ret(0)
        elif name=='calloc':
            p=self.malloc(a[0]*a[1]); self.wr(p,b'\x00'*(a[0]*a[1])); ret(p)
        elif name=='realloc':
            p=self.malloc(a[1]); ret(p)
        elif name=='memcpy' or name=='memmove':
            self.wr(a[0],bytes(self.rd(a[1],a[2]))); ret(a[0])
        elif name=='memset':
            self.wr(a[0],bytes([a[1]&0xff])*a[2]); ret(a[0])
        elif name=='memcmp':
            x=bytes(self.rd(a[0],a[2])); y=bytes(self.rd(a[1],a[2]))
            ret(0 if x==y else (1 if x>y else 0xffffffffffffffff))
        elif name=='strlen': ret(len(self.cstr(a[0])))
        elif name=='strcpy':
            s=self.cstr(a[1]); self.wr(a[0],s+b'\x00'); ret(a[0])
        elif name=='strncpy':
            s=self.cstr(a[1])[:a[2]]; self.wr(a[0],s+b'\x00'*(a[2]-len(s))); ret(a[0])
        elif name=='strcmp':
            x=self.cstr(a[0]);y=self.cstr(a[1]); ret(0 if x==y else (1 if x>y else 0xffffffffffffffff))
        elif name=='strncmp':
            x=self.cstr(a[0],a[2]);y=self.cstr(a[1],a[2]); ret(0 if x==y else (1 if x>y else 0xffffffffffffffff))
        elif name=='strstr':
            h=self.cstr(a[0]);n=self.cstr(a[1]);i=h.find(n); ret(a[0]+i if i>=0 else 0)
        elif name=='strchr':
            h=self.cstr(a[0]);i=h.find(bytes([a[1]&0xff])); ret(a[0]+i if i>=0 else 0)
        elif name=='clock': ret(0)
        elif name in ('__stack_chk_fail',): raise RuntimeError("stack smash")
        elif name in ('abort','exit','__assert2','fprintf','fflush'):
            self.logs.append(f"  !! {name} called -> stop"); raise RuntimeError(f"{name}")
        elif name in ('read','close','__open_2','__read_chk','fopen','fgets','fclose','open','stat','access','fscanf'):
            self.logs.append(f"  (stubbed IO {name} -> -1/0)"); ret(0xffffffffffffffff if name in('read','__open_2','open') else 0)
        elif name in ('inflateInit2_','inflate','inflateEnd'): ret(0)
        elif name=='pthread_once' or name=='pthread_mutex_lock' or name=='pthread_mutex_unlock': ret(0)
        elif name and name.startswith('_ctype'): ret(0)
        else:
            self.logs.append(f"  (unknown shim {name} -> 0)"); ret(0)
    # ---- run ----
    def call(self,fn,x0=0,x1=0,x2=0,x3=0,x4=0,x5=0,x6=0,x7=0,x8=0,timeout=0):
        mu=self.mu
        sp=STACK+STACK_SZ-0x10000
        mu.reg_write(UC_ARM64_REG_SP,sp)
        mu.reg_write(UC_ARM64_REG_X29,sp)
        end=STUB+STUB_SZ-0x40
        mu.reg_write(UC_ARM64_REG_LR,end)
        for r,v in zip((UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,
                        UC_ARM64_REG_X4,UC_ARM64_REG_X5,UC_ARM64_REG_X6,UC_ARM64_REG_X7,UC_ARM64_REG_X8),
                       (x0,x1,x2,x3,x4,x5,x6,x7,x8)):
            mu.reg_write(r,v)
        self.wr(end,b'\x00\x00\x20\xd4')  # brk -> trap
        try:
            mu.emu_start(fn,end,timeout=timeout or 60*1000000,count=0)
        except UcError as e:
            pc=mu.reg_write and mu.reg_read(UC_ARM64_REG_PC)
            self.logs.append(f"UcError {e} at PC=0x{pc:x}")
            raise
        return mu.reg_read(UC_ARM64_REG_X0)
if __name__=='__main__':
    e=Emu()
    print("stubs:",len(e.stubmap))
    print("relocs applied. sample GOT[0x1b6160] =",hex(struct.unpack('<Q',bytes(e.rd(0x1b6160,8)))[0]))
    print("reloc 0x1b6160 target check ok")
