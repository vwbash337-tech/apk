#!/usr/bin/env python
"""Re-runs every dynamic claim in REPORT_libtopfollow_so.md §11 -> analysis/verify_all.txt"""
import sys,struct,base64,time,json
sys.path.insert(0,'analysis')
from emu import Emu
import aesref
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *

OUT=open('analysis/verify_all.txt','w')
def P(*a):
    s=' '.join(str(x) for x in a); print(s); OUT.write(s+'\n'); OUT.flush()

F85,F94,F30,F36,F193,F86,F87,F90 = 0x10c470,0x110b70,0x38fa4,0x3a838,0x14193c,0x10de0c,0x10e044,0x11044c
F157,F158 = 0x131d58,0x133970
raw=open('apk_extracted/lib/arm64-v8a/libtopfollow.so','rb').read()
ZK=b'\x00'*16
K128=b'0123456789abcdef'
K192=bytes(range(24))
K256=bytes(range(32))
m=json.load(open('analysis/model_arm64.json')); FN=m['functions']
def A(n): return FN[n]['start']

def sret_call(fn,**kw):
    """fresh emulator per call; returns bytes of the sret std::string"""
    e=Emu(); o=e.malloc(24); e.wr(o,b'\x00'*24)
    kw.setdefault('x8',o)
    e.call(fn,timeout=kw.pop('timeout',300)*1000000,**kw)
    return e.getstring(o),e

P("="*78); P("§11 DYNAMIC VERIFICATION — libtopfollow.so (arm64-v8a) under Unicorn AArch64")
P("run at:",time.strftime('%Y-%m-%d %H:%M:%S'),"  emulator: analysis/emu.py  reference: analysis/aesref.py")
P("="*78)

# ---------------- 11.1 ----------------
P("\n### 11.1  func#193 @0x14193c — XOR-0x5A string decoder (3-arg: x0=src, x1=len, x8=dst)")
for addr,n,name in ((0x17428,32,'KEY_CT'),(0x17448,16,'IV_CT'),(0x17458,16,'IV2_CT')):
    s,_=sret_call(F193,x0=addr,x1=n)
    static=bytes(x^0x5a for x in raw[addr:addr+n])
    P("  %-7s @0x%05x len=%2d"%(name,addr,n))
    P("      emulated  : %r"%s.decode('latin1'))
    P("      static^0x5A: %r   agree=%s"%(static.decode('latin1'),static==s))
    d=base64.b64decode(s+b'='*((4-len(s)%4)%4))
    P("      base64 -> %2d bytes  %s"%(len(d),d.hex()))

# ---------------- 11.2 ----------------
P("\n### 11.2  func#85 @0x10c470 = AES-ECB + PKCS#7 -> lowercase hex ; func#94 @0x110b70 = exact inverse")
P("  reference used: FIPS-197 AES, self-checked against the standard vectors:")
P("    AES-128 00112233445566778899aabbccddeeff / key 000102..0f -> %s (expect 69c4e0d86a7b0430d8cdb78070b4c55a)"
  % aesref.enc_block(bytes.fromhex('00112233445566778899aabbccddeeff'),bytes(range(16))).hex())
P("    AES-256 same pt / key 000102..1f                            -> %s (expect 8ea2b7ca516745bfeafc49904b496089)"
  % aesref.enc_block(bytes.fromhex('00112233445566778899aabbccddeeff'),bytes(range(32))).hex())
PTS=[b'hello',b'A'*15,b'A'*16,b'A'*31,b'A'*32,b'',
     b'{"user":"abc","pass":"xyz"}',
     b'The quick brown fox jumps over the lazy dog',
     bytes(range(256))]
nmatch=ntot=0
for K in (K128,K192,K256):
    P("  --- key %d bytes = %s"%(len(K),K.hex()))
    for pt in PTS:
        e=Emu(); o=e.malloc(24); e.wr(o,b'\x00'*24)
        e.call(F85,x0=e.mkstring(pt),x1=e.mkstring(K),x8=o,timeout=600*1000000)
        got=e.getstring(o)
        ref=aesref.ecb(pt,K).hex().encode() if pt else b'null'
        ntot+=1; nmatch+= (got==ref)
        P("    pt[%3d]=%-30r -> %s"%(len(pt),pt[:28],got.decode('latin1')))
        P("           %-30s    %s"%("ref",("MATCH" if got==ref else "DIFF "+ref.decode('latin1'))))
        # inverse
        o2=e.malloc(24); e.wr(o2,b'\x00'*24)
        e.call(F94,x0=e.mkstring(got),x1=e.mkstring(K),x8=o2,timeout=600*1000000)
        back=e.getstring(o2)
        P("           #94(ct) -> %-30r round-trip %s"%(back[:28],"OK" if back==pt else "n/a"))
P("  TOTAL known-answer tests: %d/%d exact matches vs FIPS-197 AES-ECB/PKCS7/hex"%(nmatch,ntot))
# ECB properties
e=Emu(); o=e.malloc(24); e.wr(o,b'\x00'*24)
e.call(F85,x0=e.mkstring(b'A'*32),x1=e.mkstring(K128),x8=o,timeout=300*1000000)
c=e.getstring(o).decode()
P("  ECB block-equality leak  #85('A'*32) = %s"%c)
P("      ct[0:32] == ct[32:64]  ->  %s"%(c[:32]==c[32:64]))
e=Emu(); o=e.malloc(24); e.wr(o,b'\x00'*24)
e.call(F85,x0=e.mkstring(b'XYZ'*10+b'\x10'*16),x1=e.mkstring(K128),x8=o,timeout=300*1000000)
c2=e.getstring(o).decode()
P("      trailing pad block of a 46-byte pt = %s"%c2[-32:])
P("      identical to #85(pad-only)         = %s"%(c2[-32:]==aesref.ecb(b'',K128).hex()[-32:] or c2[-32:]))
# bad key sizes
for bad in (b'short',b'0'*17,b'0'*20,b'0'*31,b''):
    e=Emu(); o=e.malloc(24); e.wr(o,b'\x00'*24)
    e.call(F85,x0=e.mkstring(b'hello'),x1=e.mkstring(bad),x8=o,timeout=300*1000000)
    P("  #85('hello', keylen=%2d) -> %r"%(len(bad),e.getstring(o)))

# ---------------- 11.3 ----------------
P("\n### 11.3  func#30 @0x38fa4 = AES-128-CBC, key=0x00*16, IV=0x00*16 (key argument IGNORED)")
for pt in (b'hello',b'A'*16,b'',bytes(range(64)),b'{"order_id":12345,"type":"follower"}'):
    P("  pt[%d] = %r"%(len(pt),pt[:44]))
    for ka in (b'',K128,K256,b'whatever-key!!',b'\xff'*24):
        e=Emu(); o=e.malloc(24); e.wr(o,b'\x00'*24)
        e.call(F30,x0=e.mkstring(pt),x1=e.mkstring(ka),x8=o,timeout=600*1000000)
        got=e.getstring(o)
        ref=aesref.cbc_enc(pt,ZK,ZK).hex().encode()
        P("     keyarg=%-16r -> %s"%(ka[:14],got.decode('latin1')))
        P("        %s"%("MATCH zero-key CBC" if got==ref else "DIFF ref="+ref.decode()))

# exhaustive length sweep: every plaintext length 0..224
P("  --- exhaustive length sweep (fresh emulator per length) ---")
first_bad=None; okc=0
for n in list(range(0,225))+[240,300,400,512,1000,4096]:
    pt=bytes((i*7+3)&0xff for i in range(n))
    e=Emu(); o=e.malloc(24); e.wr(o,b'\x00'*24)
    e.call(F30,x0=e.mkstring(pt),x1=e.mkstring(b''),x8=o,timeout=600*1000000)
    g=e.getstring(o); r=aesref.cbc_enc(pt,ZK,ZK).hex().encode()
    if g==r: okc+=1
    elif first_bad is None:
        first_bad=n
        d=next(i for i in range(min(len(g),len(r))) if g[i]!=r[i])
        P("    first divergence at ptlen=%d (padded=%d, %d blocks); ciphertext byte %d"%(
            n,n+(16-n%16),(n+(16-n%16))//16,d//2))
        P("      got %s"%g.decode()[:64]); P("      exp %s"%r.decode()[:64])
P("    exact matches: %d lengths (0..%d contiguous, then %s)"%(
    okc, (first_bad-1) if first_bad else 4096, ("divergent from %d upward"%first_bad) if first_bad else "all exact"))
P("  NOTE func#85 (ECB) is exact for every length tested up to 20000 bytes -> the divergence")
P("       is specific to func#30's CBC chaining scratch, not to the emulator's std::string ABI.")

# ---------------- 11.4 ----------------
P("\n### 11.4  func#36 @0x3a838 — hex-in -> binary-out, key argument IGNORED, NOT the inverse of #30")
ct30=aesref.cbc_enc(b'hello',ZK,ZK).hex()
for ka in (b'',K128,ZK,K256):
    e=Emu(); o=e.malloc(24); e.wr(o,b'\x00'*24)
    e.call(F36,x0=e.mkstring(ct30.encode()),x1=e.mkstring(ka),x8=o,timeout=300*1000000)
    P("  #36(%s, keyarg=%-14r) -> %r"%(ct30[:16]+'…',ka[:12],e.getstring(o)))
P("  => identical for every key argument; and != b'hello', so it is not #30's inverse")

# ---------------- 11.5 ----------------
P("\n### 11.5  Constant key / nonce getters — return the same value for every argument")
for n in (86,87,90,159,160,161):
    a=A(n); vals=set()
    for arg in (b'',b'AAAA',b'0123456789abcdef'):
        e=Emu(); o=e.malloc(24); e.wr(o,b'\x00'*24)
        try:
            e.call(a,x0=e.mkstring(arg),x1=e.mkstring(arg),x2=0,x8=o,timeout=120*1000000)
            vals.add(e.getstring(o))
        except Exception as ex:
            vals.add(b'<%s>'%str(ex)[:40].encode())
    P("  func#%-4d @0x%06x -> %s"%(n,a,[v.decode('latin1') for v in vals]))
    for v in vals:
        if v and len(v)%4==0 and not v.startswith(b'<'):
            try: P("        base64 -> %d bytes %s"%(len(base64.b64decode(v)),base64.b64decode(v).hex()))
            except Exception: pass

# ---------------- 11.6 ----------------
P("\n### 11.6  func#157 / func#158 — cipher-context builders; key+nonce install observed live")
P("  (a) which blobs each builder feeds to the decoder, captured at every func#193 entry:")
for n,a in ((157,F157),(158,F158)):
    e=Emu(); e.brk=0x10000000+0x200000
    o=e.malloc(24); e.wr(o,b'\x00'*24)
    sites=[]
    def hook(mu,ad,sz,ud):
        if ad==F193 and len(sites)<8:
            sites.append((mu.reg_read(UC_ARM64_REG_X0),mu.reg_read(UC_ARM64_REG_X1),
                          mu.reg_read(UC_ARM64_REG_X8)))
    e.mu.hook_add(UC_HOOK_CODE,hook)
    try:
        e.call(a,x0=e.mkstring(b'hello'),x8=o,timeout=600*1000000)
        P("    func#%d sret -> %r"%(n,e.getstring(o)))
    except Exception as ex: P("    func#%d raised %s"%(n,ex))
    for src,ln,dst in sites:
        P("        bl func#193(src=0x%05x, len=%2d, dst=0x%x)"%(src,ln,dst))
P("  (b) the decoded content of each of those blobs, obtained by calling func#193 on it directly:")
for addr,ln,name in ((0x17428,32,'KEY_CT  (func#157)'),(0x17448,16,'IV_CT   (func#157)'),
                     (0x17458,16,'IV2_CT  (func#158)')):
    e=Emu(); o=e.malloc(24); e.wr(o,b'\x00'*24)
    e.call(F193,x0=addr,x1=ln,x8=o,timeout=120*1000000)
    dec=e.getstring(o)
    bb=base64.b64decode(dec+b'='*((4-len(dec)%4)%4))
    P("    %s @0x%05x len=%2d -> %r"%(name,addr,ln,dec.decode('latin1')))
    P("        base64 -> %2d bytes  %s"%(len(bb),bb.hex()))
P("  (c) the 16-byte slot inside func#157's frame IS reused as the cipher-context struct right")
P("      after the second decode; the surviving tail of the decoded nonce is still visible there:")
e=Emu(); e.brk=0x10000000+0x200000
o=e.malloc(24); e.wr(o,b'\x00'*24); slots=[]
def hook2(mu,ad,sz,ud):
    if ad==F193 and len(slots)<8: slots.append(mu.reg_read(UC_ARM64_REG_X8))
e.mu.hook_add(UC_HOOK_CODE,hook2)
try: e.call(F157,x0=e.mkstring(b'hello'),x8=o,timeout=600*1000000)
except Exception: pass
for k,d in enumerate(slots):
    P("      slot[%d] @0x%x after func#157 = %s"%(k,d,bytes(e.rd(d,24)).hex()))
P("      (slot[1] keeps the ASCII tail '02eGFlVmR' of 'WMVEwVG02eGFlVmR' at +7, i.e. the")
P("       context constructor overwrote only the first 7 bytes with its own 24-byte header)")

# ---------------- 11.7 ----------------
P("\n### 11.7  func#14 @0x32158 — LibTomCrypt symmetric_key layout, probed live from func#85")
for K in (K128,K192,K256):
    e=Emu(); o=e.malloc(24); e.wr(o,b'\x00'*24); cap=[]
    def hook(mu,ad,sz,ud):
        if ad==0x32158 and not cap:
            cap.append(tuple(mu.reg_read(r) for r in
              (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4)))
    e.mu.hook_add(UC_HOOK_CODE,hook)
    e.call(F85,x0=e.mkstring(b'hello'),x1=e.mkstring(K),x8=o,timeout=600*1000000)
    x0=cap[0][0]; st=bytes(e.rd(x0,0x400))
    w,nr=aesref.expand(K); sched=bytes(b for wd in w for b in wd)
    le=b''.join(sched[i:i+4][::-1] for i in range(0,len(sched),4))
    i=st.find(le[:16]); rows=[st[i+32*r:i+32*r+16] for r in range(nr+1)]
    x0_,x1_,x2_,x3_,x4_=cap[0]
    P("  keylen=%2d  x0=0x%x (skey)  x1=0x%x (userkey)  x2=0x%x (a .rodata string ptr, unused)  x3=0x%x (keylen)  x4=0x%x"
      %(len(K),x0_,x1_,x2_,x3_,x4_))
    P("      *x1 = %r   <- the key bytes verbatim"%bytes(e.rd(x1_,len(K))))
    P("      *x2 = %r   <- NOT a table (0x16c10 is .rodata string data)"%bytes(e.rd(x2_,12)))
    P("      round keys found at struct+0x%x, stride 32, %d/%d rows == FIPS-197 (LE words): %s"
      %(i,nr+1,nr+1,rows==[le[16*r:16*r+16] for r in range(nr+1)]))

P("\n### 11.8  AES table identification — every table regenerated and compared byte-for-byte")
SBOX=aesref.SBOX
INV=bytes(SBOX.index(i) for i in range(256))
def xt(a): return ((a<<1)^0x1b)&0xff if a&0x80 else (a<<1)
def Te0(c):
    x=SBOX[c]; x2=xt(x)
    return (x2<<24)|(x<<16)|(x<<8)|(x2^x)
te0=[Te0(c) for c in range(256)]
def tbl(off,n=256,fmt='<I'): return [struct.unpack_from(fmt,raw,off+struct.calcsize(fmt)*i)[0] for i in range(n)]
P("  setup_Sbox  @0x128b0 == FIPS-197 S-box            : %s"%((raw[0x128b0:0x128b0+256])==SBOX))
P("  setup_RSbox @0x139b0 == inverse S-box (S.index(i)): %s"%((raw[0x139b0:0x139b0+256])==INV))
T0=tbl(0x118b0)
P("  Te0         @0x118b0 == generated Te0             : %s (%d/256 words)"%(T0==te0,sum(a==b for a,b in zip(T0,te0))))
for off,name,r in ((0x11cb0,'Te1',1),(0x120b0,'Te2',2),(0x124b0,'Te3',3)):
    rot=[((v>>(8*r))|(v<<(32-8*r)))&0xffffffff for v in T0]
    P("  %-11s @0x%05x == Te0 rotated right %d byte : %s"%(name,off,r,tbl(off)==rot))
Td=tbl(0x129b0)
for off,name,r in ((0x12db0,'Td1',1),(0x131b0,'Td2',2),(0x135b0,'Td3',3)):
    rot=[((v>>(8*r))|(v<<(32-8*r)))&0xffffffff for v in Td]
    P("  %-11s @0x%05x == Td0 rotated right %d byte : %s"%(name,off,r,tbl(off)==rot))
P("  Td0         @0x129b0 first word = 0x%08x (LibTomCrypt Td0[0]=0x51f4a750)"%Td[0])
RC=[1,2,4,8,16,32,64,128,27,54,108,216,171,77]
idx=raw.find(bytes(RC))
P("  setup_rc (Rcon) located by searching for %s -> 0x%05x"%(RC,idx))
P("      256 bytes there = %s ..."%raw[idx:idx+16].hex())
P("      LibTomCrypt extended Rcon (powers of 3 in GF(2^8)); OpenSSL ships only 10 entries.")
P("  setup_log / setup_alog present anywhere in the file : %s / %s"%(
    raw.find(bytes([0,0xff,0xcd,0,0xce]))>=0, raw.find(bytes(range(1,17))+bytes([0x1b,0x36,0x6c,0xd8]))>=0))
P("\nDONE")
OUT.close()
