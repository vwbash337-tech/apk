import sys, struct, json
sys.path.insert(0,'analysis')
from emu import Emu
funcs=json.load(open('analysis/model_arm64.json'))['functions']
A={i:funcs[i]['start'] for i in range(len(funcs))}
CTORS=[0x3896c, 0x178188]

PT=bytes.fromhex('00112233445566778899aabbccddeeff')
K ={16:bytes.fromhex('000102030405060708090a0b0c0d0e0f'), 24:bytes(range(24)), 32:bytes(range(32))}
CT={16:bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a'),
    24:bytes.fromhex('dda97ca4864cdfe06eaf70a0ec0d7191'),
    32:bytes.fromhex('8ea2b7ca516745bfeafc49904b496089')}

def new(ctors=True):
    e=Emu()
    if ctors:
        for c in CTORS:
            try: e.call(c, timeout=60*1000000)
            except Exception as ex: print('  ctor 0x%x raised %s' % (c, ex))
    return e

print('=== .bss CFF globals after running the 2 .init_array ctors ===')
e0=Emu(); e1=new()
for a in (0x1c28a0,0x1c2d2c,0x1c2510,0x1c1d10):
    v0=struct.unpack('<Q',bytes(e0.rd(a,8)))[0]; v1=struct.unpack('<Q',bytes(e1.rd(a,8)))[0]
    print('  0x%x : before=0x%016x  after=0x%016x' % (a,v0,v1))

def prep(e, keylen):
    skey=e.malloc(0x800); e.wr(skey,b'\x00'*0x800)
    uk=e.malloc(64); e.wr(uk,K[keylen]); junk=e.malloc(32); e.wr(junk,b'\x00'*32)
    e.call(A[14], x0=skey,x1=uk,x2=junk,x3=keylen,x4=16, timeout=180*1000000)
    nr={16:10,24:12,32:14}[keylen]
    rk=[bytes(e.rd(skey+0xc+32*i,16)).hex() for i in range(nr+1)]
    return skey,rk

def run(fnid, sig, keylen):
    e=new(); skey,rk=prep(e,keylen)
    regs={}; watch={}
    for i in range(5):
        v=sig.get('x%d'%i,0)
        if v=='SKEY': regs['x%d'%i]=skey; continue
        if v=='PT':  p=e.malloc(64); e.wr(p,PT+b'\x00'*48)
        elif v=='CT':p=e.malloc(64); e.wr(p,CT[keylen]+b'\x00'*48)
        elif v=='ZERO':p=e.malloc(64); e.wr(p,b'\x00'*64)
        else: p=v
        regs['x%d'%i]=p; watch['x%d'%i]=p
    try: r=e.call(A[fnid], timeout=180*1000000, **regs)
    except Exception as ex: return 'CRASH %s'%ex, {}, rk
    return r, {k:bytes(e.rd(p,16)).hex() for k,p in watch.items()}, rk

print()
print('=== FIPS-197 KAT with ctors run first ===')
for fnid in (12,13,10,11,9):
    for keylen in (16,24,32):
        r,o1,_=run(fnid,{'x0':'PT','x1':'SKEY'},keylen)
        r2,o2,_=run(fnid,{'x0':'CT','x1':'SKEY'},keylen)
        d1='ENCRYPT' if (isinstance(o1.get('x0'),str) and o1.get('x0')==CT[keylen].hex()) else ''
        d2='DECRYPT' if (isinstance(o2.get('x0'),str) and o2.get('x0')==PT.hex()) else ''
        print('  func#%-3d AES-%-3d  PT->%s %-8s | CT->%s %-8s' % (fnid,keylen*8,
              str(o1.get('x0'))[:32], d1, str(o2.get('x0'))[:32], d2))
    print()
