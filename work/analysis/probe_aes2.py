import sys, struct, json
sys.path.insert(0,'analysis')
from emu import Emu
funcs=json.load(open('analysis/model_arm64.json'))['functions']
A={i:funcs[i]['start'] for i in range(len(funcs))}

PT=bytes.fromhex('00112233445566778899aabbccddeeff')
K ={16:bytes.fromhex('000102030405060708090a0b0c0d0e0f'), 24:bytes(range(24)), 32:bytes(range(32))}
CT={16:bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a'),
    24:bytes.fromhex('dda97ca4864cdfe06eaf70a0ec0d7191'),
    32:bytes.fromhex('8ea2b7ca516745bfeafc49904b496089')}

def prep(e, keylen):
    skey=e.malloc(0x800); e.wr(skey,b'\x00'*0x800)
    uk=e.malloc(64); e.wr(uk,K[keylen])
    junk=e.malloc(32); e.wr(junk,b'\x00'*32)
    e.call(A[14], x0=skey,x1=uk,x2=junk,x3=keylen,x4=16, timeout=180*1000000)
    nr={16:10,24:12,32:14}[keylen]
    rk=[bytes(e.rd(skey+0xc+32*i,16)).hex() for i in range(nr+1)]
    return skey, rk

def materialise(e, v, keylen):
    if v=='PT':  p=e.malloc(64); e.wr(p,PT+b'\x00'*48); return p,True
    if v=='CT':  p=e.malloc(64); e.wr(p,CT[keylen]+b'\x00'*48); return p,True
    if v=='ZERO':p=e.malloc(64); e.wr(p,b'\x00'*64); return p,True
    if v=='SKEY':return None,False
    return v,False

def run(fnid, sig, keylen):
    e=Emu(); skey,rk=prep(e,keylen)
    regs={}; watch={}
    for i in range(5):
        v=sig.get('x%d'%i, 0)
        if v=='SKEY': regs['x%d'%i]=skey
        else:
            p,w=materialise(e,v,keylen); regs['x%d'%i]=p
            if w: watch['x%d'%i]=p
    try:
        r=e.call(A[fnid], timeout=180*1000000, **regs)
    except Exception as ex:
        return 'CRASH %s'%ex, {}, rk
    return r, {k:bytes(e.rd(p,16)).hex() for k,p in watch.items()}, rk

for fnid in (12,13,9,21):
    for sig in ({'x0':'PT','x1':'SKEY'}, {'x0':'PT','x1':'SKEY','x2':'ZERO'},
                {'x0':'SKEY','x1':'PT'}, {'x0':'CT','x1':'SKEY'}):
        r,outs,rk=run(fnid,sig,16)
        verdict=[]
        for k,v in outs.items():
            if v==CT[16].hex(): verdict.append('%s==CT(ENCRYPT)'%k)
            if v==PT.hex():     verdict.append('%s==PT(identity/DECRYPT-of-CT)'%k)
        print('func#%-3d %-46s ret=%-14s %s %s' % (fnid, json.dumps(sig), (hex(r) if isinstance(r,int) else r)[:14], json.dumps(outs), ' '.join(verdict)))
    print()
