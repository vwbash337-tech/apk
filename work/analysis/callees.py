"""List direct callees + data refs of given func indices, with best-effort names."""
import json,sys
fm=json.load(open('analysis/funcmap.json'))
NAMES={}  # addr -> label, filled from known findings
known={0x103ad8:'KEYSCHED_SETUP(#73)',0x10c470:'ECB_ENC(#85)',0x110b70:'ECB_DEC(#94)',
       0x38fa4:'CBC_ZERO(#30)',0x3a838:'F36',0x32158:'F14',0x14193c:'XOR5A_DEC(#193)',
       0x128b0:'setup_Sbox',0x139b0:'setup_RSbox',0x118b0:'setup_Te0',0x129b0:'setup_Td0',
       0x13b10:'setup_rc',0x159c10:'SIGCHK(#226)',0x16bbdc:'PINBLOB(#245)'}
def lbl(a): return known.get(a,f'func#{idx_of(a)}' if (idx_of(a) is not None) else f'0x{a:x}')
starts=[(int(k),int(v['start']),int(v['size'])) for k,v in fm.items()]
starts.sort(key=lambda t:t[1])
def idx_of(a):
    for i,s,z in starts:
        if s<=a<s+z: return i
    return None
for arg in sys.argv[1:]:
    i=int(arg); f=fm[arg]
    print(f"===== func#{i} @0x{int(f['start']):x} size={f['size']} =====")
    for c in f.get('calls',[]):
        t=c[1] if isinstance(c,list) else c
        t=int(t,16) if isinstance(t,str) else t
        print(f"   call @0x{int(c[0],16) if isinstance(c[0],str) else c[0]:x} -> {lbl(t)} (0x{t:x})")
    for r in f.get('data_refs',[]):
        t=r[1] if isinstance(r,list) else r
        t=int(t,16) if isinstance(t,str) else t
        print(f"   data @0x{int(r[0],16) if isinstance(r[0],str) else r[0]:x} -> 0x{t:x}")
