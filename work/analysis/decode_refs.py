import re,json,collections,base64
data=open('apk_extracted/lib/arm64-v8a/libtopfollow.so','rb').read()
secs=json.load(open('analysis/model_arm64.json'))['sections']
def va2off(va):
    for n,(s) in secs.items():
        if s['addr']<=va<s['addr']+s['size'] and s['off']: return s['off']+(va-s['addr'])
    return None
def cstr(va,maxlen=300):
    o=va2off(va)
    if o is None: return None
    end=data.find(b'\x00',o,o+maxlen)
    if end<0: return None
    s=data[o:end]
    try:
        t=s.decode('utf-8')
        if all(32<=ord(c)<127 for c in t): return t
    except: pass
    return None
rows=json.load(open('analysis/obf_rows.json'))
fm=json.load(open('analysis/funcmap.json'))
b64re=re.compile(r'^[A-Za-z0-9+/]{6,}={0,2}$')
def tryb64(t):
    if not t or not b64re.match(t) or len(t)%4: return None
    try:
        d=base64.b64decode(t)
        s=d.decode('utf-8',errors='strict')
        if all(32<=ord(c)<127 for c in s):
            inner=tryb64(s)
            return (s, inner)
    except: return None
    return None
targets={
 60:"ANTI-TAMPER  (JNI x0015b1e9)",162:"ANTI-FRIDA /proc/maps",225:"MAPS integrity (deleted)",
 169:"access() probe",98:"clock() timing",1074:"dl_iterate_phdr",212:"SHA-256",245:"pin-sha256",
 26:"base64",10:"AES",11:"AES",12:"AES",13:"AES",14:"AES key sched",
 154:"caller of access()",56:"JNI x00120b1e",57:"JNI x0012e5a1",58:"JNI x00135e2a",
 59:"JNI x00105e9b",61:"JNI x0015a3b7",62:"JNI x0017b62c",63:"JNI x0011f42b",
 64:"JNI x0012f5b7",65:"JNI x0014b4f3",66:"JNI x0011f1a2",67:"JNI x0015e49c",
 71:"JNI x00126f7c",72:"JNI x0018d3f7",50:"JNI_OnLoad",
}
for idx in sorted(targets):
    v=fm[str(idx)]
    print(f"\n{'='*90}\nfunc#{idx} @0x{v['start']:x} size={v['size']} insns={v['insns']}  :: {targets[idx]}")
    print(f"  PLT imports used: {v['plt']}")
    strs=[]
    for d in sorted(v['data_refs']):
        s=cstr(d)
        if s and len(s)>=3:
            dec=tryb64(s)
            strs.append((d,s,dec))
    print(f"  --- {len(strs)} decoded string refs ---")
    for d,s,dec in strs:
        line=f"   0x{d:06x}  {s!r}"
        if dec:
            line+=f"\n             b64-> {dec[0]!r}"
            if dec[1]: line+=f"\n             b64-> b64-> {dec[1]!r}"
        print(line)
