from androguard.misc import AnalyzeAPK
import re
a,d,dx=AnalyzeAPK('/home/user/apk/TopFollow_v845-Beta.apk')
dex=d[0]
print("=== classes under com/nivaroid (non-obfuscated names) ===")
names=[]
for c in dex.get_classes():
    n=c.get_name()
    if n.startswith('Lcom/nivaroid/'): names.append(n)
for n in sorted(names): print("  ",n)
print("\n=== Retrofit @POST/@GET/@FormUrlEncoded annotations + endpoint strings ===")
for c in dex.get_classes():
    n=c.get_name()
    if not n.startswith('Lcom/nivaroid/'): continue
    for m in c.get_methods():
        ann=m.get_annotations() if hasattr(m,'get_annotations') else None
    # class-level string constants
print("\n=== all string constants in com/nivaroid classes (URL-ish / header-ish) ===")
pat=re.compile(r'(https?://|/[a-z_]+/v\d|X-IG|User-Agent|Content-Type|application/|Authorization|Bearer|header|Header|POST|GET|api/v\d|graphql|instagram|topfollow|\.com|\.ir|\.net|\.org)',re.I)
found=set()
for c in dex.get_classes():
    n=c.get_name()
    if not n.startswith('Lcom/nivaroid/'): continue
    for m in c.get_methods():
        try: code=m.get_code()
        except Exception: continue
        if code is None: continue
        try:
            for _,call,arg in m.get_xref_from(): pass
        except Exception: pass
        try:
            src=m.get_source()
        except Exception:
            src=None
