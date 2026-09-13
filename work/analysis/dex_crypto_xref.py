from androguard.misc import AnalyzeAPK
import re
a,d,dx=AnalyzeAPK('/home/user/apk/TopFollow_v845-Beta.apk')
TARGETS=['AES/GCM/NoPadding','RSA/ECB/PKCS1PADDING','AES','RSA','SHA-256','SHA-1','MD5','secret_key','secret_key_2fa','captcha_key','captcha_stamp']
print("=== who references each crypto string ===")
for t in TARGETS:
    print(f"\n----- {t!r} -----")
    try:
        for s in dx.find_strings(t):
            s0=s.get_value()
            if s0!=t: continue
            xrefs=list(s.get_xref_from())
            if not xrefs: print("   (no xref)"); continue
            for cls,meth,_ in xrefs[:12]:
                print(f"   {meth.get_class_name()}->{meth.get_name()}{meth.get_descriptor()}")
    except Exception as e:
        print("   err",e)
