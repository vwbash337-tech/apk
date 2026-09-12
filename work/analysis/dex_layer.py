from androguard.misc import AnalyzeAPK
import re
a,d,dx=AnalyzeAPK('/home/user/apk/TopFollow_v845-Beta.apk')
dex=d[0]
want=['Lcom/nivaroid/topfollow/helper/q;','Lcom/nivaroid/topfollow/helper/T;',
      'Lcom/nivaroid/topfollow/helper/a0;','Lcom/nivaroid/topfollow/application/G;',
      'Lcom/nivaroid/topfollow/db/MyDatabase;']
for cn in want:
    for c in dex.get_classes():
        if c.get_name()!=cn: continue
        print("="*100)
        print("CLASS",cn,"access=",c.get_access_flags_string())
        print("  super:",c.get_superclassname())
        for f in c.get_fields(): print(f"   FIELD {f.get_access_flags_string():24s} {f.get_descriptor()} {f.get_name()}")
        for m in c.get_methods():
            print(f"   METHOD {m.get_access_flags_string():24s} {m.get_name()}{m.get_descriptor()}")
