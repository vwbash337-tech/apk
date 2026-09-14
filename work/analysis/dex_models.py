from androguard.misc import AnalyzeAPK
a,d,dx=AnalyzeAPK('/home/user/apk/TopFollow_v845-Beta.apk')
dex=d[0]
for cn in ['Lcom/nivaroid/topfollow/models/DeviceModel;','Lcom/nivaroid/topfollow/models/InstagramAccount;','Lcom/nivaroid/topfollow/models/Order;']:
    for c in dex.get_classes():
        if c.get_name()!=cn: continue
        print("="*80); print(cn)
        for f in c.get_fields(): print(f"  FIELD {f.get_access_flags_string():20s} {f.get_descriptor():40s} {f.get_name()}")
        for m in c.get_methods():
            if m.get_access_flags_string().startswith('public') and ('set' in m.get_name() or 'get' in m.get_name()):
                print(f"  METH  {m.get_name()}{m.get_descriptor()}")
