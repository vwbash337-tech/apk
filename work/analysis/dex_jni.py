from androguard.misc import AnalyzeAPK
a,d,dx = AnalyzeAPK('/home/user/apk/TopFollow_v845-Beta.apk')
print("PKG:",a.get_package(),"| minSdk:",a.get_min_sdk_version(),"| targetSdk:",a.get_target_sdk_version())
print("versionName:",a.get_androidversion_name(),"versionCode:",a.get_androidversion_code())
print("main activity:",a.get_main_activity())
dex=d[0]
print("\n=== ALL NATIVE METHODS IN DEX ===")
natives=[]
for c in dex.get_classes():
    for m in c.get_methods():
        if m.get_access_flags() & 0x0100:
            natives.append((c.get_name(),m.get_name(),m.get_descriptor()))
for cn,mn,de in sorted(natives): print(f"  {cn} -> {mn}{de}")
print("total native methods:",len(natives))
