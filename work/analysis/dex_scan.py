from androguard.misc import AnalyzeAPK
import sys, json, re
a,d,dx = AnalyzeAPK('/home/user/apk/TopFollow_v845-Beta.apk')
print("PKG:",a.get_package())
print("minSdk:",a.get_min_sdk_version(),"targetSdk:",a.get_target_sdk_version())
print("app name:",a.get_app_name())
print("\n=== PERMISSIONS ===")
for p in sorted(a.get_permissions()): print("  ",p)
print("\n=== NATIVE LIBRARY DECLARATIONS ===")
for e in a.get_activities()[:0]: pass
print("\n=== classes under com/nivaroid ===")
names=[c.get_name() for c in d[0].get_classes() if 'nivaroid' in c.get_name()]
print(len(names))
for n in sorted(names): print("  ",n)
