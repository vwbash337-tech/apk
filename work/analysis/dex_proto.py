from androguard.misc import AnalyzeAPK
import re,sys
a,d,dx=AnalyzeAPK('/home/user/apk/TopFollow_v845-Beta.apk')
dex=d[0]
S=list(dex.get_strings())
def dump(title,pred,limit=400):
    print("\n"+"#"*90); print("###",title); print("#"*90)
    hits=sorted({s for s in S if pred(s)})
    print(f"  count={len(hits)}")
    for s in hits[:limit]: print("   |",repr(s))
EP=re.compile(r'^[a-z0-9_][a-z0-9_/\.\-]{3,90}/$')
dump("INSTAGRAM API ENDPOINT PATHS (trailing slash)", lambda s: EP.match(s) and not s.startswith('http') and ' ' not in s and 'android' not in s and 'com/' not in s and 'res/' not in s)
dump("X-IG / HTTP HEADERS", lambda s: re.match(r'^(x-ig|x-graphql|X-IG|X-Ig|user-agent|User-Agent|authorization|Authorization|content-type|Content-Type|accept|cookie|ig-|X-FB|X-Meta)',s))
dump("BACKEND HOSTS / URLs", lambda s: re.search(r'(nivafollower|topfollow-apk|nivaroid|b\.i\.instagram|i\.instagram\.com|instagram\.com)',s) and len(s)<200)
dump("SECRETKEY / CRYPTO-ish JAVA STRINGS", lambda s: re.match(r'^(AES|DES|RSA|HmacSHA|PBKDF|SHA-|MD5|AES/|PBEWith|Cipher|SecretKey|javax\.crypto|java\.security|Base64|secret|api_key|apikey|app_key|salt|iv$|IV$|key$)',s) or re.search(r'(AES/|DES/|RSA/|HmacSHA|PBKDF2|PBEWith|/CBC/|/ECB/|/GCM/|/PKCS5|/NoPadding|javax\.crypto)',s))
dump("APP-OWN JSON FIELD NAMES (snake_case)", lambda s: re.match(r'^[a-z][a-z0-9]*(_[a-z0-9]+)+$',s) and len(s)<40)
print("\n"+"#"*90); print("### SecretKey model fields"); print("#"*90)
for c in dex.get_classes():
    if c.get_name()=='Lcom/nivaroid/topfollow/models/SecretKey;':
        for f in c.get_fields(): print("  FIELD",f.get_access_flags_string(),f.get_descriptor(),f.get_name())
        for m in c.get_methods(): print("  METH ",m.get_name()+m.get_descriptor())
print("\n### InstagramReqInfo / BaseResponse / GetOrderResponse fields")
for cn in ('Lcom/nivaroid/topfollow/models/InstagramReqInfo;','Lcom/nivaroid/topfollow/models/BaseResponse;','Lcom/nivaroid/topfollow/models/GetOrderResponse;','Lcom/nivaroid/topfollow/models/AppInfo;','Lcom/nivaroid/topfollow/models/BaseInfo;'):
    for c in dex.get_classes():
        if c.get_name()==cn:
            print(" --",cn)
            for f in c.get_fields(): print("    ",f.get_descriptor(),f.get_name())
