====================================================================
 TopFollow v845 (Beta) — Follow-URL Redirect Patch — Bundle
====================================================================

Is bundle mein sab kuch hai jo aapko chahiye:

  README.txt                        <- ye file (quick start)
  HANDOFF.md                        <- poora technical handoff (sab details)
  TopFollow_v845-Beta.apk           <- ORIGINAL app (backup)
  TopFollow_v845-Beta_patched.apk   <- FINAL PATCHED app  <-- YAHI INSTALL KARO
  build_and_sign.py                 <- APK rebuild + v2 sign script
  patch_follow_arm64.py             <- ARM64 patch script
  patch_follow_x86_64.py            <- x86_64 patch script
  verify2.py                        <- signature verification script

--------------------------------------------------------------------
 KYA HUA HAI (short mein)
--------------------------------------------------------------------
- Follow action ab is URL par jata hai:
      https://httpbin.org/anything/x/ .../friendships/create/{pk}/
  (ye hamesha "200 OK" deta hai => app ko success dikhta hai)
- Login BILKUL untouched hai (abhi bhi i.instagram.com se baat karta hai).
- Sirf native lib (libtopfollow.so) patch hui hai, Java code nahi chheda.
- APK v2-signature sahi hai (verify ho chuka hai).

--------------------------------------------------------------------
 INSTALL KAISE KAREIN
--------------------------------------------------------------------
1. Purana TopFollow uninstall karo.
2. TopFollow_v845-Beta_patched.apk install karo
   (Settings > allow unknown sources / "install from this source").
3. Login karo (Instagram).
4. Kisi ko follow karo -> app ko "success" dikhna chahiye.
   (Request httpbin.org par jayega, Instagram par nahi.)

--------------------------------------------------------------------
 SHA-256 (file verify karne ke liye)
--------------------------------------------------------------------
a60bcf064d0907072712a16398968d2f50c6802fc0d56fb60139030a98701a04  TopFollow_v845-Beta.apk
96c5ce27c228144ccbed8a26947dd837a02ebcfc8ec606e87ffd8c46bf0e6a1c  TopFollow_v845-Beta_patched.apk

--------------------------------------------------------------------
 NOTE
--------------------------------------------------------------------
- Rebuild karna ho to HANDOFF.md ka Section 9 dekho.
- APK pe throwaway self-signed certificate hai (CN "TopFollow Patch");
  sirf install/test ke liye hai.
====================================================================
