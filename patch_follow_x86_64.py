#!/usr/bin/env python3
"""Surgical follow redirect for libtopfollow.so (x86_64).
The base-URL builder is inlined: each call site does
   lea rsi,[rip+disp]  (src = 0x12930 base string)
   ... rdi=dest; mov edx,0x1f; call decode(0xc8be0)
q.h (action URLs) has 5 such sites; q.l (login Retrofit) has 2.
Redirect the 5 q.h sites to a new httpbin string; leave q.l on original.
"""
import struct, sys

HTTPBIN_PLAIN = b"https://httpbin.org/anything/x/"   # 31 bytes
XOR_KEY = 0x55
HTTPBIN_ENC = bytes(b ^ XOR_KEY for b in HTTPBIN_PLAIN)

STR_HTTPBIN = 0x13489
QH_SITES = [0xb04d1, 0xb0617, 0xb06ad, 0xb0704, 0xb0759]
ORIG_BASE = 0x12930

def main(path):
    data = bytearray(open(path,'rb').read())

    # verify each site currently points at ORIG_BASE
    for site in QH_SITES:
        disp = struct.unpack_from('<i', data, site+3)[0]
        tgt = site + 7 + disp
        assert tgt == ORIG_BASE, f"site {site:#x} -> {tgt:#x}, expected {ORIG_BASE:#x}"

    # write httpbin string
    assert data[STR_HTTPBIN:STR_HTTPBIN+31] == b'\x00'*31
    data[STR_HTTPBIN:STR_HTTPBIN+31] = HTTPBIN_ENC

    # retarget the 5 q.h lea displacements
    for site in QH_SITES:
        disp = STR_HTTPBIN - (site + 7)
        struct.pack_into('<i', data, site+3, disp)

    open(path,'wb').write(bytes(data))
    print("patched", path)

if __name__ == '__main__':
    main(sys.argv[1])
