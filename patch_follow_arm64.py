#!/usr/bin/env python3
"""
Surgical follow-URL redirect for libtopfollow.so (arm64-v8a).

Strategy:
  - The native "base URL builder" (fn @ 0x16ab6c) hard-codes the shared
    i.instagram.com/api/v1/ base string @ 0x1762c. It is called by:
       * q.h (Order->String, action-URL builder) @ 5 sites  -> follow/like/comment URLs
       * q.l (Retrofit factory) @ 2 sites                    -> login/API Retrofit base
  - We overwrite the base-builder with a stub that decodes an httpbin URL
    (redirecting the action URLs), and place a second stub at 0x16ab7c that
    decodes the ORIGINAL i.instagram base. q.l's two call sites are retargeted
    to the second stub so login keeps talking to Instagram.
  - This leaves 0x1762c untouched (login intact) and redirects follow (+ other
    auto-actions) to https://httpbin.org/anything/x/ .../friendships/create/{pk}/
"""
import struct, sys

HTTPBIN_PLAIN = b"https://httpbin.org/anything/x/"   # 31 bytes
assert len(HTTPBIN_PLAIN) == 31
XOR_KEY = 0x55
HTTPBIN_ENC = bytes(b ^ XOR_KEY for b in HTTPBIN_PLAIN)

# locations (arm64, VA == file offset for .text/.rodata)
STR_HTTPBIN = 0x1aa83
STUB_HTTPBIN = 0x16ab6c   # overwrite original base-URL builder
STUB_ORIG    = 0x16ab7c   # new: decode original i.instagram base @0x1762c
QL_CALL_1    = 0x10268c   # bl 0x16ab6c  ->  bl 0x16ab7c
QL_CALL_2    = 0x102724   # bl 0x16ab6c  ->  bl 0x16ab7c
DECODE_HELPER = 0x109e44

def adrp(rd, target_page, pc):
    imm = ((target_page - (pc & ~0xfff)) >> 12) & 0x1fffff
    immhi = (imm >> 2) & 0x7ffff
    immlo = imm & 0x3
    return (1 << 31) | (immlo << 29) | (0x10 << 24) | (immhi << 5) | rd

def add_imm(rd, rn, imm12):
    return (0x91 << 24) | ((imm12 & 0xfff) << 10) | (rn << 5) | rd

def b(target, pc):
    imm = ((target - pc) >> 2) & 0x3ffffff
    return (0x5 << 26) | imm

def bl(target, pc):
    imm = ((target - pc) >> 2) & 0x3ffffff
    return (0x25 << 26) | imm

def build_stub(str_addr, pc):
    words = [
        adrp(0, str_addr & ~0xfff, pc),
        add_imm(0, 0, str_addr & 0xfff),
        0x528003e1,          # mov w1, #0x1f  (len 31)
        b(DECODE_HELPER, pc + 12),
    ]
    return words

def main(path):
    data = bytearray(open(path, 'rb').read())

    # 1) write encrypted httpbin string
    assert data[STR_HTTPBIN:STR_HTTPBIN+31] == b'\x00'*31, "string slot not empty!"
    data[STR_HTTPBIN:STR_HTTPBIN+31] = HTTPBIN_ENC

    # 2) overwrite base-builder with httpbin stub
    hw = build_stub(STR_HTTPBIN, STUB_HTTPBIN)
    data[STUB_HTTPBIN:STUB_HTTPBIN+16] = b''.join(struct.pack('<I', w) for w in hw)

    # 3) place orig stub right after
    ow = build_stub(0x1762c, STUB_ORIG)
    data[STUB_ORIG:STUB_ORIG+16] = b''.join(struct.pack('<I', w) for w in ow)

    # 4) retarget q.l call sites
    data[QL_CALL_1:QL_CALL_1+4] = struct.pack('<I', bl(STUB_ORIG, QL_CALL_1))
    data[QL_CALL_2:QL_CALL_2+4] = struct.pack('<I', bl(STUB_ORIG, QL_CALL_2))

    open(path, 'wb').write(bytes(data))
    print(f"patched {path}")

if __name__ == '__main__':
    main(sys.argv[1])
