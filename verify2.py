#!/usr/bin/env python3
"""Independent APK Signature Scheme v2 verifier (spec-exact, written from the
AOSP V2SchemeVerifier / ApkSigningBlockUtils source). Used to cross-check the
ORIGINAL apk (known good, real apksigner output) and my PATCHED apk."""
import struct, hashlib, sys
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography import x509

CHUNK = 1024 * 1024
MAGIC = b'APK Sig Block 42'
V2_ID = 0x7109871a


def u32(b, o):
    return struct.unpack('<I', b[o:o+4])[0]


def u64(b, o):
    return struct.unpack('<Q', b[o:o+8])[0]


def lp_slice(buf, off):
    """Return (payload, next_off) for a uint32-length-prefixed element."""
    n = u32(buf, off)
    return buf[off+4:off+4+n], off+4+n


def chunked_sha256(segments):
    parts = b''
    count = 0
    for seg in segments:
        pos = 0
        while pos < len(seg):
            c = seg[pos:pos+CHUNK]
            pos += len(c)
            parts += hashlib.sha256(b'\xa5' + struct.pack('<I', len(c)) + c).digest()
            count += 1
    return hashlib.sha256(b'\x5a' + struct.pack('<I', count) + parts).digest()


def parse_v2(apk):
    data = open(apk, 'rb').read()
    # EOCD
    pos = data.rfind(b'\x50\x4b\x05\x06')
    if pos < 0:
        return {'err': 'no eocd'}
    cd_size = u32(data, pos+12)
    cd_off = u32(data, pos+16)
    eocd_end = len(data)
    if pos + 22 + u16(data, pos+20) != eocd_end:
        return {'err': 'eocd comment mismatch'}
    # signing block
    mi = cd_off - 16
    if data[mi:mi+16] != MAGIC:
        return {'err': 'no magic'}
    S = u64(data, mi-8)
    block_start = cd_off - (8 + S)
    if u64(data, block_start) != S:
        return {'err': 'size mismatch'}
    # pairs
    p = block_start + 8
    end = mi - 8
    v2 = None
    while p < end:
        ps = u64(data, p); p += 8
        pid = u32(data, p)
        val = data[p+4:p+ps]
        p += ps
        if pid == V2_ID:
            v2 = val
    if v2 is None:
        return {'err': 'no v2 block'}
    # v2: signers
    signers, _ = lp_slice(v2, 0)
    results = []
    so = 0
    while so < len(signers):
        signer, so = lp_slice(signers, so)
        r = {}
        sd, nxt = lp_slice(signer, 0)
        sigs, nxt = lp_slice(signer, nxt)
        pk, nxt = lp_slice(signer, nxt)
        r['signed_data'] = sd
        r['signatures_seq'] = sigs
        r['public_key'] = pk
        # signatures
        r['sig_algs'] = []
        r['sig_bytes'] = []
        x = 0
        while x < len(sigs):
            ent, x = lp_slice(sigs, x)
            alg = u32(ent, 0)
            sb, _ = lp_slice(ent, 4)
            r['sig_algs'].append(alg)
            r['sig_bytes'].append(sb)
        # signed data
        digests, d2 = lp_slice(sd, 0)
        certs, d3 = lp_slice(sd, d2)
        attrs, d4 = lp_slice(sd, d3)
        r['digests_seq'] = digests
        r['certs_seq'] = certs
        r['attrs'] = attrs
        r['digest_algs'] = []
        r['digest_vals'] = []
        y = 0
        while y < len(digests):
            ent, y = lp_slice(digests, y)
            alg = u32(ent, 0)
            dv, _ = lp_slice(ent, 4)
            r['digest_algs'].append(alg)
            r['digest_vals'].append(dv)
        # certs
        r['certs'] = []
        z = 0
        while z < len(certs):
            cd_, z = lp_slice(certs, z)
            r['certs'].append(cd_)
        results.append(r)
    return {'block_start': block_start, 'cd_off': cd_off,
            'cd_size': cd_size, 'eocd_pos': pos, 'signers': results}


def u16(b, o):
    return struct.unpack('<H', b[o:o+2])[0]


def verify(apk):
    data = open(apk, 'rb').read()
    r = parse_v2(apk)
    if 'err' in r:
        return r
    for s in r['signers']:
        # signature over signed_data
        cert_der = s['certs'][0]
        cert = x509.load_der_x509_certificate(cert_der)
        pub = cert.public_key()
        # verify each signature
        for alg, sig in zip(s['sig_algs'], s['sig_bytes']):
            try:
                pub.verify(sig, s['signed_data'], padding.PKCS1v15(), hashes.SHA256())
                s['sig_ok'] = True
            except Exception as e:
                s['sig_ok'] = False
                s['sig_err'] = str(e)
        # digest
        # Per AOSP ApkSigningBlockUtils.verifyIntegrity: the EOCD's central
        # directory offset field is rewritten to point at the start of the APK
        # Signing Block before digesting.
        eocd = bytearray(data[r['eocd_pos']:])
        eocd[16:20] = struct.pack('<I', r['block_start'])
        segments = [data[:r['block_start']],
                    data[r['cd_off']:r['cd_off']+r['cd_size']],
                    bytes(eocd)]
        recomputed = chunked_sha256(segments)
        for alg, dv in zip(s['digest_algs'], s['digest_vals']):
            s['digest_match'] = (dv == recomputed)
            s['recomputed'] = recomputed
        # public key match: encodePublicKey(cert pubkey) == signer pk
        spki = cert.public_key().public_bytes(
            __import__('cryptography.hazmat.primitives.serialization', fromlist=['Encoding']).Encoding.DER,
            __import__('cryptography.hazmat.primitives.serialization', fromlist=['PublicFormat']).PublicFormat.SubjectPublicKeyInfo)
        s['pk_match'] = (spki == s['public_key'])
        s['sig_alg_ids'] = [hex(a) for a in s['sig_algs']]
        s['digest_alg_ids'] = [hex(a) for a in s['digest_algs']]
        s['cert_subject'] = cert.subject.rfc4514_string()
    return r


if __name__ == '__main__':
    for apk in sys.argv[1:]:
        print('=' * 60)
        print(apk)
        r = verify(apk)
        if 'err' in r:
            print('  ERROR:', r['err'])
            continue
        print('  block_start=%d cd_off=%d cd_size=%d eocd=%d' %
              (r['block_start'], r['cd_off'], r['cd_size'], r['eocd_pos']))
        for i, s in enumerate(r['signers']):
            print(f'  signer[{i}]: subject={s["cert_subject"]}')
            print('     sig_alg_ids   :', s['sig_alg_ids'])
            print('     digest_alg_ids:', s['digest_alg_ids'])
            print('     sig_ok        :', s.get('sig_ok'), s.get('sig_err', ''))
            print('     digest_match  :', s.get('digest_match'))
            print('     pk_match      :', s.get('pk_match'))
