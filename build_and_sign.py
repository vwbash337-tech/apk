#!/usr/bin/env python3
"""
Rebuild TopFollow APK with patched native libs and re-sign it with
APK Signature Scheme v2 (only). Reimplements the v2 signing block format
exactly per AOSP apksig (V2SchemeSigner / ApkSigningBlockUtils).

CRITICAL detail (the reason the first attempt was rejected by Android):
the v2 content digest is computed over the EOCD record with its
central-directory-offset field rewritten to point at the START of the APK
Signing Block (see ApkSigningBlockUtils.verifyIntegrity).
"""
import struct, zlib, datetime, sys, os, hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID

ORIG_APK = '/home/user/apk/TopFollow_v845-Beta.apk'
PATCHED_DIR = '/home/user/apk_work/extracted'
OUT_APK = '/home/user/apk/TopFollow_v845-Beta_patched.apk'

V2_BLOCK_ID = 0x7109871a
VERITY_PADDING_BLOCK_ID = 0x42726577
MAGIC = b'APK Sig Block 42'
ALG_RSA_PKCS1_SHA256 = 0x0103
CHUNK_SIZE = 1024 * 1024
PAGE = 4096

PATCHED_FILES = {
    'lib/arm64-v8a/libtopfollow.so': os.path.join(PATCHED_DIR, 'lib/arm64-v8a/libtopfollow.so'),
    'lib/x86/libtopfollow.so': os.path.join(PATCHED_DIR, 'lib/x86/libtopfollow.so'),
    'lib/x86_64/libtopfollow.so': os.path.join(PATCHED_DIR, 'lib/x86_64/libtopfollow.so'),
}


def le(n):
    return struct.pack('<I', n)


def seq_len_prefixed(elements):
    out = bytearray()
    for e in elements:
        out += le(len(e)) + e
    return bytes(out)


def pairs_int_lenprefixed_bytes(pairs):
    out = bytearray()
    for i, b in pairs:
        out += le(8 + len(b)) + le(i) + le(len(b)) + b
    return bytes(out)


def chunked_sha256_digest(segments):
    """CHUNKED-SHA256 (1 MiB chunks) over ordered segments."""
    chunk_digests = b''
    count = 0
    for seg in segments:
        pos = 0
        while pos < len(seg):
            chunk = seg[pos:pos + CHUNK_SIZE]
            pos += len(chunk)
            chunk_digests += hashlib.sha256(b'\xa5' + le(len(chunk)) + chunk).digest()
            count += 1
    return hashlib.sha256(b'\x5a' + le(count) + chunk_digests).digest()


def make_key_and_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'TopFollow Patch'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'TopFollow'),
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'IN'),
    ])
    now = datetime.datetime(2023, 1, 1)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(datetime.datetime(2048, 1, 1))
        .sign(key, hashes.SHA256())
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return key, cert_der, spki


def build_aligned_zip():
    import zipfile
    zf = zipfile.ZipFile(ORIG_APK)
    entries = []
    for info in zf.infolist():
        if info.filename in PATCHED_FILES:
            data = open(PATCHED_FILES[info.filename], 'rb').read()
        else:
            data = zf.read(info.filename)
        entries.append((info.filename, data, info.compress_type))
    zf.close()

    out = bytearray()
    central = []
    dostime = 0
    dosdate = ((2023 - 1980) << 9) | (1 << 5) | 1
    for name, data, method in entries:
        name_b = name.encode('utf-8')
        if method == 8:
            co = zlib.compressobj(9, zlib.DEFLATED, -15)
            cdata = co.compress(data) + co.flush()
        else:
            cdata = data
        crc = zlib.crc32(data) & 0xffffffff
        if method == 0:
            align = PAGE if name.endswith('.so') else 4
            hdr_off = len(out)
            pad = (-(hdr_off + 30 + len(name_b))) % align
            extra = b'\x00' * pad
        else:
            extra = b''
        ver_needed = 20 if method == 8 else 10
        hdr_off = len(out)
        out += struct.pack('<IHHHHHIIIHH',
            0x04034b50, ver_needed, 0, method,
            dostime, dosdate, crc, len(cdata), len(data),
            len(name_b), len(extra))
        out += name_b + extra + cdata
        central.append((name_b, method, crc, len(cdata), len(data), extra, hdr_off))
    cd = bytearray()
    for name_b, method, crc, csize, usize, extra, hdr_off in central:
        ver_needed = 20 if method == 8 else 10
        cd += struct.pack('<IHHHHHHIIIHHHHHII',
            0x02014b50, 0x031e, ver_needed, 0, method,
            dostime, dosdate, crc, csize, usize,
            len(name_b), len(extra), 0, 0, 0, (0o100644 << 16), hdr_off)
        cd += name_b + extra
    return bytes(out), bytes(cd), len(central)


def build_signing_block(v2_value):
    pair = struct.pack('<Q', 4 + len(v2_value)) + le(V2_BLOCK_ID) + v2_value
    result_size = 8 + len(pair) + 8 + 16
    padding_pair = b''
    if result_size % PAGE != 0:
        pad = PAGE - (result_size % PAGE)
        if pad < 12:
            pad += PAGE
        padding_pair = struct.pack('<Q', pad - 8) + le(VERITY_PADDING_BLOCK_ID) + b'\x00' * (pad - 12)
        result_size += pad
    block = struct.pack('<Q', result_size - 8)
    block += pair
    block += padding_pair
    block += struct.pack('<Q', result_size - 8)
    block += MAGIC
    return block, result_size


def make_eocd(n_entries, cd_size, cd_offset):
    return struct.pack('<IHHHHIIH', 0x06054b50, 0, 0, n_entries, n_entries,
                       cd_size, cd_offset, 0)


def main():
    key, cert_der, spki = make_key_and_cert()
    before_cd, cd, n_entries = build_aligned_zip()

    # signing block size (independent of the content digest; deterministic for
    # a fixed key/cert since digest and signature lengths are fixed)
    digests_el = pairs_int_lenprefixed_bytes([(ALG_RSA_PKCS1_SHA256, b'\x00' * 32)])
    certs_el = seq_len_prefixed([cert_der])
    sd = seq_len_prefixed([digests_el, certs_el, b'', b''])
    sigs_el = pairs_int_lenprefixed_bytes([(ALG_RSA_PKCS1_SHA256, b'\x00' * 256)])
    signer = seq_len_prefixed([sd, sigs_el, spki])
    v2_value = seq_len_prefixed([seq_len_prefixed([signer])])
    block, block_size = build_signing_block(v2_value)

    block_start = len(before_cd)
    cd_offset = block_start + block_size
    real_eocd = make_eocd(n_entries, len(cd), cd_offset)

    # v2 content digest: EOCD with central-directory offset rewritten to the
    # start of the signing block.
    modified_eocd = bytearray(real_eocd)
    modified_eocd[16:20] = le(block_start)
    content_digest = chunked_sha256_digest([before_cd, cd, bytes(modified_eocd)])

    # rebuild signed data with the real digest and sign
    digests_el = pairs_int_lenprefixed_bytes([(ALG_RSA_PKCS1_SHA256, content_digest)])
    sd = seq_len_prefixed([digests_el, certs_el, b'', b''])
    sig = key.sign(sd, padding.PKCS1v15(), hashes.SHA256())
    assert len(sig) == 256
    sigs_el = pairs_int_lenprefixed_bytes([(ALG_RSA_PKCS1_SHA256, sig)])
    signer = seq_len_prefixed([sd, sigs_el, spki])
    v2_value = seq_len_prefixed([seq_len_prefixed([signer])])
    block, block_size2 = build_signing_block(v2_value)
    assert block_size2 == block_size, "signing block size changed!"

    final = before_cd + block + cd + real_eocd
    open(OUT_APK, 'wb').write(final)
    print("Wrote", OUT_APK, "size", len(final))
    print("  entries:", n_entries, " signing block size:", block_size)
    print("  block_start:", block_start, " cd_offset:", cd_offset)
    print("  content digest:", content_digest.hex())


if __name__ == '__main__':
    main()
