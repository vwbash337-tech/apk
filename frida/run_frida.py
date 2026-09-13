#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_frida.py — topfollow_agent.js / topfollow_capture.js chalane wala runner
============================================================================

Gadget (non-rooted) aur frida-server (rooted) dono ke saath kaam karta hai.

Do script hain, `--script` se chuno:

    agent    (default) topfollow_agent.js  — bypass + self-test + offline decrypt
    capture            topfollow_capture.js — sirf dekhna, kuch change nahi karta:
                        poora AES chain, string layer, JNI_OnLoad, 22 natives,
                        okhttp3/retrofit2 request+response, JSONL file mein

Sabse aam istemaal
------------------
    # repackaged APK phone par install hai, gadget `on_load: wait` par hai:
    python3 frida/run_frida.py

    # sirf self-test chalao aur nikal jao (offsets aur AES vectors verify):
    python3 frida/run_frida.py --rpc selftest

    # capture kiya hua ciphertext offline decrypt karo (phone ki zaroorat nahi):
    python3 frida/run_frida.py --offline-decrypt 9834ed518cbc8fbe9af3c6ecb75eb8c0

    # sab kuch JSON mein save karo:
    python3 frida/run_frida.py --save capture.json

    # read-only capture script chalao (bypass nahi, sirf observe):
    python3 frida/run_frida.py --script capture
    python3 frida/run_frida.py --script capture --rpc calibrate
    python3 frida/run_frida.py --script capture --set captureAesLayer=true

REPL commands — `--script capture` ke extra exports
---------------------------------------------------
    cfg / stats / tail / find / flush / dumpAll
    strings <n>         func#17/#21/#23 se nikle saare runtime strings
    nestedStrings <n>   4-layer Base64 decode chain, live
    keyschedule <n>     func#14 ke round keys (return ke BAAD padhe gaye)
    cbc <n>             func#15/#16 CBC enc/dec, ctx + IV chaining
    blocks <n>          func#10..#13 ke per-block AES events
    regNatives          JNI_OnLoad ka live RegisterNatives table (VM jaisa dekhta hai)
    onload / jniMap / blobs

REPL commands (script ke rpc.exports par jaate hain)
----------------------------------------------------
    help                sab commands
    config              agent ka CONFIG
    module              libtopfollow.so ka base/size/path
    selftest            26 known-answer vectors (AES + signature pin + .rodata)
    calibrate           live JNI table vs static recovery (22 entries)
    secrets             XOR-0x5A se decode hue saare strings
    keys                rijndael_setup (func#14) ko diye gaye saare AES keys
    crypto              func#85/#94/#30/#36 ke saare encrypt/decrypt, pt+key+ct
    jni                 22 natives ke saare Java-side calls
    detect              detection functions ke hits (maps/frida/root/timing)
    notes               agent ke notes/warnings
    knownkeys           hardcoded key material jo humein pehle se pata hai
    signature           APK-signature pin ka poora hisaab (§6.5)
    vectors             report §11 ke vectors, abhi dobara compute karke
    decrypt <hex>       offline decrypt: func#30 zero-key CBC, phir ECB/CBC
                        har known key ke saath
    decrypt <hex> <key> ek specific ASCII key ke saath
    xordecode <off> <len> [key]   live .rodata blob ko XOR-decode karo
    read <off> <len>    live module se raw hex padho
    clear               sab buffers khaali karo
    dump                upar ke sab lists ek saath (JSON)
    quit / exit
"""
import argparse
import asyncio
import binascii
import json
import os
import sys
import time

try:
    import frida
except ImportError:
    sys.exit("frida chahiye:  pip install frida      (yahan 17.18.0 tested hai)")

HERE = os.path.dirname(os.path.abspath(__file__))
AGENT = os.path.join(HERE, 'topfollow_agent.js')
CAPTURE = os.path.join(HERE, 'topfollow_capture.js')
SCRIPT_CHOICES = {'agent': AGENT, 'capture': CAPTURE}

MODE_PRESETS = {
    # mode : extra CONFIG overrides
    'recon':  {'stubDetection': False, 'sslUnpin': False, 'spoofSignature': False},
    'crypto': {'stubDetection': False},
    'bypass': {'stubDetection': True},
    'all':    {'stubDetection': True},
}

BANNER = r"""
================================================================================
 run_frida.py  —  libtopfollow.so live instrumentation
 mode=%(mode)s   device=%(device)s   target=%(target)s
 agent=%(agent)s
 type 'help' for the RPC command list
================================================================================
"""


def log(m):
    print(m, flush=True)


# --------------------------------------------------------------------------- #
#  message handling
# --------------------------------------------------------------------------- #
class Sink:
    def __init__(self, path=None):
        self.records = []
        self.path = path

    def on_message(self, message, data):
        if message.get('type') == 'send':
            p = message.get('payload', {})
            self.records.append(p)
            tag = str(p.get('tag', '?'))
            body = {k: v for k, v in p.items() if k not in ('tag', 'ts')}
            log('  [%s] %s' % (tag, json.dumps(body, ensure_ascii=False, default=str)))
        elif message.get('type') == 'error':
            log('  [AGENT ERROR] %s' % message.get('description'))
            for line in (message.get('stack') or '').splitlines()[:8]:
                log('        ' + line)
        else:
            log('  [msg] %s' % json.dumps(message, default=str))

    def save(self, extra=None):
        if not self.path:
            return
        doc = {'savedAt': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
               'frida': frida.__version__,
               'records': self.records}
        if extra:
            doc.update(extra)
        with open(self.path, 'w', encoding='utf-8') as f:
            json.dump(doc, f, indent=2, ensure_ascii=False, default=str)
        log('\n[saved] %s  (%d records, %d bytes)'
            % (self.path, len(self.records), os.path.getsize(self.path)))


# --------------------------------------------------------------------------- #
#  offline (no device) helpers — the agent's pure JS runs under Node instead
# --------------------------------------------------------------------------- #
def offline_decrypt(hexstr, key=None):
    """Decrypt without a phone by driving the agent's JS under Node.
       Falls back to a small built-in AES if Node is unavailable."""
    import shutil
    import subprocess
    node = shutil.which('node')
    if node:
        runner = os.path.join(HERE, '_offline_decrypt.js')
        with open(runner, 'w', encoding='utf-8') as f:
            f.write('''
/* generated by run_frida.py — loads topfollow_agent.js under Node with the
   Frida API stubbed out and calls rpc.exports.decrypt(). The agent's own
   console output is silenced so stdout carries ONLY the JSON result. */
const fs = require('fs'), vm = require('vm');
const SRC = fs.readFileSync(process.argv[2], 'utf8');
const SILENT = { log() {}, warn() {}, error() {}, info() {} };
const stubPtr = () => ({ _v: 0, add() { return this; }, sub() { return this; },
  and() { return this; }, shr() { return this; }, isNull: () => true,
  compare: () => 0, toInt32: () => 0, toString: () => '0x0',
  readU8: () => 0, readU32: () => 0, readPointer: () => stubPtr(),
  readByteArray: () => new ArrayBuffer(0), readUtf8String: () => '',
  readCString: () => '', writeU8() {}, writeUtf8String() {}, writeByteArray() {} });
const sb = {
  console: SILENT, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, Math, JSON,
  Object, Array, String, Number, BigInt, parseInt, RegExp, Error,
  TOPFOLLOW_NO_AUTOBOOT: true,
  ptr: stubPtr,
  Process: { findModuleByName: () => null, findModuleByAddress: () => null,
             arch: 'arm64', platform: 'android', pointerSize: 8, pageSize: 4096, id: 0 },
  Module: { findExportByName: () => null, enumerate: () => [] },
  Interceptor: { attach() {}, replace() {}, detachAll() {} },
  NativeFunction: function () { return () => {}; },
  NativeCallback: function () { return stubPtr(); },
  Memory: { alloc: () => stubPtr(), protect() {} },
  Thread: { backtrace: () => [] }, Backtracer: { FUZZY: 0, ACCURATE: 1 },
  DebugSymbol: { fromAddress: a => ({ toString: () => String(a) }) },
  Frida: { version: 'offline-node' },
  Java: { available: false, perform() {}, use() { throw new Error('no java'); },
          registerClass: () => ({ $new: () => ({}) }) },
  rpc: { exports: {} }, hexdump: () => '',
  setTimeout, setInterval, clearInterval, clearTimeout
};
vm.createContext(sb);
vm.runInContext(SRC, sb, { filename: 'topfollow_agent.js' });
const out = sb.rpc.exports.decrypt(process.argv[3], process.argv[4] || undefined, true);
process.stdout.write(JSON.stringify(out));
''')
        try:
            r = subprocess.run([node, runner, AGENT, hexstr, key or ''],
                               capture_output=True, text=True, timeout=120)
            os.remove(runner)
            if r.returncode == 0 and r.stdout.strip():
                return json.loads(r.stdout)
            log('  [warn] node runner failed: %s' % (r.stderr.strip()[-400:] or r.returncode))
        except Exception as e:
            log('  [warn] node runner exception: %s' % e)
    log('  [warn] node nahi mila — built-in mini-AES use ho raha hai '
        '(sirf func#30 zero-key CBC aur func#85 ECB, plaintext key ke saath)')
    return _mini_decrypt(hexstr, key)


def _mini_decrypt(hexstr, key=None):
    """Tiny self-contained AES so `--offline-decrypt` works with zero deps.
       The S-box is COMPUTED (multiplicative inverse in GF(2^8) + the affine
       map) instead of transcribed, so it cannot suffer a copy typo. It is
       asserted against two FIPS-197 sample values below."""
    def _gmul(x, y):
        r = 0
        while y:
            if y & 1:
                r ^= x
            x <<= 1
            if x & 0x100:
                x ^= 0x11b
            y >>= 1
        return r & 0xff

    def _inv(x):
        if x == 0:
            return 0
        for i in range(1, 256):
            if _gmul(x, i) == 1:
                return i
        return 0

    SBOX = []
    for i in range(256):
        b = _inv(i)
        r = b
        for k in range(4):
            r ^= ((b << (k + 1)) | (b >> (7 - k))) & 0xff
        SBOX.append((r ^ 0x63) & 0xff)
    assert SBOX[0x00] == 0x63 and SBOX[0x53] == 0xed and SBOX[0xff] == 0x16, 'S-box build failed'
    RSBOX = [0] * 256
    for i, v in enumerate(SBOX):
        RSBOX[v] = i
    RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8]

    def xt(a):
        a <<= 1
        return (a ^ 0x1b) & 0xff if a & 0x100 else a

    def gmul(x, k):
        r = 0
        for i in range(7, -1, -1):
            r = xt(r)
            if (k >> i) & 1:
                r ^= x
        return r & 0xff

    def expand(key):
        nk = len(key) // 4
        nr = nk + 6
        w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        for i in range(nk, 4 * (nr + 1)):
            t = list(w[i - 1])
            if i % nk == 0:
                t = t[1:] + t[:1]
                t = [SBOX[b] for b in t]
                t[0] ^= RCON[i // nk - 1]
            elif nk > 6 and i % nk == 4:
                t = [SBOX[b] for b in t]
            w.append([w[i - nk][j] ^ t[j] for j in range(4)])
        return w, nr

    def dec_block(ct, w, nr):
        s = [[0] * 4 for _ in range(4)]
        for c in range(4):
            for r in range(4):
                s[r][c] = ct[r + 4 * c]

        def addrk(rnd):
            for c in range(4):
                for r in range(4):
                    s[r][c] ^= w[rnd * 4 + c][r]
        addrk(nr)
        for rnd in range(nr - 1, -1, -1):
            for r in range(1, 4):
                s[r] = s[r][4 - r:] + s[r][:4 - r]
            for r in range(4):
                for c in range(4):
                    s[r][c] = RSBOX[s[r][c]]
            addrk(rnd)
            if rnd:
                for c in range(4):
                    a = [s[r][c] for r in range(4)]
                    s[0][c] = gmul(a[0], 14) ^ gmul(a[1], 11) ^ gmul(a[2], 13) ^ gmul(a[3], 9)
                    s[1][c] = gmul(a[0], 9) ^ gmul(a[1], 14) ^ gmul(a[2], 11) ^ gmul(a[3], 13)
                    s[2][c] = gmul(a[0], 13) ^ gmul(a[1], 9) ^ gmul(a[2], 14) ^ gmul(a[3], 11)
                    s[3][c] = gmul(a[0], 11) ^ gmul(a[1], 13) ^ gmul(a[2], 9) ^ gmul(a[3], 14)
        return [s[r][c] for c in range(4) for r in range(4)]

    ct = list(binascii.unhexlify(hexstr.replace(' ', '')))
    out = []
    keys = []
    if key:
        keys.append(('user-supplied', list(key.encode())))
    keys += [('plaintext .rodata key @0x161ca', list(b'0123456789abcdef')),
             ('AES-128 zero key (func#30)', [0] * 16),
             ('func#157 AES-192 key @0x17428',
              list(binascii.unhexlify('02df752315674526c5a695745313457544a7a654d6e4e340')))]

    def txt(b):
        try:
            s = bytes(b).decode('utf-8')
            if all((32 <= ord(c) < 127) or c in '\n\r\t' for c in s):
                return s
            return None
        except Exception:
            return None

    # func#30: zero-key zero-iv CBC
    w, nr = expand([0] * 16)
    prev = [0] * 16
    pt = []
    for i in range(0, len(ct), 16):
        blk = ct[i:i + 16]
        if len(blk) < 16:
            break
        d = dec_block(blk, w, nr)
        pt += [d[j] ^ prev[j] for j in range(16)]
        prev = blk
    n = pt[-1] if pt else 0
    padok = 1 <= n <= 16 and pt[-n:] == [n] * n
    out.append({'cipher': 'func#30 AES-128-CBC key=0 iv=0', 'key': 'AES-128 zero key',
                'paddingOk': padok, 'text': txt(pt[:-n] if padok else pt)})
    for name, k in keys:
        if len(k) not in (16, 24, 32):
            continue
        w, nr = expand(k)
        pt = []
        for i in range(0, len(ct), 16):
            blk = ct[i:i + 16]
            if len(blk) < 16:
                break
            pt += dec_block(blk, w, nr)
        n = pt[-1] if pt else 0
        padok = 1 <= n <= 16 and pt[-n:] == [n] * n
        out.append({'cipher': 'func#85 AES-ECB PKCS7', 'key': name, 'keyLen': len(k),
                    'paddingOk': padok, 'text': txt(pt[:-n] if padok else pt)})
    return [o for o in out if o['paddingOk'] and o['text']] or out


# --------------------------------------------------------------------------- #
#  device / session
# --------------------------------------------------------------------------- #
def get_device(kind, host):
    if kind == 'local':
        return frida.get_local_device()
    if kind == 'remote':
        mgr = frida.get_device_manager()
        return mgr.add_remote_device(host or '127.0.0.1:27042')
    try:
        return frida.get_usb_device(timeout=15)
    except Exception as e:
        sys.exit('USB device nahi mila (%s).\n'
                 '  * Gadget build hai to:  adb forward tcp:27042 tcp:27042  karke\n'
                 '                          --device remote --host 127.0.0.1:27042\n'
                 '  * frida-server (root) hai to:  adb shell su -c /data/local/tmp/frida-server &' % e)


async def pick_session(device, name, package, spawn, timeout):
    if package:
        if spawn:
            log('[spawn] %s' % package)
            pid = await device.spawn([package])
            session = await device.attach(pid)
            return session, pid, True
        log('[attach] package %s' % package)
        session = await device.attach(package)
        return session, session.pid, False
    log('[attach] name %r  (timeout %ss)' % (name, timeout))
    t0 = time.time()
    last = None
    while time.time() - t0 < timeout:
        try:
            session = await device.attach(name)
            return session, session.pid, False
        except frida.ProcessNotFoundError as e:
            last = e
            procs = await device.enumerate_processes()
            cand = [p.name for p in procs if 'gadget' in p.name.lower()
                    or 'topfollow' in p.name.lower() or 'frida' in p.name.lower()]
            if cand and (time.time() - t0) % 10 < 1.2:
                log('  abhi tak yeh dikhe: %s' % cand)
            await asyncio.sleep(0.7)
    sys.exit('process %r nahi mila (%s).\n'
             '  App ko phone par KHUD launch kijiye — gadget `on_load: wait` par\n'
             '  process ko rok kar rakhta hai, tab yeh runner attach kar leta hai.\n'
             '  `frida-ps -U` se naam confirm kar lijiye.' % (name, last))


# --------------------------------------------------------------------------- #
#  REPL
# --------------------------------------------------------------------------- #
SIMPLE = {
    'config': 'config', 'module': 'module', 'secrets': 'secrets', 'keys': 'keys',
    'crypto': 'crypto', 'jni': 'jni', 'detect': 'detect', 'notes': 'notes',
    'knownkeys': 'known_keys', 'signature': 'signature', 'vectors': 'vectors',
    'clear': 'clear',
}

HELP = """
  config | module | selftest | calibrate | secrets | keys | crypto | jni |
  detect | notes | knownkeys | signature | vectors | dump | clear
  decrypt <hex> [key]        xordecode <off> <len> [key]     read <off> <len>
  raw <expr>                 e.g.  raw crypto()   /  raw knownKeys()
  quit
"""


async def repl(script, sink):
    ex = script.exports          # frida-python 17: this IS the sync exports object
    try:
        avail = script.list_exports_sync()
    except Exception:
        avail = []
    loop = asyncio.get_event_loop()
    log('[rpc] %d exports: %s' % (len(avail), ', '.join(sorted(avail))))

    async def call(fn, *args):
        return await loop.run_in_executor(None, lambda: fn(*args))

    log('\nready. ' + HELP)
    while True:
        try:
            line = (await loop.run_in_executor(None, lambda: input('tf> '))).strip()
        except (EOFError, KeyboardInterrupt):
            log('')
            break
        if not line:
            continue
        if line in ('quit', 'exit', 'q'):
            break
        if line == 'help':
            log(HELP)
            continue
        parts = line.split(None, 1)
        cmd, rest = parts[0].lower(), (parts[1] if len(parts) > 1 else '')
        try:
            if cmd == 'decrypt':
                a = rest.split(None, 1)
                if not a or not a[0]:
                    log('  usage: decrypt <hexstring> [asciiKey]')
                    continue
                r = await call(ex.decrypt, a[0], a[1] if len(a) > 1 else None)
                hits = [x for x in r if x.get('paddingOk') and x.get('text')]
                log('  %d candidates, %d plausible' % (len(r), len(hits)))
                for x in (hits or r):
                    log('   * %-40s key=%-38s pad=%s%s\n     text=%r'
                        % (x.get('cipher'), str(x.get('key'))[:38], x.get('paddingOk'),
                           '  GUESS' if x.get('guessed') else '', x.get('text', x.get('error'))))
            elif cmd in ('xordecode', 'read'):
                nums = [int(t, 0) for t in rest.split()]
                if not nums:
                    log('  usage: %s <offset> <len> [xorKey]' % cmd)
                    continue
                fn = ex.xor_decode if cmd == 'xordecode' else ex.read
                if cmd == 'xordecode':
                    r = await call(fn, nums[0], nums[1], nums[2] if len(nums) > 2 else None)
                else:
                    r = await call(fn, nums[0], nums[1])
                log(json.dumps(r, indent=2, ensure_ascii=False, default=str))
            elif cmd == 'raw':
                r = await loop.run_in_executor(None, lambda: eval(rest, {'ex': ex}))  # noqa: S307
                log(json.dumps(r, indent=2, ensure_ascii=False, default=str))
            elif cmd == 'dump':
                r = {}
                for k in ('config', 'module', 'secrets', 'keys', 'crypto', 'jni',
                          'detect', 'notes', 'knownKeys', 'signature', 'vectors'):
                    try:
                        r[k] = await call(getattr(ex, k[0].lower() + k[1:]))
                    except Exception as e:
                        r[k] = '<%s>' % e
                log(json.dumps(r, indent=2, ensure_ascii=False, default=str)[:20000])
                sink.records.append({'tag': 'DUMP', 'data': r})
            elif cmd in ('selftest', 'calibrate'):
                fn = ex.self_test if cmd == 'selftest' else ex.self_calibrate
                r = await call(fn)
                if cmd == 'selftest':
                    log('  allOk=%s passed=%s failed=%s skipped=%s'
                        % (r.get('allOk'), r.get('passed'), len(r.get('failed') or []),
                           r.get('skipped')))
                    for f in (r.get('failed') or []):
                        log('    FAIL %s\n         got    %s\n         expect %s'
                            % (f.get('what'), f.get('got'), f.get('expect')))
                else:
                    log('  ok=%s matched=%s/%s' % (r.get('ok'), r.get('matched'), r.get('total')))
                    for e in (r.get('table') or []):
                        if e.get('expect') and (e.get('expect', {}).get('name') != e.get('name')
                                                or e.get('expect', {}).get('off') != e.get('off')):
                            log('    MISMATCH #%s live=%s@%s expect=%s@%s'
                                % (e.get('i'), e.get('name'), e.get('off'),
                                   e['expect'].get('name'), e['expect'].get('off')))
                sink.records.append({'tag': cmd.upper(), 'data': r})
            elif cmd in SIMPLE:
                fn = getattr(ex, SIMPLE[cmd], None)
                if fn is None:
                    log('  [error] agent mein %r export nahi hai' % SIMPLE[cmd])
                    continue
                r = await call(fn)
                log(json.dumps(r, indent=2, ensure_ascii=False, default=str)[:20000])
                if cmd != 'clear':
                    sink.records.append({'tag': cmd.upper(), 'data': r})
            else:
                log('  unknown command %r — try: help' % cmd)
        except Exception as e:
            log('  [error] %s: %s' % (type(e).__name__, e))
    return


# --------------------------------------------------------------------------- #
async def run(args):
    with open(args.script, 'r', encoding='utf-8') as f:
        src = f.read()

    cfg = dict(MODE_PRESETS.get(args.mode, {}))
    cfg['mode'] = args.mode
    cfg['maxDump'] = args.max_dump
    cfg['quiet'] = args.quiet
    for kv in args.set or []:
        k, v = kv.split('=', 1)
        cfg[k] = json.loads(v)
    runtime = 'const globalThis_TF = 1; globalThis.TF_CONFIG = %s;\n' % json.dumps(cfg)
    log(BANNER % {'mode': args.mode, 'device': args.device,
                  'target': args.package or args.name, 'agent': args.script})
    log('[config] %s' % json.dumps(cfg))

    device = get_device(args.device, args.host)
    log('[device] %s (%s)' % (device.name, device.type))

    session, pid, spawned = await pick_session(device, args.name, args.package,
                                               args.spawn, args.timeout)
    log('[session] pid=%d spawned=%s' % (pid, spawned))
    session.on('detached', lambda reason, crash: log('\n[DETACHED] %s %s' % (reason, crash or '')))

    sink = Sink(args.save)
    script = await session.create_script(runtime + src)
    script.on('message', sink.on_message)
    await script.load()
    if spawned:
        await device.resume(pid)
        log('[resumed] %d' % pid)

    if args.rpc:
        await asyncio.sleep(args.wait)
        ex = script.exports
        name = args.rpc.replace('-', '_')
        name = {'selftest': 'self_test', 'calibrate': 'self_calibrate',
                'knownkeys': 'known_keys', 'xordecode': 'xor_decode'}.get(name, name)
        a = list(args.arg or [])
        coerced = []
        for x in a:
            try:
                coerced.append(int(x, 0))
            except ValueError:
                coerced.append(x)
        r = getattr(ex, name)(*coerced)
        print(json.dumps(r, indent=2, ensure_ascii=False, default=str))
        sink.save({'rpc': args.rpc, 'result': r})
        await script.unload()
        return

    await asyncio.sleep(args.wait)
    await repl(script, sink)
    sink.save()
    try:
        await script.unload()
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--mode', default='crypto', choices=sorted(MODE_PRESETS))
    ap.add_argument('--script', default=AGENT,
                    help='inject hone wala JS: %s (default: agent), ya koi bhi '
                         'path. "capture" = topfollow_capture.js'
                    % ' / '.join(sorted(SCRIPT_CHOICES)))
    ap.add_argument('--device', default='usb', choices=['usb', 'local', 'remote'])
    ap.add_argument('--host', default='127.0.0.1:27042', help='--device remote ke liye')
    ap.add_argument('--name', default='Gadget', help='attach karne wala process naam')
    ap.add_argument('--package', default=None, help='package name se attach/spawn (rooted)')
    ap.add_argument('--spawn', action='store_true', help='--package ke saath spawn karo')
    ap.add_argument('--timeout', type=float, default=120, help='process ka wait (seconds)')
    ap.add_argument('--wait', type=float, default=0.5, help='load ke baad kitna rukein')
    ap.add_argument('--max-dump', type=int, default=4096)
    ap.add_argument('--quiet', action='store_true')
    ap.add_argument('--set', action='append', metavar='K=JSON',
                    help='CONFIG override, e.g. --set sslUnpin=false')
    ap.add_argument('--save', default=None, help='saare records JSON mein save karo')
    ap.add_argument('--rpc', default=None, help='ek RPC call karke exit (e.g. selftest)')
    ap.add_argument('--arg', action='append', help='--rpc ke arguments (repeatable)')
    ap.add_argument('--offline-decrypt', metavar='HEX', default=None,
                    help='bina phone ke: agent ke JS AES se ciphertext decrypt karo')
    ap.add_argument('--offline-key', default=None, help='--offline-decrypt ke saath ASCII key')
    a = ap.parse_args()
    if a.script in SCRIPT_CHOICES:
        a.script = SCRIPT_CHOICES[a.script]
    elif not os.path.isabs(a.script):
        a.script = os.path.join(HERE, a.script)
    if not os.path.isfile(a.script):
        ap.error('script nahi mila: %s' % a.script)

    if a.offline_decrypt:
        r = offline_decrypt(a.offline_decrypt, a.offline_key)
        hits = [x for x in r if x.get('paddingOk') and x.get('text')]
        log('[offline-decrypt] %d candidates, %d plausible' % (len(r), len(hits)))
        for x in (hits or r):
            log('  * %-38s key=%-40s pad=%-5s%s'
                % (x.get('cipher'), str(x.get('key'))[:40], x.get('paddingOk'),
                   '  GUESS' if x.get('guessed') else ''))
            log('    text=%r' % (x.get('text', x.get('error')),))
        return
    try:
        asyncio.run(run(a))
    except KeyboardInterrupt:
        log('\n[bye]')


if __name__ == '__main__':
    main()
