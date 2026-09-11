# APK audit pipeline — `TopFollow_v845-Beta.apk`

Static-only analysis of the sample in this repo, plus the engine that produces it.
Nothing here executes the sample: every finding comes from parsing the container,
the manifest, the DEX and the native libraries.

## Layout

| path | what it is |
|---|---|
| `TopFollow_v845-Beta.apk` | the sample under analysis (10,379,650 bytes) |
| `scripts/apk_audit/` | the audit engine (6 layers, stdlib-first) |
| `scripts/merge_vendor.py` | folds Google's tool verdicts into the report |
| `scripts/selftest.py` | positive/negative controls for the behavioural detectors |
| `.github/workflows/apk-audit.yml` | CI: vendor tools + engine + SARIF + artifacts |
| `audit.sh` | one-command local reproduction |

## Engine layers

| layer | file | answers |
|---|---|---|
| container | `container.py` | signing-block layout, alignment, zip hygiene, repack traces |
| signing | `signing.py` | who signed it, key strength, cert version/validity |
| manifest | `manifest.py` | permissions, exported surface, backup, capability inference |
| resources | `resources.py` | `resources.arsc` string pool, UI wording, asset inventory |
| native | `native.py` | ELF hardening, imports, JNI surface, anti-analysis markers |
| dex | `dex.py` | instruction-level behavioural evidence + combined signals |

Outputs per run: `report.md` (human), `findings.json` (machine),
`audit.sarif` (code scanning), `summary.md` (CI job summary).

## Run locally

```bash
python3 -m venv .venv && .venv/bin/pip install -r scripts/requirements.txt
./audit.sh TopFollow_v845-Beta.apk            # -> audit-out/report.md
PYTHONPATH=$PWD/scripts .venv/bin/python scripts/selftest.py
```

Without androguard installed the container/signing/native layers still run;
manifest and DEX layers degrade and say so in the log.

## Run in CI

Push a commit touching `**.apk`, `scripts/**` or the workflow, or dispatch it
manually (`Actions → APK Deep Audit → Run workflow`). The CI job adds what the
engine cannot self-supply: `aapt2 dump badging`, `apksigner verify --print-certs`,
`zipalign -c`, a full `apktool` smali decode, and `readelf`/`strings` on every
shipped ELF. Where Google's verdict and the engine disagree, the report says so
explicitly in *Appendix B — vendor tool cross-check* instead of hiding it.

## What the detectors look for

The behavioural rules are deliberately compositional — a single API mention is
informational, capability only becomes a finding when it composes:

- **`SPOOF-001`** a class that holds a platform *mutation* endpoint **and** builds
  a success-shaped response object locally, with no network call in between.
- **`OBF-010`** three or more equivalent mutation endpoints behind a switch —
  endpoint rotation, i.e. N copies of one action to dodge rate/anomaly limits.
- **`OVL-010`** `WindowManager.addView` plus toggle-style state — a floating
  control panel; the same window type over a login screen is UI hijacking.
- **`NAT-*`** `/proc` scanning, ptrace, su/emulator/hook-framework strings, W^X
  segments, high-entropy sections, `JNI_OnLoad` dynamic registration.
- **`CONT-023`** a signing block that only a non-`apksigner` writer would emit.

These are the patterns we *detect and report*. Implementing them (adding an
overlay menu to a package, forging platform API responses, rotating follow
endpoints) is out of scope for this repo and is the part that gets accounts
banned and users' sessions stolen.
