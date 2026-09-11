#!/usr/bin/env bash
# Reproduce the CI audit locally in one command.
#   ./audit.sh [path/to/file.apk] [severity-gate]
# Requires: python3.10+ ; optionally: pip install -r scripts/requirements.txt
set -uo pipefail
cd "$(dirname "$0")"
APK="${1:-TopFollow_v845-Beta.apk}"
GATE="${2:-never}"
OUT="${OUT:-audit-out}"

PY=python3
[ -x .venv/bin/python ] && PY=.venv/bin/python

if ! $PY -c 'import androguard' 2>/dev/null; then
  echo "note: androguard missing -> AXML/DEX layers degrade. Optional:" >&2
  echo "      python3 -m venv .venv && .venv/bin/pip install -r scripts/requirements.txt" >&2
fi

mkdir -p "$OUT"
PYTHONPATH="$PWD/scripts" $PY -m apk_audit "$APK" -o "$OUT" --fail-on "$GATE"
rc=$?
echo
echo "report : $OUT/report.md"
echo "json   : $OUT/findings.json"
echo "sarif  : $OUT/audit.sarif"
exit $rc
