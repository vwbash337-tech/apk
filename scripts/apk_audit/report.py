"""Report renderers: Markdown (human), JSON (machine), SARIF (code scanning)."""

from __future__ import annotations

import json
import os
from typing import Any

from .core import SEV_WEIGHT, Finding, Findings, Sev, human

ORDER = [Sev.CRITICAL, Sev.HIGH, Sev.MEDIUM, Sev.LOW, Sev.INFO]


def _group(F: Findings) -> dict[Sev, list[Finding]]:
    g: dict[Sev, list[Finding]] = {s: [] for s in ORDER}
    for f in F.items:
        g[f.severity].append(f)
    for s in ORDER:
        g[s].sort(key=lambda f: (f.category, f.rule_id))
    return g


def summary_table(F: Findings, meta: dict[str, Any]) -> list[str]:
    g = _group(F)
    out = [
        "| Severity | Count |",
        "|---|---|",
    ]
    for s in ORDER:
        n = len(g[s])
        if n:
            out.append(f"| {s.emoji} **{s.label}** | {n} |")
    score, band = F.score()
    out.append(f"| | |")
    out.append(f"| **Aggregate risk score** | **{score} / 100 — {band}** |")
    return out


def render_markdown(F: Findings, meta: dict[str, Any], layers: dict[str, dict[str, Any]]) -> str:
    score, band = F.score()
    L: list[str] = []
    a = L.append
    m = meta
    a(f"# Static audit — `{os.path.basename(m['apk'])}`")
    a("")
    a("| | |")
    a("|---|---|")
    a(f"| Package | `{m.get('package')}` |")
    a(f"| Version | `{m.get('version_name')}` (code `{m.get('version_code')}`) |")
    a(f"| Size | {human(m['size'])} |")
    a(f"| SHA-256 | `{m['sha256']}` |")
    a(f"| SHA-1 | `{m['sha1']}` |")
    a(f"| MD5 | `{m['md5']}` |")
    a(f"| Engine | {m.get('engine')} |")
    a(f"| Risk score | **{score}/100 — {band}** |")
    a("")
    a("## 1. Verdict at a glance")
    a("")
    for line in summary_table(F, meta):
        a(line)
    a("")

    order = [
        ("signing", "2. Signing identity"),
        ("container", "3. Container / packaging"),
        ("manifest", "4. Manifest & permissions"),
        ("attack-surface", "5. Exported attack surface"),
        ("native", "6. Native code (ELF)"),
        ("behaviour", "7. Behavioural API evidence"),
        ("credential", "8. Credentials & secrets"),
        ("network", "9. Network indicators"),
        ("capability", "10. Declared capability"),
        ("obfuscation", "11. Anti-analysis & obfuscation"),
        ("persistence", "12. Persistence"),
        ("resources", "13. Resources & UI strings"),
    ]
    g = _group(F)
    flat: dict[str, list[Finding]] = {}
    for s in ORDER:
        for f in g[s]:
            flat.setdefault(f.category, []).append(f)
    for cat, title in order:
        items = flat.get(cat)
        if not items:
            continue
        a("")
        a(f"## {title}")
        a("")
        for f in sorted(items, key=lambda x: (-x.severity.value, x.rule_id)):
            a(f"### {f.severity.emoji} `{f.rule_id}` — {f.title}")
            a("")
            if f.detail:
                a(f._wrap(f.detail))
                a("")
            if f.attack:
                a("*MITRE ATT&CK Mobile: " + ", ".join(f"`{x}`" for x in f.attack) + "*")
                a("")
            if f.cwe:
                a(f"*Weakness: `{f.cwe}`*")
                a("")
            if f.evidence:
                a("```")
                for e in f.evidence[:18]:
                    a(str(e)[:220])
                extra = len(f.evidence) - 18
                if extra > 0:
                    a(f"... +{extra} more (see findings.json)")
                a("```")
                a("")
    a("")
    a("## Appendix — extracted indicators")
    a("")
    for key, title in (
        ("hosts", "Hosts seen in managed code"),
        ("third_party_hosts", "Non-infrastructure hosts"),
        ("urls", "Full URL list"),
        ("api_paths", "API paths without host"),
        ("all_native_urls", "Native-code URLs"),
        ("emails", "E-mail addresses"),
    ):
        for layer in layers.values():
            if isinstance(layer, dict) and layer.get(key):
                vals = layer[key]
                a(f"**{title}** ({len(vals)})")
                a("")
                a("```")
                for v in vals[:120]:
                    a(str(v))
                a("```")
                a("")
                break
    a("---")
    a("")
    a("_Static analysis only: the sample was never executed. Findings describe capability and "
      "design, not observed on-device behaviour; confirm with dynamic analysis before acting._")
    return "\n".join(L)


def _wrap(self, text: str, width: int = 100) -> str:
    words, lines, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return "\n".join(lines)


Finding._wrap = _wrap  # type: ignore[attr-defined]


def render_sarif(F: Findings, meta: dict[str, Any]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for f in F.items:
        rules.setdefault(
            f.rule_id,
            {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.title[:120]},
                "fullDescription": {"text": f.detail or f.title},
                "properties": {"category": f.category, "tags": [f.category] + (f.attack or [])},
            },
        )
        results.append(
            {
                "ruleId": f.rule_id,
                "level": {
                    Sev.CRITICAL: "error",
                    Sev.HIGH: "error",
                    Sev.MEDIUM: "warning",
                    Sev.LOW: "note",
                    Sev.INFO: "note",
                }[f.severity],
                "message": {"text": f"{f.title}. {f.detail}"[:2000]},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": os.path.basename(meta["apk"])},
                            "region": {"startLine": 1},
                        }
                    }
                ],
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "apk-audit",
                        "version": "1.0",
                        "informationUri": "https://github.com/vwbash337-tech/apk",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def write(outdir: str, F: Findings, meta: dict[str, Any], layers: dict[str, dict[str, Any]]) -> dict[str, str]:
    os.makedirs(outdir, exist_ok=True)
    paths = {}
    md = render_markdown(F, meta, layers)
    p = os.path.join(outdir, "report.md")
    open(p, "w").write(md)
    paths["markdown"] = p

    payload = {
        "meta": meta,
        "score": F.score()[0],
        "band": F.score()[1],
        "counts": {s.name: len([f for f in F.items if f.severity is s]) for s in ORDER},
        "findings": [f.to_dict() for f in sorted(F.items, key=lambda x: (-x.severity.value, x.category))],
        "layers": json.loads(json.dumps(layers, default=str)),
    }
    p = os.path.join(outdir, "findings.json")
    json.dump(payload, open(p, "w"), indent=1, default=str)
    paths["json"] = p

    p = os.path.join(outdir, "audit.sarif")
    json.dump(render_sarif(F, meta), open(p, "w"), indent=1)
    paths["sarif"] = p

    # job summary fragment for CI
    lines = [f"### `{os.path.basename(meta['apk'])}` — risk **{F.score()[0]}/100 {F.score()[1]}**", ""]
    for line in summary_table(F, meta):
        lines.append(line)
    lines += ["", "<details><summary>Critical / High findings</summary>", ""]
    for s in (Sev.CRITICAL, Sev.HIGH):
        for f in [x for x in F.items if x.severity is s]:
            lines.append(f"- {s.emoji} `{f.rule_id}` **{f.title}** — {f.detail[:180]}")
    lines += ["", "</details>", ""]
    p = os.path.join(outdir, "summary.md")
    open(p, "w").write("\n".join(lines))
    paths["summary"] = p
    return paths
