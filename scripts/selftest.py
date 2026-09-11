#!/usr/bin/env python3
"""Self-check for the combined-signal detectors (positive + negative control).

Why this exists: SPOOF-001 / OBF-010 / OVL-010 are the rules that decide whether
a package fabricates platform responses, rotates endpoints, or shows a floating
toggle panel. If the regexes silently break, a real sample reads clean and a
benign one reads guilty. So the rules are tested against synthetic shapes:
one that must fire and one that must not.
"""

from __future__ import annotations

import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from apk_audit.core import Findings, Sev  # noqa: E402
from apk_audit.dex import combined_signals  # noqa: E402

FAIL = 0


def check(name: str, cond: bool) -> None:
    global FAIL
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        FAIL += 1


def run() -> int:
    print("combined-signal detector controls")

    # ---- positive control: an implementation that fabricates success -------
    F = Findings()
    class_meta = {"La/fake;": {}, "Lbenign/Thing;": {}}
    calls = {
        "La/fake;": {"Lretrofit2/Response;->success(Ljava/lang/Object;)Lretrofit2/Response;"},
        "Lbenign/Thing;": {"Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V"},
    }
    strs = {
        # the "N equivalent mutation endpoints + a switch over them" shape
        "La/fake;": {
            "/api/v1/friendships/create/",
            "/v1/friendships/create/",
            "/api/v1/friendships/destroy/",
            "/ig/friendships/create/",
            "/fql/friendships",
            "status",
            '"status": "ok"',
            "feedback_url",
        },
        "Lbenign/Thing;": {"hello"},
    }
    switches: Counter[str] = Counter({"La/fake;": 4, "Lbenign/Thing;": 0})
    out = combined_signals(class_meta, calls, strs, switches, F)
    ids = {f.rule_id for f in F.items}
    check("SPOOF-001 fires on mutation path + fabricated response", "SPOOF-001" in ids)
    check("OBF-010 fires on 3+ paths with switch dispatch", "OBF-010" in ids)
    check("benign class is not flagged for spoofing", "Lbenign/Thing;" not in out["fake_success_classes"])
    check("severity of SPOOF-001 is CRITICAL",
          all(f.severity is Sev.CRITICAL for f in F.items if f.rule_id == "SPOOF-001"))

    # ---- positive control: floating toggle panel ---------------------------
    F2 = Findings()
    out2 = combined_signals(
        {"Lmenu/Float;": {}},
        {"Lmenu/Float;": {"Landroid/view/WindowManager;->addView(Landroid/view/View;"
                          "Landroid/view/WindowManager$LayoutParams;)V"}},
        {"Lmenu/Float;": {"follow_pass_1", "follow_pass_2", "toggle", "enable"}},
        Counter(),
        F2,
    )
    check("OVL-010 fires on overlay addView + toggles",
          "OVL-010" in {f.rule_id for f in F2.items} and out2["overlay_panel_classes"] == ["Lmenu/Float;"])

    # ---- negative controls -------------------------------------------------
    F3 = Findings()
    # a legit client posts to the endpoint and parses the reply: no local success object
    combined_signals(
        {"Lnet/Client;": {}},
        {"Lnet/Client;": {"Lokhttp3/OkHttpClient;->newCall(Lokhttp3/Request;)Lokhttp3/Call;"}},
        {"Lnet/Client;": {"https://i.instagram.com/api/v1/friendships/create/123/"}},
        Counter(),
        F3,
    )
    # single endpoint + no switch + no fabrication object -> must stay quiet
    check("real network call to one endpoint does not look like rotation",
          "OBF-010" not in {f.rule_id for f in F3.items})
    check("mutation path alone (no fabrication) does NOT flag spoof",
          "SPOOF-001" not in {f.rule_id for f in F3.items})

    F4 = Findings()
    combined_signals({"Lui/Activity;": {}}, {"Lui/Activity;": {"Landroid/widget/Button;->setOnClickListener"}},
                     {"Lui/Activity;": {"Submit", "Cancel"}}, Counter(), F4)
    check("plain UI class raises nothing", len(F4) == 0)

    print()
    if FAIL:
        print(f"{FAIL} control(s) FAILED")
        return 1
    print("all controls OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
