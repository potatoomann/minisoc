"""Detection scorecard: did MiniSOC catch the attack?

Reads alerts from a running MiniSOC dashboard (http://127.0.0.1:8000) or straight
from the SQLite database, and prints which MITRE ATT&CK techniques were detected,
how noisy each rule was, and whether the key correlations fired.

    python3 scorecard.py                 # read from the running dashboard
    python3 scorecard.py --db minisoc.db # read the database file directly

Use it after lab/attack_lab.sh (the SSH brute-force lab) or after firing
simulator.py scenarios, to turn a wall of alerts into a pass/fail summary.
"""
import argparse
import json
import sqlite3
import sys
import urllib.request
from collections import defaultdict

# Detections we expect the SSH brute-force lab to produce.
SSH_LAB_EXPECTED = [
    ("AUTH-001", "SSH brute force detected"),
    ("AUTH-002", "Compromise correlated (success after brute force)"),
]


def from_api(base):
    with urllib.request.urlopen(f"{base}/api/alerts?limit=1000", timeout=5) as r:
        return json.load(r)


def from_db(path):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in db.execute("SELECT * FROM alerts ORDER BY id").fetchall()]
    finally:
        db.close()


def load(args):
    if args.db:
        return from_db(args.db)
    try:
        return from_api(args.url)
    except Exception as exc:
        print(f"[scorecard] could not reach {args.url} ({exc}); trying {args.db_fallback}", file=sys.stderr)
        return from_db(args.db_fallback)


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def main():
    ap = argparse.ArgumentParser(description="MiniSOC detection scorecard")
    ap.add_argument("--url", default="http://127.0.0.1:8000", help="running dashboard base URL")
    ap.add_argument("--db", help="read this SQLite DB instead of the dashboard")
    ap.add_argument("--db-fallback", default="minisoc.db", help="DB to use if the dashboard is unreachable")
    ap.add_argument("--ssh-lab", action="store_true", help="also grade the SSH brute-force lab objectives")
    args = ap.parse_args()

    alerts = load(args)
    if not alerts:
        print("No alerts recorded yet. Start MiniSOC, run an attack, then try again.")
        return

    by_rule = defaultdict(lambda: {"count": 0, "hits": 0, "sev": "", "title": "", "mitre": "", "ips": set()})
    for a in alerts:
        r = by_rule[a["rule_id"]]
        r["count"] += 1
        r["hits"] += a.get("count", 1)
        r["sev"], r["title"], r["mitre"] = a["severity"], a["title"], a["mitre"]
        if a.get("source_ip"):
            r["ips"].add(a["source_ip"])

    rows = sorted(by_rule.items(), key=lambda kv: (SEV_ORDER.get(kv[1]["sev"], 9), kv[0]))
    total_alerts = len(alerts)
    total_events = sum(r["hits"] for _, r in rows)

    print("\n" + "=" * 70)
    print(" MiniSOC DETECTION SCORECARD")
    print("=" * 70)
    print(f" Distinct alerts: {total_alerts:<6} Correlated events: {total_events:<6} Rules fired: {len(rows)}")
    print("-" * 70)
    print(f" {'RULE':<9} {'SEVERITY':<9} {'x':>3}  {'MITRE':<28} DETECTION")
    print("-" * 70)
    for rid, r in rows:
        print(f" {rid:<9} {r['sev']:<9} {r['hits']:>3}  {r['mitre'][:27]:<28} {r['title']}")
        if r["ips"]:
            shown = ", ".join(sorted(r["ips"])[:4]) + (" ..." if len(r["ips"]) > 4 else "")
            print(f" {'':<9} {'':<9} {'':>3}  sources: {shown}")
    print("=" * 70)

    if args.ssh_lab:
        print(" SSH BRUTE-FORCE LAB OBJECTIVES")
        print("-" * 70)
        all_pass = True
        for rid, desc in SSH_LAB_EXPECTED:
            ok = rid in by_rule
            all_pass &= ok
            print(f"  [{'PASS' if ok else 'MISS'}]  {rid}  {desc}")
        print("-" * 70)
        print("  RESULT:", "attack fully detected ✓" if all_pass
              else "some objectives missed - check the collector is running and re-run the lab")
        print("=" * 70)


if __name__ == "__main__":
    main()
