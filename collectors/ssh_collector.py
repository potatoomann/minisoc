"""Feed REAL SSH authentication events into MiniSOC.

Reads sshd events from systemd-journald (preferred) or /var/log/auth.log, and
appends them to the log file the MiniSOC engine tails (logs/auth.log), normalised
to the format the engine parses:

    2026-11-23T10:00:00 kali sshd[1234]: Failed password for root from 1.2.3.4 port 5 ssh2

This is what makes MiniSOC detect REAL attacks (e.g. a hydra brute force against
your own Kali SSH) instead of only simulated ones.

Usage (on Kali / any Linux):
    python3 collectors/ssh_collector.py            # follow live, append to logs/auth.log
    python3 collectors/ssh_collector.py --once     # process what exists, then exit
    python3 collectors/ssh_collector.py --source /var/log/auth.log
"""
import argparse
import os
import re
import subprocess
import sys
import time
from datetime import datetime

# Accept both "sshd" and OpenSSH 9.8+'s per-connection "sshd-session" / "sshd-auth" process.
_PROG = r"sshd(?:-\w+)?"
# journald short-iso: "2026-11-23T10:00:00+0530 host sshd[pid]: msg"
# traditional syslog:  "Nov 23 10:00:00 host sshd[pid]: msg"
ISO_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\S*)\s+(?P<host>\S+)\s+" + _PROG + r"(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$")
SYSLOG_LINE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    + _PROG + r"(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$")
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

# Only forward the sshd messages the engine actually has rules for; drop the rest as noise.
KEEP = re.compile(r"Failed password|Accepted (?:password|publickey)|Invalid user", re.I)


def _iso(ts):
    """Normalise a timestamp to clean ISO-8601 the engine's parser accepts."""
    try:
        return datetime.fromisoformat(ts).replace(microsecond=0).isoformat()
    except ValueError:
        return ts


def normalize_line(line, now=None):
    """Turn one real sshd log line into MiniSOC format, or None if not a relevant sshd event.

    Pure and side-effect free, so it can be unit-tested.
    """
    line = line.rstrip("\n")
    m = ISO_LINE.match(line)
    if m:
        ts = _iso(m["ts"])
    else:
        m = SYSLOG_LINE.match(line)
        if not m:
            return None
        # Traditional syslog has no year; assume the current one (or the supplied clock).
        base = now or datetime.now()
        hh, mm, ss = (int(x) for x in m["time"].split(":"))
        ts = datetime(base.year, MONTHS[m["mon"]], int(m["day"]), hh, mm, ss).isoformat()
    if not KEEP.search(m["msg"]):
        return None
    pid = m["pid"] or "0"
    return f'{ts} {m["host"]} sshd[{pid}]: {m["msg"]}'


def iter_journal(follow):
    """Yield raw sshd lines from journald.

    `_COMM=sshd` is tried first: it catches sshd's auth messages ("Failed password")
    regardless of which unit they were logged under, which is the reliable source on
    WSL/Kali. The unit filters are fallbacks.
    """
    # OpenSSH 9.8+ logs auth under sshd-session/sshd-auth; match all of them (same-field matches are OR'd).
    for selector in (["_COMM=sshd", "_COMM=sshd-session", "_COMM=sshd-auth"], ["-u", "ssh"], ["-u", "sshd"]):
        cmd = ["journalctl", *selector, "-o", "short-iso", "--no-pager"]
        if follow:
            cmd.append("-f")
        else:
            cmd += ["-n", "2000"]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        except FileNotFoundError:
            return  # no journalctl on this system
        got = False
        try:
            for raw in proc.stdout:
                got = True
                yield raw
        finally:
            proc.terminate()
        if got or follow:
            return  # this selector produced output (or we're following it); don't try the rest


def iter_file(path, follow):
    """Yield raw lines from a log file, optionally following it like tail -f."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            yield line
        while follow:
            where = f.tell()
            line = f.readline()
            if line:
                yield line
            else:
                time.sleep(0.5)
                f.seek(where)


def run(out_path, source=None, follow=True):
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    if source:
        lines = iter_file(source, follow)
        desc = source
    elif os.path.exists("/var/log/auth.log"):
        lines = iter_file("/var/log/auth.log", follow)
        desc = "/var/log/auth.log"
    else:
        lines = iter_journal(follow)
        desc = "journald (ssh)"
    print(f"[ssh-collector] reading {desc} -> {out_path}"
          f"{' (following, Ctrl+C to stop)' if follow else ''}", flush=True)
    count = 0
    with open(out_path, "a", encoding="utf-8") as out:
        for raw in lines:
            norm = normalize_line(raw)
            if norm:
                out.write(norm + "\n")
                out.flush()
                count += 1
    print(f"[ssh-collector] forwarded {count} SSH event(s)", flush=True)


def main():
    if not sys.platform.startswith("linux"):
        print("This collector reads Linux SSH logs; run it on Kali (WSL), not Windows.", file=sys.stderr)
        sys.exit(1)
    ap = argparse.ArgumentParser(description="Feed real SSH logs into MiniSOC")
    ap.add_argument("--out", default="logs/auth.log", help="log file the MiniSOC engine tails")
    ap.add_argument("--source", help="read this file instead of journald / /var/log/auth.log")
    ap.add_argument("--once", action="store_true", help="process existing events then exit (no follow)")
    args = ap.parse_args()
    try:
        run(args.out, source=args.source, follow=not args.once)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
