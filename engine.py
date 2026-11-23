"""Detection engine: tail logs -> parse -> detect -> dedupe -> store -> respond -> publish."""
import ipaddress
import json
import os
import re
import sys
import time
from collections import defaultdict, deque
from datetime import datetime
from urllib.parse import unquote_plus

# ---------------------------------------------------------------- parsing

AUTH_RE = re.compile(r"^(?P<ts>\S+) (?P<host>\S+) (?P<prog>[\w.-]+)(?:\[\d+\])?: (?P<msg>.*)$")
FAILED_RE = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+)")
ACCEPT_RE = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+)")
NEWUSER_RE = re.compile(r"new user: name=(?P<user>[^,\s]+)")
WEB_RE = re.compile(
    r'^(?P<ip>[0-9a-fA-F.:]+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+) [^"]*" (?P<status>\d{3}) (?P<size>\d+|-)'
)
MAX_FIELD = 2048  # cap attacker-controlled fields we store/display


def _epoch(ts):
    """ISO-8601 (simulator, syslog RFC 5424) or Apache/Nginx `23/Nov/2026:10:00:00 +0000`."""
    try:
        return datetime.fromisoformat(ts).timestamp()
    except ValueError:
        pass
    try:
        return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z").timestamp()
    except ValueError:
        return time.time()


def parse_auth(line):
    m = AUTH_RE.match(line)
    if not m:
        return None
    ev = {"source": "auth", "ts": m["ts"], "epoch": _epoch(m["ts"]), "host": m["host"],
          "prog": m["prog"], "raw": line[:MAX_FIELD], "action": "other", "ip": None, "user": None}
    msg = m["msg"]
    for action, rx in (("failed", FAILED_RE), ("accepted", ACCEPT_RE), ("useradd", NEWUSER_RE)):
        hit = rx.search(msg)
        if hit:
            ev["action"] = action
            ev["user"] = hit["user"]
            ev["ip"] = hit.groupdict().get("ip")
            break
    return ev


def parse_web(line):
    m = WEB_RE.match(line)
    if not m:
        return None
    return {"source": "web", "ts": m["ts"], "epoch": _epoch(m["ts"]), "host": "web-01", "ip": m["ip"],
            "method": m["method"], "path": m["path"][:MAX_FIELD], "status": int(m["status"]),
            "raw": line[:MAX_FIELD]}


def parse_process(line):
    try:
        d = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(d, dict) or "cmdline" not in d:
        return None
    ts = str(d.get("ts", ""))
    return {"source": "process", "ts": ts, "epoch": _epoch(ts), "host": str(d.get("host", "?"))[:128],
            "user": str(d.get("user", "?"))[:128], "image": str(d.get("image", ""))[:256],
            "cmdline": str(d["cmdline"])[:MAX_FIELD], "parent": str(d.get("parent", ""))[:256], "ip": None,
            "raw": line[:MAX_FIELD]}


# ---------------------------------------------------------------- rules

PROCESS_RULES = [
    ("PROC-001", "Encoded PowerShell command", "high", "T1059.001 PowerShell",
     # PowerShell accepts any prefix of -EncodedCommand (-e, -ec, -enc, -enco...) and '/' as prefix
     re.compile(r"powershell(?:\.exe)?\b.*\s[-/](?:e|ec|en[a-z]*)\b", re.I)),
    ("PROC-002", "Certutil used to download a file", "high", "T1105 Ingress Tool Transfer",
     re.compile(r"certutil(?:\.exe)?\b.*-urlcache", re.I)),
    ("PROC-003", "Credential dumping (Mimikatz / LSASS)", "critical", "T1003 OS Credential Dumping",
     re.compile(r"mimikatz|sekurlsa::|procdump.*lsass|comsvcs\.dll.*minidump", re.I)),
    ("PROC-004", "Shadow copies deleted (ransomware behaviour)", "critical", "T1490 Inhibit System Recovery",
     re.compile(r"vssadmin(?:\.exe)?\s+delete\s+shadows|wmic.*shadowcopy.*delete", re.I)),
    ("PROC-005", "Privilege / user discovery", "low", "T1033 System Owner/User Discovery",
     re.compile(r"\bwhoami(?:\.exe)?\s+/(?:priv|all|groups)|\bnet\s+(?:user|group)\b.*/domain", re.I)),
]

WEB_RULES = [
    ("WEB-001", "SQL injection attempt", "high", "T1190 Exploit Public-Facing Application",
     re.compile(r"union\s+(?:all\s+)?select|'\s*or\s*'?1'?\s*=\s*'?1|sleep\(\s*\d+\s*\)|information_schema", re.I)),
    ("WEB-002", "Path traversal attempt", "high", "T1190 Exploit Public-Facing Application",
     re.compile(r"\.\./|\.\.\\|/etc/passwd|win\.ini", re.I)),
    ("WEB-003", "Cross-site scripting attempt", "medium", "T1190 Exploit Public-Facing Application",
     re.compile(r"<script|javascript:|onerror\s*=", re.I)),
]


def _alert(ev, rule_id, title, severity, mitre, details, key):
    return {"rule_id": rule_id, "title": title, "severity": severity, "mitre": mitre,
            "source_ip": ev.get("ip"), "host": ev.get("host"), "ts": ev["ts"], "epoch": ev["epoch"],
            "details": details[:MAX_FIELD], "dedup_key": key}


class Detector:
    """Stateless pattern rules + stateful sliding-window rules."""

    def __init__(self, brute_threshold=5, scan_threshold=15, window=60, compromise_window=300):
        self.brute_threshold = brute_threshold
        self.scan_threshold = scan_threshold
        self.window = window
        self.compromise_window = compromise_window
        self._failed = defaultdict(deque)   # ip -> timestamps of failed logins
        self._notfound = defaultdict(deque) # ip -> timestamps of 404s
        self._bruteforced = {}              # ip -> epoch of last brute-force alert

    def _hit_window(self, table, key, now):
        q = table[key]
        q.append(now)
        while q and now - q[0] > self.window:
            q.popleft()
        return len(q)

    def process(self, ev):
        src = ev["source"]
        if src == "auth":
            return self._auth(ev)
        if src == "web":
            return self._web(ev)
        if src == "process":
            return self._process(ev)
        return []

    def _auth(self, ev):
        out, ip, now = [], ev["ip"], ev["epoch"]
        if ev["action"] == "failed" and ip:
            n = self._hit_window(self._failed, ip, now)
            if n >= self.brute_threshold:
                self._bruteforced[ip] = now
                out.append(_alert(ev, "AUTH-001", "SSH brute force", "high", "T1110.001 Password Guessing",
                                  f"{n} failed logins from {ip} within {self.window}s (last user: {ev['user']})", ip))
        elif ev["action"] == "accepted" and ip:
            last = self._bruteforced.get(ip)
            if last is not None and now - last <= self.compromise_window:
                out.append(_alert(ev, "AUTH-002", "Successful login after brute force", "critical",
                                  "T1078 Valid Accounts",
                                  f"User '{ev['user']}' logged in from {ip} shortly after a brute-force attack", ip))
            # Deliberately NOT clearing the failure window here: otherwise an attacker with one
            # valid account could interleave successful logins to keep the counter below threshold.
        elif ev["action"] == "useradd":
            out.append(_alert(ev, "AUTH-003", "New local user account created", "medium",
                              "T1136.001 Create Account: Local Account",
                              f"Account '{ev['user']}' created on {ev['host']}", f"{ev['host']}:{ev['user']}"))
        return out

    def _web(self, ev):
        out, ip = [], ev["ip"]
        decoded = unquote_plus(unquote_plus(ev["path"]))  # catch double-encoding too
        for rule_id, title, sev, mitre, rx in WEB_RULES:
            if rx.search(decoded):
                out.append(_alert(ev, rule_id, title, sev, mitre, f"{ev['method']} {decoded} -> {ev['status']}",
                                  f"{rule_id}:{ip}"))
        if ev["status"] == 404:
            n = self._hit_window(self._notfound, ip, ev["epoch"])
            if n >= self.scan_threshold:
                out.append(_alert(ev, "WEB-004", "Web directory scanning", "medium",
                                  "T1595.003 Wordlist Scanning", f"{n} 404 responses to {ip} within {self.window}s",
                                  ip))
        return out

    def _process(self, ev):
        out = []
        for rule_id, title, sev, mitre, rx in PROCESS_RULES:
            if rx.search(ev["cmdline"]):
                out.append(_alert(ev, rule_id, title, sev, mitre,
                                  f"{ev['user']}@{ev['host']} ran: {ev['cmdline']} (parent: {ev['parent']})",
                                  f"{ev['host']}:{ev['cmdline']}"))
        return out

    def prune(self, now):
        """Drop idle state so memory stays bounded on long runs."""
        for table in (self._failed, self._notfound):
            for k in [k for k, q in table.items() if not q or now - q[-1] > self.window]:
                del table[k]
        for k in [k for k, t in self._bruteforced.items() if now - t > self.compromise_window]:
            del self._bruteforced[k]


# ---------------------------------------------------------------- response

DEFAULT_ALLOWLIST = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128"]


class Responder:
    """Simulated SOAR: records a block for high/critical alerts from external IPs.

    It never touches the real firewall; it records the command an analyst would run.
    """

    def __init__(self, store, allowlist=DEFAULT_ALLOWLIST, severities=("high", "critical")):
        self.store = store
        self.allow = [ipaddress.ip_network(n) for n in allowlist]
        self.severities = set(severities)

    def handle(self, alert):
        ip = alert.get("source_ip")
        if not ip or alert["severity"] not in self.severities:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if any(addr in net for net in self.allow):
            return None
        record = self.store.block_ip(str(addr), f"{alert['rule_id']} {alert['title']}")
        if record:
            record["command"] = block_command(addr)
        return record


def block_command(addr):
    """The firewall command an analyst would run on this OS (shown, never executed)."""
    if sys.platform.startswith("linux"):  # Kali / any Linux
        flag = "ip6tables" if addr.version == 6 else "iptables"
        return f"sudo {flag} -I INPUT -s {addr} -j DROP"
    return (f'netsh advfirewall firewall add rule name="MiniSOC block {addr}" '
            f"dir=in action=block remoteip={addr}")


# ---------------------------------------------------------------- tailing

class Tailer:
    """Follows a file like `tail -f`, survives truncation, buffers partial lines."""

    MAX_BUF = 64 * 1024

    def __init__(self, path):
        self.path = path
        self.offset = 0
        self.buf = b""

    def read_lines(self):
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return []
        if size < self.offset:  # file was truncated / rotated
            self.offset, self.buf = 0, b""
        if size == self.offset:
            return []
        with open(self.path, "rb") as f:
            f.seek(self.offset)
            data = f.read(size - self.offset)
            self.offset += len(data)
        parts = (self.buf + data).split(b"\n")
        self.buf = parts.pop()[-self.MAX_BUF:]
        return [p.decode("utf-8", "replace").rstrip("\r") for p in parts if p.strip()]


class Engine:
    DEDUP_SECONDS = 120

    def __init__(self, store, log_dir, publish=lambda kind, data: None, detector=None, responder=None):
        self.store = store
        self.publish = publish
        self.detector = detector or Detector()
        self.responder = responder if responder is not None else Responder(store)
        self.sources = [(Tailer(os.path.join(log_dir, "auth.log")), parse_auth),
                        (Tailer(os.path.join(log_dir, "web.log")), parse_web),
                        (Tailer(os.path.join(log_dir, "process.log")), parse_process)]
        self.events_processed = 0
        self.latest_epoch = 0.0  # newest event time seen: the engine's clock (works for replayed logs too)
        self._recent = {}  # (rule_id, dedup_key) -> (alert_id, epoch)

    def handle_event(self, ev):
        self.events_processed += 1
        self.latest_epoch = max(self.latest_epoch, ev["epoch"])
        for a in self.detector.process(ev):
            self._emit(a)

    def _emit(self, a):
        key = (a["rule_id"], a["dedup_key"])
        prev = self._recent.get(key)
        if prev and a["epoch"] - prev[1] < self.DEDUP_SECONDS:
            bumped = self.store.bump_alert(prev[0], a["ts"])  # None if the analyst closed it
            if bumped:
                self._recent[key] = (prev[0], a["epoch"])
                self.publish("update", bumped)
                return
        alert = self.store.add_alert(a)
        self._recent[key] = (alert["id"], a["epoch"])
        self.publish("alert", alert)
        blocked = self.responder.handle(alert) if self.responder else None
        if blocked:
            self.publish("block", blocked)

    def poll_once(self):
        for tailer, parser in self.sources:
            for line in tailer.read_lines():
                ev = parser(line)
                if ev:
                    self.handle_event(ev)

    def prune(self):
        """Drop expired state, measured on the event clock rather than the wall clock."""
        now = self.latest_epoch
        self.detector.prune(now)
        self._recent = {k: v for k, v in self._recent.items() if now - v[1] < self.DEDUP_SECONDS}

    def run(self, stop, interval=0.5):
        last_prune = time.time()
        last_count = -1
        while not stop.is_set():
            try:
                self.poll_once()
            except Exception as exc:  # keep the pipeline alive; report and continue
                print(f"[engine] error: {exc!r}")
            if self.events_processed != last_count:
                last_count = self.events_processed
                self.publish("events", {"events_processed": last_count})
            if time.time() - last_prune > 60:
                self.prune()
                last_prune = time.time()
            stop.wait(interval)
