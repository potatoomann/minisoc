# MiniSOC - a real-time mini SOC

A lightweight Security Operations Center pipeline written in pure Python (no dependencies).
It tails security logs in real time, detects attacks with rules mapped to **MITRE ATT&CK**,
de-duplicates alerts, automatically "blocks" malicious IPs (simulated SOAR), and streams
everything to a live analyst dashboard. Built and tested on **Kali Linux (WSL 2)**; also
runs on Windows.

```
 auth.log ----+
 web.log  ----+--> Tailer --> Parser --> Detector (12 rules) --> Dedup --> SQLite --> SSE --> Dashboard
 process.log -+                                    |
                                                   +--> Responder (auto-block external IPs)
```

## Quick start on Kali (WSL)

```bash
cd /mnt/c/Users/<you>/Documents/MiniSOC
chmod +x run.sh
./run.sh
```

Open **http://127.0.0.1:8000** in your Windows browser. Use `127.0.0.1`, not `localhost`.
The server listens on IPv4 only, and `localhost` may try IPv6 first.

`./run.sh` starts a built-in simulator that writes normal traffic plus a random attack every
6-12 seconds, so alerts show up live. Stop it with `Ctrl+C`.

| Command | What it does |
|---|---|
| `./run.sh` | Demo mode: simulator + dashboard on port 8000 |
| `./run.sh --quiet` | Dashboard only, so you can fire attacks yourself |
| `./run.sh --quiet --attack-panel` | Dashboard with an on-screen **Attack panel** (attack + defend together) |
| `./run.sh --port 8080` | Use another port (any option is passed to `main.py`) |

Fire one specific attack (in a second Kali terminal, while `./run.sh --quiet` runs):

```bash
python3 simulator.py --scenario brute_force
```

Scenarios: `brute_force`, `sql_injection`, `path_traversal`, `xss`, `dir_scan`,
`encoded_powershell`, `certutil_download`, `credential_dump`, `shadow_delete`,
`discovery`, `new_user`.

Run the tests:

```bash
python3 -m unittest discover -s tests -v
```

On Windows, use `python main.py --demo` and `python` instead of `python3`.

### Troubleshooting

- **`Address already in use`**: with WSL "mirrored" networking, Kali and Windows share ports.
  Stop the other program on that port, wait a minute for old connections to close, or
  use `./run.sh --port 8080`.
- **`python3: command not found`**: `sudo apt update && sudo apt install -y python3`.

## Detection rules

| ID | Detection | Severity | MITRE ATT&CK |
|---|---|---|---|
| AUTH-001 | SSH brute force (5+ failures in 60 s per IP) | High | T1110.001 Password Guessing |
| AUTH-002 | Successful login after brute force (correlation) | Critical | T1078 Valid Accounts |
| AUTH-003 | New local user created | Medium | T1136.001 Create Local Account |
| WEB-001 | SQL injection | High | T1190 Exploit Public-Facing App |
| WEB-002 | Path traversal | High | T1190 |
| WEB-003 | Cross-site scripting | Medium | T1190 |
| WEB-004 | Directory scanning (15+ 404s in 60 s) | Medium | T1595.003 Wordlist Scanning |
| PROC-001 | Encoded PowerShell (`-e`, `-ec`, `-enc`, `/enc`...) | High | T1059.001 PowerShell |
| PROC-002 | Certutil download | High | T1105 Ingress Tool Transfer |
| PROC-003 | Mimikatz / LSASS dumping | Critical | T1003 OS Credential Dumping |
| PROC-004 | Shadow copy deletion (ransomware) | Critical | T1490 Inhibit System Recovery |
| PROC-005 | Privilege / user discovery | Low | T1033 System Owner/User Discovery |

URLs are decoded twice before matching, so double-encoded payloads are still caught.

## Attack panel (attack + defend at once)

Run with `--attack-panel` to get a red **Attack panel** on the dashboard with a button for
each attack. Click one and watch the alert appear live in the same screen — a self-contained
"red team vs. blue team" demo:

```bash
./run.sh --quiet --attack-panel     # then open http://127.0.0.1:8000
```

The buttons only fire the **bundled simulator scenarios** (they write log lines — no real
network traffic, no shell commands), the endpoint accepts allow-listed scenario names only,
and the panel is **off unless you pass `--attack-panel`**, so a normal defensive run never
exposes it. The real external brute force stays in the `sudo` CLI lab below, on purpose.

## Validate against a REAL attack (Kali)

The simulator proves the *logic*; this proves MiniSOC detects a **real** attack on real logs.
It runs a genuine SSH brute force against **your own machine's loopback** (`127.0.0.1` only,
hard-coded) and scores what MiniSOC caught. Only run it on a machine you own.

Open three Kali terminals in the project folder:

```bash
# 1. dashboard
./run.sh --quiet

# 2. feed real SSH logs into MiniSOC
python3 collectors/ssh_collector.py

# 3. run the brute-force lab against your own SSH, then clean up
sudo ./lab/attack_lab.sh
```

Then grade it:

```bash
python3 scorecard.py --ssh-lab
```

You should see **AUTH-001** (real brute force) and **AUTH-002** (critical: a real successful
login right after the brute force). The dashboard shows the same alerts live, now driven by
real `sshd` events instead of the simulator.

- **`collectors/ssh_collector.py`** reads real sshd events from journald or `/var/log/auth.log`,
  normalises them, and appends to the log MiniSOC tails. Point it at any Linux host's SSH logs.
- **`lab/attack_lab.sh`** installs `openssh-server` + `hydra`, creates a throwaway `socdemo`
  user, brute-forces `127.0.0.1`, logs in once, then deletes the user.
- **`scorecard.py`** turns the alert queue into a pass/fail detection summary.

## Features

- **Real-time ingestion**: `tail -f` style followers that handle partial lines and log rotation.
- **Stateful correlation**: sliding windows per IP, and brute force followed by a successful
  login is escalated to critical. A valid login in between does not reset the counter, so
  attackers can't hide a brute force that way.
- **Alert de-duplication**: repeats within 120 s raise a counter instead of flooding the queue.
  If an analyst already closed the alert, renewed activity opens a new one.
- **Automated response (simulated SOAR)**: external IPs behind high/critical alerts are added
  to a block list. The firewall command is generated per OS (`iptables` on Kali, `netsh` on
  Windows) and is **never executed**. Internal ranges (RFC 1918, loopback) are never blocked.
- **Analyst workflow**: alert status open / investigating / closed, with severity and status filters.
- **Live dashboard**: Server-Sent Events, KPIs, top ATT&CK techniques, blocked IP list.
- **Real log formats**: ISO timestamps and standard Apache/Nginx access-log dates.
- **Real-attack validation**: a Kali lab that brute-forces your own SSH and scores detection
  against real `sshd` logs, not just simulated traffic.

## Security of the tool itself

- Binds to `127.0.0.1` by default.
- Rejects requests whose `Host` header is not this machine (DNS-rebinding protection).
- State-changing requests must be `application/json`, which forces a CORS preflight that is
  never approved (CSRF protection).
- Parameterised SQL everywhere; status values are allow-listed; request bodies are size-capped.
- Attacker-controlled log fields are length-capped and rendered with `textContent` only (no XSS
  in the dashboard), with a restrictive Content-Security-Policy.
- Attack simulations use reserved documentation IP ranges (203.0.113.0/24, 198.51.100.0/24).

## Using real logs

Point `--logs` at a folder that has `auth.log` (sshd/syslog lines with ISO timestamps),
`web.log` (access-log format) and `process.log` (JSON lines with `ts, host, user, image,
cmdline, parent`, for example Sysmon Event ID 1 exported to JSON).

## Ideas for next steps

- Load rules from Sigma YAML files instead of Python.
- Enrichment with GeoIP / AbuseIPDB reputation.
- Slack or email notification for critical alerts.
- Cross-check detections against Wazuh or Splunk on the same attack.

## Resume bullets

- Built **MiniSOC**, a real-time SOC pipeline in Python on Kali Linux that tails auth, web and
  endpoint logs and detects 12 attack techniques mapped to MITRE ATT&CK (brute force, SQLi,
  credential dumping, ransomware precursors).
- Implemented stateful correlation (brute force -> successful login escalated to critical),
  evasion-resistant counters and alert de-duplication to cut analyst noise.
- Added simulated SOAR auto-containment (iptables/netsh) with internal-network allowlisting,
  and a live SSE dashboard hardened against XSS, CSRF and DNS rebinding; covered by 29 tests.
- Validated detections against a real SSH brute force (hydra) on a Kali lab, ingesting live
  `journald`/`auth.log` events and scoring detection coverage with a repeatable scorecard.
