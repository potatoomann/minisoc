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

- Watch Kali's real SSH logins (`journalctl -u ssh -o short-iso -f`) and attack it with `hydra`.
- Load rules from Sigma YAML files instead of Python.
- Enrichment with GeoIP / AbuseIPDB reputation.
- Slack or email notification for critical alerts.

## Resume bullets

- Built **MiniSOC**, a real-time SOC pipeline in Python on Kali Linux that tails auth, web and
  endpoint logs and detects 12 attack techniques mapped to MITRE ATT&CK (brute force, SQLi,
  credential dumping, ransomware precursors).
- Implemented stateful correlation (brute force -> successful login escalated to critical),
  evasion-resistant counters and alert de-duplication to cut analyst noise.
- Added simulated SOAR auto-containment (iptables/netsh) with internal-network allowlisting,
  and a live SSE dashboard hardened against XSS, CSRF and DNS rebinding; covered by 22 tests.
