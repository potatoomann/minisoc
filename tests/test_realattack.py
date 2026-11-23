"""Tests for the real-SSH-log collector and the real-attack detection path."""
import os
import sys
import unittest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collectors.ssh_collector import normalize_line  # noqa: E402
from engine import Detector, parse_auth  # noqa: E402


class NormalizeTests(unittest.TestCase):
    def test_journald_iso_failed(self):
        line = "2026-11-23T10:00:00+0000 kali sshd[1234]: Failed password for root from 203.0.113.9 port 5 ssh2"
        out = normalize_line(line)
        # timezone offset is preserved (the engine parses it); the message is intact
        self.assertEqual(out, "2026-11-23T10:00:00+00:00 kali sshd[1234]: Failed password for root from 203.0.113.9 port 5 ssh2")
        # and the engine can parse what the collector emits
        ev = parse_auth(out)
        self.assertEqual((ev["action"], ev["ip"]), ("failed", "203.0.113.9"))

    def test_traditional_syslog(self):
        out = normalize_line("Nov 23 10:00:00 kali sshd[22]: Accepted password for socdemo from 127.0.0.1 port 5 ssh2",
                             now=datetime(2026, 1, 1))
        self.assertTrue(out.startswith("2026-11-23T10:00:00 kali sshd[22]: Accepted password"))
        self.assertEqual(parse_auth(out)["action"], "accepted")

    def test_invalid_user_kept(self):
        self.assertIsNotNone(normalize_line(
            "2026-11-23T10:00:00 kali sshd[1]: Failed password for invalid user oracle from 10.0.0.9 port 5 ssh2"))

    def test_noise_dropped(self):
        self.assertIsNone(normalize_line("2026-11-23T10:00:00 kali sshd[1]: Server listening on 0.0.0.0 port 22"))
        self.assertIsNone(normalize_line("2026-11-23T10:00:00 kali systemd[1]: Started OpenSSH server"))
        self.assertIsNone(normalize_line("not a log line at all"))


class RealAttackDetectionTests(unittest.TestCase):
    def test_hydra_style_bruteforce_then_login(self):
        """Simulate what the lab produces: many failures from one IP, then a success."""
        d = Detector()
        alerts = []
        raw = [
            f"2026-11-23T10:00:{i:02d}+0000 kali sshd[{i}]: Failed password for socdemo from 127.0.0.1 port {i} ssh2"
            for i in range(6)
        ]
        # a real attacker's source on the lab is loopback; use an external IP to also exercise response path
        raw = [r.replace("127.0.0.1", "203.0.113.50") for r in raw]
        raw.append("2026-11-23T10:00:07+0000 kali sshd[99]: Accepted password for socdemo from 203.0.113.50 port 7 ssh2")
        for line in raw:
            ev = parse_auth(normalize_line(line))
            alerts += d.process(ev)
        fired = [a["rule_id"] for a in alerts]
        self.assertIn("AUTH-001", fired)   # brute force
        self.assertIn("AUTH-002", fired)   # compromise (success after brute force)
        self.assertEqual(next(a["severity"] for a in alerts if a["rule_id"] == "AUTH-002"), "critical")


if __name__ == "__main__":
    unittest.main()
