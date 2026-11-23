"""SQLite storage for alerts and blocked IPs."""
import sqlite3
import threading
from datetime import datetime

VALID_STATUSES = ("open", "investigating", "closed")

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT    NOT NULL,
    rule_id    TEXT    NOT NULL,
    title      TEXT    NOT NULL,
    severity   TEXT    NOT NULL,
    mitre      TEXT    NOT NULL,
    source_ip  TEXT,
    host       TEXT,
    details    TEXT    NOT NULL,
    status     TEXT    NOT NULL DEFAULT 'open',
    count      INTEGER NOT NULL DEFAULT 1,
    last_seen  TEXT    NOT NULL
);
CREATE TABLE IF NOT EXISTS blocked_ips (
    ip     TEXT PRIMARY KEY,
    ts     TEXT NOT NULL,
    reason TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path=":memory:"):
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._db.executescript(SCHEMA)
            self._db.commit()

    def _one(self, sql, args=()):
        row = self._db.execute(sql, args).fetchone()
        return dict(row) if row else None

    def add_alert(self, a):
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO alerts (ts, rule_id, title, severity, mitre, source_ip, host, details, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (a["ts"], a["rule_id"], a["title"], a["severity"], a["mitre"],
                 a.get("source_ip"), a.get("host"), a["details"], a["ts"]),
            )
            self._db.commit()
            return self._one("SELECT * FROM alerts WHERE id = ?", (cur.lastrowid,))

    def bump_alert(self, alert_id, ts):
        """Repeat of an existing alert: increase count instead of creating noise.

        Returns None if the alert is closed, so renewed activity becomes a fresh alert.
        """
        with self._lock:
            cur = self._db.execute(
                "UPDATE alerts SET count = count + 1, last_seen = ? WHERE id = ? AND status != 'closed'",
                (ts, alert_id))
            self._db.commit()
            if cur.rowcount == 0:
                return None
            return self._one("SELECT * FROM alerts WHERE id = ?", (alert_id,))

    def set_status(self, alert_id, status):
        if status not in VALID_STATUSES:
            raise ValueError(f"invalid status: {status}")
        with self._lock:
            cur = self._db.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
            self._db.commit()
            if cur.rowcount == 0:
                return None
            return self._one("SELECT * FROM alerts WHERE id = ?", (alert_id,))

    def list_alerts(self, limit=200):
        limit = max(1, min(int(limit), 1000))
        with self._lock:
            rows = self._db.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def block_ip(self, ip, reason):
        """Returns the new block record, or None if the IP was already blocked."""
        ts = datetime.now().isoformat(timespec="seconds")
        with self._lock:
            cur = self._db.execute("INSERT OR IGNORE INTO blocked_ips (ip, ts, reason) VALUES (?, ?, ?)", (ip, ts, reason))
            self._db.commit()
        return {"ip": ip, "ts": ts, "reason": reason} if cur.rowcount else None

    def list_blocked(self):
        with self._lock:
            rows = self._db.execute("SELECT * FROM blocked_ips ORDER BY ts DESC").fetchall()
        return [dict(r) for r in rows]

    def stats(self):
        with self._lock:
            sev = dict(self._db.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity").fetchall())
            status = dict(self._db.execute("SELECT status, COUNT(*) FROM alerts GROUP BY status").fetchall())
            mitre = self._db.execute(
                "SELECT mitre, COUNT(*) AS n FROM alerts GROUP BY mitre ORDER BY n DESC LIMIT 10").fetchall()
            total = self._db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            blocked = self._db.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
        return {
            "total_alerts": total,
            "by_severity": sev,
            "by_status": status,
            "top_mitre": [{"technique": m, "count": n} for m, n in mitre],
            "blocked_ips": blocked,
        }
