"""Dashboard web server: JSON API + Server-Sent Events live stream (stdlib only)."""
import json
import os
import queue
import re
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from store import VALID_STATUSES

STATIC_INDEX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "index.html")
STATUS_PATH = re.compile(r"^/api/alerts/(\d{1,9})/status$")
MAX_BODY = 4096


class Hub:
    """Fan-out of live events to every connected dashboard."""

    def __init__(self, max_clients=50):
        self._subs = set()
        self._lock = threading.Lock()
        self.max_clients = max_clients

    def subscribe(self):
        with self._lock:
            if len(self._subs) >= self.max_clients:
                return None
            q = queue.Queue(maxsize=200)
            self._subs.add(q)
            return q

    def unsubscribe(self, q):
        with self._lock:
            self._subs.discard(q)

    def publish(self, kind, data):
        msg = f"event: {kind}\ndata: {json.dumps(data)}\n\n".encode()
        with self._lock:
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(msg)
            except queue.Full:  # slow client: drop rather than block the engine
                pass


def make_handler(store, hub, engine, allowed_hosts, attacker=None):
    class Handler(BaseHTTPRequestHandler):
        server_version = "MiniSOC"
        sys_version = ""

        def log_message(self, fmt, *args):  # keep the console quiet
            pass

        # ---- helpers
        def _host_ok(self):
            # Blocks DNS-rebinding: only answer requests addressed to our own host name.
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
            return host in allowed_hosts

        def _send(self, code, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        # ---- routes
        def do_GET(self):
            if not self._host_ok():
                return self._send(403, {"error": "forbidden host"})
            url = urlparse(self.path)
            if url.path == "/":
                with open(STATIC_INDEX, "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            if url.path == "/api/alerts":
                try:
                    limit = int(parse_qs(url.query).get("limit", ["200"])[0])
                except ValueError:
                    return self._send(400, {"error": "limit must be an integer"})
                return self._send(200, store.list_alerts(limit))
            if url.path == "/api/stats":
                stats = store.stats()
                stats["events_processed"] = engine.events_processed if engine else 0
                return self._send(200, stats)
            if url.path == "/api/blocked":
                return self._send(200, store.list_blocked())
            if url.path == "/api/attacks":
                # The attack panel is an opt-in lab feature; off unless --attack-panel was passed.
                return self._send(200, {"enabled": attacker is not None,
                                        "scenarios": attacker.scenarios if attacker else []})
            if url.path == "/api/stream":
                return self._stream()
            return self._send(404, {"error": "not found"})

        def do_POST(self):
            if not self._host_ok():
                return self._send(403, {"error": "forbidden host"})
            # Requiring JSON forces a CORS preflight, which we never approve -> blocks CSRF.
            if (self.headers.get("Content-Type") or "").split(";")[0].strip() != "application/json":
                return self._send(415, {"error": "Content-Type must be application/json"})
            path = urlparse(self.path).path
            body = self._read_json()
            if body is None:
                return  # error already sent
            if path == "/api/attack":
                return self._attack(body)
            m = STATUS_PATH.match(path)
            if not m:
                return self._send(404, {"error": "not found"})
            status = body.get("status")
            if status not in VALID_STATUSES:
                return self._send(400, {"error": f"status must be one of {list(VALID_STATUSES)}"})
            alert = store.set_status(int(m.group(1)), status)
            if not alert:
                return self._send(404, {"error": "alert not found"})
            hub.publish("update", alert)
            return self._send(200, alert)

        def _read_json(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._send(400, {"error": "bad Content-Length"})
                return None
            if length <= 0 or length > MAX_BODY:
                self._send(413, {"error": "body too large or empty"})
                return None
            try:
                body = json.loads(self.rfile.read(length))
            except ValueError:
                self._send(400, {"error": "invalid JSON"})
                return None
            if not isinstance(body, dict):
                self._send(400, {"error": "expected a JSON object"})
                return None
            return body

        def _attack(self, body):
            # Lab only: fires one bundled simulator scenario (writes log lines). No shell, no network.
            if attacker is None:
                return self._send(403, {"error": "attack panel is disabled (start with --attack-panel)"})
            scenario = body.get("scenario")
            if scenario not in attacker.scenarios:  # allow-list; no arbitrary input is ever executed
                return self._send(400, {"error": "unknown scenario"})
            attacker.run(scenario)
            return self._send(200, {"ok": True, "scenario": scenario})

        def _stream(self):
            q = hub.subscribe()
            if q is None:
                return self._send(503, {"error": "too many live clients"})
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            try:
                while True:
                    try:
                        msg = q.get(timeout=15)
                    except queue.Empty:
                        msg = b": keep-alive\n\n"
                    self.wfile.write(msg)
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                pass
            finally:
                hub.unsubscribe(q)

    return Handler


def allowed_hosts(bind_host):
    """Host-header names we answer to. Wildcard binds also accept this machine's own name and IPs."""
    allowed = {"localhost", "127.0.0.1", "::1", bind_host.lower()}
    if bind_host in ("0.0.0.0", "::", ""):
        name = socket.gethostname()
        allowed.add(name.lower())
        try:
            allowed.update(info[4][0].lower() for info in socket.getaddrinfo(name, None))
        except OSError:
            pass
    return allowed


class QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        # Browsers drop connections all the time (tab closed, page reloaded); that is not an error.
        if isinstance(sys.exc_info()[1], (ConnectionError, TimeoutError)):
            return
        super().handle_error(request, client_address)


def make_server(host, port, store, hub, engine, attacker=None):
    allowed = allowed_hosts(host)
    return QuietServer((host, port), make_handler(store, hub, engine, allowed, attacker))
