"""MiniSOC entry point: starts the detection engine, the dashboard, and (optionally) the simulator."""
import argparse
import threading

import simulator
from engine import Engine
from server import Hub, make_server
from store import Store


def main():
    ap = argparse.ArgumentParser(description="MiniSOC - real-time mini SOC")
    ap.add_argument("--host", default="127.0.0.1", help="dashboard bind address (default: localhost only)")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--logs", default="logs", help="directory containing auth.log, web.log, process.log")
    ap.add_argument("--db", default="minisoc.db", help="SQLite database file")
    ap.add_argument("--demo", action="store_true", help="also run the built-in attack simulator")
    args = ap.parse_args()

    stop = threading.Event()
    store = Store(args.db)
    hub = Hub()
    engine = Engine(store, args.logs, publish=hub.publish)

    if args.demo:
        threading.Thread(target=simulator.run_forever, args=(args.logs,), kwargs={"stop": stop}, daemon=True).start()
    threading.Thread(target=engine.run, args=(stop,), daemon=True).start()

    srv = make_server(args.host, args.port, store, hub, engine)
    print(f"[minisoc] dashboard: http://{args.host}:{args.port}  (Ctrl+C to stop)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        srv.server_close()


if __name__ == "__main__":
    main()
