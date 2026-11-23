#!/usr/bin/env bash
# Start MiniSOC on Kali Linux (WSL or native).
#   ./run.sh                 -> demo mode: built-in attack simulator + dashboard on port 8000
#   ./run.sh --quiet         -> no simulator; fire attacks yourself with: python3 simulator.py --scenario NAME
#   ./run.sh --port 8080     -> any extra options are passed to main.py
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v python3 >/dev/null; then
    echo "python3 not found. Install it with: sudo apt update && sudo apt install -y python3" >&2
    exit 1
fi

if [[ "${1:-}" == "--quiet" ]]; then
    shift
    exec python3 main.py "$@"
fi
exec python3 main.py --demo "$@"
