#!/usr/bin/env bash
#
# MiniSOC self-contained detection lab (Kali / Linux).
#
# Runs a REAL SSH brute force against THIS machine's own loopback (127.0.0.1) so
# MiniSOC can detect a real attack, then scores what it caught. Everything stays
# on localhost: the target is hard-coded to 127.0.0.1 and cannot be changed, so
# this only ever exercises your own machine. Only run it on a machine you own.
#
# What it does:
#   1. Installs openssh-server + hydra (apt) if missing.
#   2. Creates a throwaway local user 'socdemo' with a known password.
#   3. Brute-forces 127.0.0.1 SSH with wrong passwords (-> real "Failed password" logs).
#   4. Logs in once with the correct password (-> real "Accepted password": the
#      brute-force-then-success that MiniSOC escalates to CRITICAL).
#   5. Removes the 'socdemo' user.
#
# Before running, start MiniSOC + the SSH collector in two other terminals:
#   Terminal A:  ./run.sh --quiet
#   Terminal B:  python3 collectors/ssh_collector.py
# Then:          sudo ./lab/attack_lab.sh
# Finally:       python3 scorecard.py
#
set -euo pipefail

TARGET="127.0.0.1"          # loopback only - do not change; this is the safety boundary
USER_NAME="socdemo"
GOOD_PASS="Sup3rSecret!"
WRONG=(password 123456 admin letmein root toor qwerty welcome monkey dragon)

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "Run this on Kali (WSL) or another Linux machine, not Windows." >&2
    exit 1
fi
if [[ "${EUID}" -ne 0 ]]; then
    echo "Needs root to create a test user and manage ssh. Run: sudo ./lab/attack_lab.sh" >&2
    exit 1
fi

echo "[lab] target is ${TARGET} (your own loopback). Press Enter to continue, Ctrl+C to abort."
read -r _

cleanup() {
    echo "[lab] cleaning up test user '${USER_NAME}'..."
    pkill -u "${USER_NAME}" 2>/dev/null || true
    userdel -r "${USER_NAME}" 2>/dev/null || true
}
trap cleanup EXIT

echo "[lab] ensuring openssh-server, hydra and sshpass are installed..."
if ! command -v sshd >/dev/null || ! command -v hydra >/dev/null || ! command -v sshpass >/dev/null; then
    apt-get update -qq
    apt-get install -y -qq openssh-server hydra sshpass
fi

echo "[lab] starting ssh service..."
service ssh start 2>/dev/null || /usr/sbin/sshd 2>/dev/null || true
sleep 1

echo "[lab] creating throwaway user '${USER_NAME}'..."
userdel -r "${USER_NAME}" 2>/dev/null || true
useradd -m -s /bin/bash "${USER_NAME}"
echo "${USER_NAME}:${GOOD_PASS}" | chpasswd

WORDLIST="$(mktemp)"
printf '%s\n' "${WRONG[@]}" > "${WORDLIST}"

echo "[lab] === brute forcing ${TARGET} SSH (wrong passwords) ==="
# One retry at a time against localhost; these all fail and generate "Failed password" logs.
hydra -l "${USER_NAME}" -P "${WORDLIST}" -t 1 -W 1 -f "ssh://${TARGET}" 2>/dev/null || true
rm -f "${WORDLIST}"

echo "[lab] === one successful login (the compromise) ==="
if command -v sshpass >/dev/null; then
    sshpass -p "${GOOD_PASS}" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        "${USER_NAME}@${TARGET}" "echo logged-in" 2>/dev/null || true
else
    echo "[lab] (install sshpass for the automatic success step; or log in once by hand:"
    echo "       ssh ${USER_NAME}@${TARGET}   # password: ${GOOD_PASS} )"
fi

echo "[lab] done. Now run:  python3 scorecard.py"
