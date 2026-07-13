#!/usr/bin/env bash
# local_e2e_test.sh -- unprivileged loopback E2E validation for raptorq-pep
#
# Usage:
#   ./tests/local_e2e_test.sh
#
# Optional env vars:
#   BIN=/path/to/raptorq-pep
#   PAYLOAD_BYTES=1048576
#   FLOW_COUNT=4
#   MAX_SEND_MBPS=50

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BIN="${BIN:-$PROJECT_DIR/target/debug/raptorq-pep}"
PAYLOAD_BYTES="${PAYLOAD_BYTES:-1048576}"
FLOW_COUNT="${FLOW_COUNT:-4}"
MAX_SEND_MBPS="${MAX_SEND_MBPS:-50}"

if [[ ! -x "$BIN" ]]; then
    echo "ERROR: binary not found at $BIN"
    echo "Run: cargo build --bin raptorq-pep"
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is required"
    exit 1
fi

TMP_DIR="$(mktemp -d)"
PSK_FILE="$TMP_DIR/psk.key"
ECHO_PID=""
REMOTE_PID=""
LOCAL_PID=""

cleanup() {
    status=$?
    set +e
    if [[ -n "$LOCAL_PID" ]]; then kill "$LOCAL_PID" >/dev/null 2>&1; fi
    if [[ -n "$REMOTE_PID" ]]; then kill "$REMOTE_PID" >/dev/null 2>&1; fi
    if [[ -n "$ECHO_PID" ]]; then kill "$ECHO_PID" >/dev/null 2>&1; fi
    wait >/dev/null 2>&1
    if [[ "$status" -ne 0 ]]; then
        echo "--- remote.log ---"
        cat "$TMP_DIR/remote.log" 2>/dev/null
        echo "--- local.log ---"
        cat "$TMP_DIR/local.log" 2>/dev/null
        echo "--- echo.log ---"
        cat "$TMP_DIR/echo.log" 2>/dev/null
    fi
    rm -rf "$TMP_DIR"
    exit "$status"
}
trap cleanup EXIT

printf '0123456789abcdef0123456789abcdef' > "$PSK_FILE"

read -r UDP_PORT LOCAL_TCP_PORT ECHO_PORT < <(python3 - <<'PY'
import socket
ports = []
socks = []
for _ in range(3):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    ports.append(s.getsockname()[1])
    socks.append(s)
print(*ports)
for s in socks:
    s.close()
PY
)

echo "[*] Using ports: udp=${UDP_PORT} local_tcp=${LOCAL_TCP_PORT} echo=${ECHO_PORT}"

echo "[*] Starting loopback echo sink..."
python3 "$SCRIPT_DIR/tcp_echo.py" "$ECHO_PORT" > "$TMP_DIR/echo.log" 2>&1 &
ECHO_PID=$!
sleep 0.25

echo "[*] Starting remote PEP..."
env RUST_LOG="${RUST_LOG:-warn}" "$BIN" \
  --mode remote \
  --udp-listen "127.0.0.1:${UDP_PORT}" \
  --allow-target "127.0.0.1:${ECHO_PORT}" \
  --psk-file "$PSK_FILE" \
  --max-send-mbps "$MAX_SEND_MBPS" \
  > "$TMP_DIR/remote.log" 2>&1 &
REMOTE_PID=$!
sleep 0.40

echo "[*] Starting local PEP..."
env RUST_LOG="${RUST_LOG:-warn}" "$BIN" \
  --mode local \
  --tcp-listen "127.0.0.1:${LOCAL_TCP_PORT}" \
  --peer "127.0.0.1:${UDP_PORT}" \
  --forward "127.0.0.1:${ECHO_PORT}" \
  --psk-file "$PSK_FILE" \
  --max-send-mbps "$MAX_SEND_MBPS" \
  > "$TMP_DIR/local.log" 2>&1 &
LOCAL_PID=$!
sleep 1

for pid in "$ECHO_PID" "$REMOTE_PID" "$LOCAL_PID"; do
    if ! kill -0 "$pid" >/dev/null 2>&1; then
        echo "ERROR: process $pid exited unexpectedly"
        echo "--- remote.log ---"
        cat "$TMP_DIR/remote.log"
        echo "--- local.log ---"
        cat "$TMP_DIR/local.log"
        exit 1
    fi
done

echo "[*] Sending ${FLOW_COUNT} concurrent flows of ${PAYLOAD_BYTES} bytes..."
LOCAL_TCP_PORT="$LOCAL_TCP_PORT" PAYLOAD_BYTES="$PAYLOAD_BYTES" FLOW_COUNT="$FLOW_COUNT" python3 - <<'PY'
import concurrent.futures
import hashlib
import os
import socket

payload_size = int(os.environ["PAYLOAD_BYTES"])
local_tcp_port = int(os.environ["LOCAL_TCP_PORT"])
flow_count = int(os.environ["FLOW_COUNT"])


def run_flow(flow_id):
    payload = bytes(((i + flow_id * 31) % 256 for i in range(payload_size)))
    sock = socket.create_connection(("127.0.0.1", local_tcp_port), timeout=5)
    sock.settimeout(10)
    sock.sendall(payload)
    sock.shutdown(socket.SHUT_WR)

    received = bytearray()
    while len(received) < payload_size:
        chunk = sock.recv(65536)
        if not chunk:
            break
        received.extend(chunk)
    sock.close()

    recv = bytes(received)
    if recv != payload:
        raise RuntimeError(
            f"flow={flow_id} payload mismatch sent={len(payload)} recv={len(recv)}"
        )
    return flow_id, hashlib.sha256(recv).hexdigest()


with concurrent.futures.ThreadPoolExecutor(max_workers=flow_count) as executor:
    for flow_id, digest in executor.map(run_flow, range(flow_count)):
        print(f"flow={flow_id} e2e-bytes={payload_size} sha256={digest}")
PY

echo "[*] PASS: unprivileged local<->remote loopback tunnel validation succeeded"