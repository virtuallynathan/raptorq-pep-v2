#!/usr/bin/env bash
# netns_test.sh — end-to-end test using network namespaces
#
# Usage: sudo ./tests/netns_test.sh [--loss PERCENT]
#
# Creates two netns (pep_local, pep_remote) connected by a veth pair,
# runs local+remote PEP instances, pipes data through, and verifies
# byte-exact output.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BIN="$PROJECT_DIR/target/release/raptorq-pep"
PSK_FILE=$(mktemp)
TEST_INPUT=$(mktemp)
TEST_OUTPUT=$(mktemp)
LOSS="${1:-0}"
if [[ "${1:-}" == "--loss" ]]; then LOSS="${2:-5}"; fi

RUN_SUFFIX="$$-${RANDOM}"
NS_LOCAL="rqp-local-${RUN_SUFFIX}"
NS_REMOTE="rqp-remote-${RUN_SUFFIX}"
VETH_LOCAL="rql$$"
VETH_REMOTE="rqr$$"
LOCAL_IP="10.99.0.1"
REMOTE_IP="10.99.0.2"
ECHO_PORT=9999
TCP_PORT=1935
UDP_PORT=9000

cleanup() {
    echo "[*] Cleaning up..."
    # Kill background processes
    kill $(jobs -p) 2>/dev/null || true
    wait 2>/dev/null || true
    # Remove namespaces
    ip netns del "$NS_LOCAL" 2>/dev/null || true
    ip netns del "$NS_REMOTE" 2>/dev/null || true
    rm -f "$PSK_FILE" "$TEST_INPUT" "$TEST_OUTPUT"
}
trap cleanup EXIT

echo "[*] Checking prerequisites..."
if [[ ! -x "$BIN" ]]; then
    echo "ERROR: Binary not found at $BIN. Run: cargo build --release"
    exit 1
fi
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Must run as root (need network namespaces)"
    exit 1
fi

# --- Setup namespaces ---
echo "[*] Creating network namespaces..."
ip netns add "$NS_LOCAL"
ip netns add "$NS_REMOTE"

# Create veth pair
ip link add "$VETH_LOCAL" type veth peer name "$VETH_REMOTE"
ip link set "$VETH_LOCAL" netns "$NS_LOCAL"
ip link set "$VETH_REMOTE" netns "$NS_REMOTE"

# Configure IPs
ip netns exec "$NS_LOCAL" ip addr add "${LOCAL_IP}/24" dev "$VETH_LOCAL"
ip netns exec "$NS_LOCAL" ip link set "$VETH_LOCAL" up
ip netns exec "$NS_LOCAL" ip link set lo up

ip netns exec "$NS_REMOTE" ip addr add "${REMOTE_IP}/24" dev "$VETH_REMOTE"
ip netns exec "$NS_REMOTE" ip link set "$VETH_REMOTE" up
ip netns exec "$NS_REMOTE" ip link set lo up

# --- Optional: add loss with netem ---
if [[ "$LOSS" != "0" ]]; then
    echo "[*] Adding ${LOSS}% packet loss (both directions)..."
    ip netns exec "$NS_LOCAL" tc qdisc add dev "$VETH_LOCAL" root netem loss "${LOSS}%" 25%
    ip netns exec "$NS_REMOTE" tc qdisc add dev "$VETH_REMOTE" root netem loss "${LOSS}%" 25%
fi

# --- Generate PSK ---
echo "[*] Generating PSK..."
head -c 32 /dev/urandom | base64 > "$PSK_FILE"
chmod 600 "$PSK_FILE"

# --- Generate test data ---
echo "[*] Generating test data (256KB)..."
dd if=/dev/urandom of="$TEST_INPUT" bs=1024 count=256 2>/dev/null

# --- Start TCP echo server in remote namespace ---
echo "[*] Starting TCP echo server on ${REMOTE_IP}:${ECHO_PORT}..."
ip netns exec "$NS_REMOTE" socat TCP-LISTEN:${ECHO_PORT},reuseaddr,fork EXEC:cat &
ECHO_PID=$!
sleep 0.3

# --- Start remote PEP ---
echo "[*] Starting remote PEP..."
ip netns exec "$NS_REMOTE" env RUST_LOG=raptorq_pep=info "$BIN" \
    --mode remote \
    --udp-listen "0.0.0.0:${UDP_PORT}" \
    --psk-file "$PSK_FILE" \
    --mtu 1500 \
    --up-k-max 50 --up-r-base 5 --up-timeout-ms 100 \
    --down-k-max 5 --down-r-base 2 --down-timeout-ms 250 \
    --max-send-mbps 50 \
    --repair-deadline-ms 2000 &
REMOTE_PID=$!
sleep 0.5

# --- Start local PEP ---
echo "[*] Starting local PEP..."
ip netns exec "$NS_LOCAL" env RUST_LOG=raptorq_pep=info "$BIN" \
    --mode local \
    --tcp-listen "0.0.0.0:${TCP_PORT}" \
    --peer "${REMOTE_IP}:${UDP_PORT}" \
    --forward "127.0.0.1:${ECHO_PORT}" \
    --psk-file "$PSK_FILE" \
    --mtu 1500 \
    --up-k-max 50 --up-r-base 5 --up-timeout-ms 100 \
    --down-k-max 5 --down-r-base 2 --down-timeout-ms 250 \
    --max-send-mbps 50 \
    --repair-deadline-ms 2000 &
LOCAL_PID=$!
sleep 1.0

# --- Send data through the tunnel ---
echo "[*] Sending 256KB through tunnel (echo test)..."
ip netns exec "$NS_LOCAL" \
    socat -t 10 \
    STDIO \
    "TCP:127.0.0.1:${TCP_PORT}" \
    < "$TEST_INPUT" \
    > "$TEST_OUTPUT" 2>/dev/null || true

sleep 3

# --- Verify ---
echo "[*] Verifying output..."
INPUT_HASH=$(sha256sum "$TEST_INPUT" | cut -d' ' -f1)
OUTPUT_HASH=$(sha256sum "$TEST_OUTPUT" | cut -d' ' -f1)

INPUT_SIZE=$(wc -c < "$TEST_INPUT")
OUTPUT_SIZE=$(wc -c < "$TEST_OUTPUT")

echo "    Input:  ${INPUT_SIZE} bytes, sha256=${INPUT_HASH:0:16}..."
echo "    Output: ${OUTPUT_SIZE} bytes, sha256=${OUTPUT_HASH:0:16}..."

if [[ "$INPUT_HASH" == "$OUTPUT_HASH" ]]; then
    echo ""
    echo "=== PASS: byte-exact match (loss=${LOSS}%) ==="
    exit 0
else
    echo ""
    echo "=== FAIL: output does not match input ==="
    echo "    Input size:  $INPUT_SIZE"
    echo "    Output size: $OUTPUT_SIZE"
    exit 1
fi
