#!/usr/bin/env bash
# burst_test.sh -- 6 Mbps TCP through PEP under burst loss
#
# Simulates a crappy link: 25ms one-way delay (50ms RTT),
# periodic 100-500ms total blackouts every 2-5 seconds.
#
# Usage: sudo ./tests/burst_test.sh [--duration SECS] [--burst-ms MIN-MAX] [--baseline]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BIN="$PROJECT_DIR/target/release/raptorq-pep"
TMP_DIR=$(mktemp -d)
PSK_FILE="$TMP_DIR/psk.key"
STREAM_INPUT="$TMP_DIR/input.bin"
TIMELINE="$TMP_DIR/sink_timeline.json"

RUN_SUFFIX="$$-${RANDOM}"
NS_LOCAL="rqp-local-${RUN_SUFFIX}"
NS_REMOTE="rqp-remote-${RUN_SUFFIX}"
VETH_LOCAL="rql$$"
VETH_REMOTE="rqr$$"
LOCAL_IP="10.99.0.1"
REMOTE_IP="10.99.0.2"
SINK_PORT=9999
TCP_PORT=1935
UDP_PORT=9000
DURATION=20
TARGET_MBPS=6
BURST_MIN=100
BURST_MAX=500
BASELINE=false
ONE_WAY_DELAY=25
GOOD_MIN=2000
GOOD_MAX=5000

while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration)   DURATION="$2"; shift 2 ;;
        --burst-ms)   IFS='-' read -r BURST_MIN BURST_MAX <<< "$2"; shift 2 ;;
        --baseline)   BASELINE=true; shift ;;
        --rate-mbps)  TARGET_MBPS="$2"; shift 2 ;;
        *)            echo "Unknown arg: $1"; exit 1 ;;
    esac
done

RATE_BYTES=$(( TARGET_MBPS * 1000000 / 8 ))  # bytes/sec

cleanup() {
    echo ""
    echo "[*] Cleaning up..."
    kill $(jobs -p) 2>/dev/null || true
    wait 2>/dev/null || true
    ip netns del "$NS_LOCAL" 2>/dev/null || true
    ip netns del "$NS_REMOTE" 2>/dev/null || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "================================================================"
echo " raptorq-pep burst loss test"
echo " Duration: ${DURATION}s | Rate: ${TARGET_MBPS} Mbps"
echo " RTT: $((ONE_WAY_DELAY * 2))ms (${ONE_WAY_DELAY}ms/dir)"
if $BASELINE; then
    echo " Mode: BASELINE (no burst loss)"
else
    echo " Burst: ${BURST_MIN}-${BURST_MAX}ms blackout / ${GOOD_MIN}-${GOOD_MAX}ms good"
fi
echo "================================================================"
echo ""

if [[ ! -x "$BIN" ]]; then echo "ERROR: cargo build --release first"; exit 1; fi
if [[ $EUID -ne 0 ]]; then echo "ERROR: Must run as root"; exit 1; fi

# --- Namespaces ---
echo "[*] Creating namespaces + veth..."
ip netns add "$NS_LOCAL"
ip netns add "$NS_REMOTE"
ip link add "$VETH_LOCAL" type veth peer name "$VETH_REMOTE"
ip link set "$VETH_LOCAL" netns "$NS_LOCAL"
ip link set "$VETH_REMOTE" netns "$NS_REMOTE"
for ns_dev in "$NS_LOCAL $VETH_LOCAL $LOCAL_IP" "$NS_REMOTE $VETH_REMOTE $REMOTE_IP"; do
    read -r ns dev ip <<< "$ns_dev"
    ip netns exec "$ns" ip addr add "${ip}/24" dev "$dev"
    ip netns exec "$ns" ip link set "$dev" up
    ip netns exec "$ns" ip link set lo up
done

echo "[*] Adding ${ONE_WAY_DELAY}ms delay each direction..."
ip netns exec "$NS_LOCAL"  tc qdisc add dev "$VETH_LOCAL"  root handle 1: netem delay ${ONE_WAY_DELAY}ms 2ms
ip netns exec "$NS_REMOTE" tc qdisc add dev "$VETH_REMOTE" root handle 1: netem delay ${ONE_WAY_DELAY}ms 2ms

head -c 32 /dev/urandom | base64 > "$PSK_FILE"
chmod 600 "$PSK_FILE"

# --- TCP timestamped sink (remote ns) ---
echo "[*] Starting timestamped TCP sink on remote:${SINK_PORT}..."
ip netns exec "$NS_REMOTE" python3 "$SCRIPT_DIR/timed_sink.py" "$SINK_PORT" "$TIMELINE" &
SINK_PID=$!
sleep 0.3

# --- PEPs ---
REPAIR_DEADLINE=$((BURST_MAX + 2500))

echo "[*] Starting remote PEP..."
ip netns exec "$NS_REMOTE" env RUST_LOG=raptorq_pep=info "$BIN" \
    --mode remote \
    --udp-listen "0.0.0.0:${UDP_PORT}" \
    --psk-file "$PSK_FILE" --mtu 1500 \
    --up-k-max 50 --up-r-base 5 --up-timeout-ms 50 \
    --down-k-max 5  --down-r-base 2 --down-timeout-ms 250 \
    --repair-delay-ms 100 --repair-retry-ms 200 \
    --repair-deadline-ms "$REPAIR_DEADLINE" --repair-max-reqs 4 \
    --max-send-mbps 50 &
sleep 0.5

echo "[*] Starting local PEP..."
ip netns exec "$NS_LOCAL" env RUST_LOG=raptorq_pep=info "$BIN" \
    --mode local \
    --tcp-listen "0.0.0.0:${TCP_PORT}" \
    --peer "${REMOTE_IP}:${UDP_PORT}" \
    --forward "127.0.0.1:${SINK_PORT}" \
    --psk-file "$PSK_FILE" --mtu 1500 \
    --up-k-max 50 --up-r-base 5 --up-timeout-ms 50 \
    --down-k-max 5  --down-r-base 2 --down-timeout-ms 250 \
    --repair-delay-ms 100 --repair-retry-ms 200 \
    --repair-deadline-ms "$REPAIR_DEADLINE" --repair-max-reqs 4 \
    --max-send-mbps 50 &
sleep 1.0

# --- Burst loss injector ---
inject_bursts() {
    local burst_count=0 total_burst_ms=0
    while true; do
        local good_ms=$(( RANDOM % (GOOD_MAX - GOOD_MIN + 1) + GOOD_MIN ))
        sleep "$(echo "scale=3; $good_ms / 1000" | bc)"

        local burst_ms=$(( RANDOM % (BURST_MAX - BURST_MIN + 1) + BURST_MIN ))
        burst_count=$((burst_count + 1))
        total_burst_ms=$((total_burst_ms + burst_ms))
        echo "  [burst #${burst_count}] ${burst_ms}ms blackout (total: ${total_burst_ms}ms)" >&2

        ip netns exec "$NS_LOCAL"  tc qdisc change dev "$VETH_LOCAL"  root handle 1: netem delay ${ONE_WAY_DELAY}ms 2ms loss 100%
        ip netns exec "$NS_REMOTE" tc qdisc change dev "$VETH_REMOTE" root handle 1: netem delay ${ONE_WAY_DELAY}ms 2ms loss 100%
        sleep "$(echo "scale=3; $burst_ms / 1000" | bc)"
        ip netns exec "$NS_LOCAL"  tc qdisc change dev "$VETH_LOCAL"  root handle 1: netem delay ${ONE_WAY_DELAY}ms 2ms loss 0%
        ip netns exec "$NS_REMOTE" tc qdisc change dev "$VETH_REMOTE" root handle 1: netem delay ${ONE_WAY_DELAY}ms 2ms loss 0%
    done
}

if ! $BASELINE; then
    echo "[*] Starting burst loss injector..."
    inject_bursts &
    BURST_PID=$!
fi

# --- Stream data at target rate ---
TOTAL_BYTES=$(( RATE_BYTES * DURATION ))
TOTAL_MB=$(echo "scale=1; $TOTAL_BYTES / 1000000" | bc)
head -c "$TOTAL_BYTES" /dev/urandom > "$STREAM_INPUT"
INPUT_HASH=$(sha256sum "$STREAM_INPUT" | cut -d' ' -f1)
echo "[*] Streaming ${TOTAL_MB} MB at ${TARGET_MBPS} Mbps for ${DURATION}s..."
echo ""

T_START=$(date +%s%N)

STREAM_FAILED=false
if ! pv -s "$TOTAL_BYTES" -L "$RATE_BYTES" -f "$STREAM_INPUT" 2>/dev/null \
    | ip netns exec "$NS_LOCAL" socat -t 10 STDIN "TCP:127.0.0.1:${TCP_PORT}" 2>/dev/null; then
    STREAM_FAILED=true
fi

T_END=$(date +%s%N)
ELAPSED_NS=$(( T_END - T_START ))
ELAPSED_S=$(echo "scale=2; $ELAPSED_NS / 1000000000" | bc)

# Wait for drain
echo ""
echo "[*] Waiting for tunnel drain..."
sleep 5

# Stop burst injector so we can read final stats
if ! $BASELINE; then
    kill "$BURST_PID" 2>/dev/null || true
fi

# --- Results ---
if [[ -f "$TIMELINE" ]]; then
    RECV_BYTES=$(python3 -c "import json; print(json.load(open('$TIMELINE'))['total_bytes'])")
    RECV_HASH=$(python3 -c "import json; print(json.load(open('$TIMELINE'))['sha256'])")
else
    RECV_BYTES=0
    RECV_HASH=""
fi
RECV_MB=$(echo "scale=2; $RECV_BYTES / 1000000" | bc)
DELIVERY_PCT=$(echo "scale=1; $RECV_BYTES * 100 / $TOTAL_BYTES" | bc 2>/dev/null || echo 0)

echo ""
echo "================================================================"
echo " BYTE DELIVERY"
echo "================================================================"
echo "  Sent:         ${TOTAL_MB} MB (target ${TARGET_MBPS} Mbps × ${DURATION}s)"
echo "  Received:     ${RECV_MB} MB"
echo "  Delivery:     ${DELIVERY_PCT}%"
echo "  Input hash:   ${INPUT_HASH}"
echo "  Output hash:  ${RECV_HASH:-missing}"
echo "================================================================"
echo ""

# --- Timing analysis ---
if [[ -f "$TIMELINE" ]]; then
    python3 "$SCRIPT_DIR/analyze_timeline.py" "$TIMELINE" "$TARGET_MBPS"
fi

if $STREAM_FAILED || [[ "$RECV_BYTES" -ne "$TOTAL_BYTES" ]] || [[ "$RECV_HASH" != "$INPUT_HASH" ]]; then
    echo "=== FAIL: burst test did not deliver byte-exact output ==="
    exit 1
fi

echo "=== PASS: burst test delivered byte-exact output ==="