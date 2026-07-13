#!/usr/bin/env bash
# twitch_stream.sh -- launch helper for raptorq-pep Twitch streaming setup
#
# Usage:
#   # On VPS (remote side)
#   ./tests/twitch_stream.sh remote --psk-file psk.key [--udp-listen 0.0.0.0:9000]
#
#   # On streaming machine (local side)
#   ./tests/twitch_stream.sh local --psk-file psk.key --peer YOUR_VPS_IP:9000 \
#       [--tcp-listen 127.0.0.1:1935] [--forward live.twitch.tv:1935]
#
# Notes:
# - Remote mode intentionally does NOT accept --forward.
# - Local mode owns --forward and defaults to live.twitch.tv:1935.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BIN="$PROJECT_DIR/target/release/raptorq-pep"
MODE="${1:-}"

if [[ -z "$MODE" ]]; then
    echo "ERROR: mode is required (local|remote)"
    exit 1
fi
shift

if [[ "$MODE" != "local" && "$MODE" != "remote" ]]; then
    echo "ERROR: invalid mode '$MODE' (expected local or remote)"
    exit 1
fi

PSK_FILE=""
UDP_LISTEN="0.0.0.0:9000"
TCP_LISTEN="127.0.0.1:1935"
PEER=""
FORWARD="live.twitch.tv:1935"
FORWARD_SET=false
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --psk-file)
            PSK_FILE="${2:-}"
            shift 2
            ;;
        --udp-listen)
            UDP_LISTEN="${2:-}"
            shift 2
            ;;
        --tcp-listen)
            TCP_LISTEN="${2:-}"
            shift 2
            ;;
        --peer)
            PEER="${2:-}"
            shift 2
            ;;
        --forward)
            FORWARD="${2:-}"
            FORWARD_SET=true
            shift 2
            ;;
        --)
            shift
            EXTRA_ARGS+=("$@")
            break
            ;;
        *)
            EXTRA_ARGS+=("$1")
            shift
            ;;
    esac
done

if [[ ! -x "$BIN" ]]; then
    echo "ERROR: binary not found at $BIN"
    echo "Run: cargo build --release --bin raptorq-pep"
    exit 1
fi

if [[ -z "$PSK_FILE" ]]; then
    echo "ERROR: --psk-file is required"
    exit 1
fi

if [[ "$MODE" == "remote" ]]; then
    if [[ "$FORWARD_SET" == true ]]; then
        echo "ERROR: --forward is only valid in local mode"
        exit 1
    fi

    exec "$BIN" \
        --mode remote \
        --udp-listen "$UDP_LISTEN" \
        --psk-file "$PSK_FILE" \
        "${EXTRA_ARGS[@]}"
fi

if [[ -z "$PEER" ]]; then
    echo "ERROR: --peer is required in local mode"
    exit 1
fi

exec "$BIN" \
    --mode local \
    --tcp-listen "$TCP_LISTEN" \
    --peer "$PEER" \
    --forward "$FORWARD" \
    --psk-file "$PSK_FILE" \
    "${EXTRA_ARGS[@]}"