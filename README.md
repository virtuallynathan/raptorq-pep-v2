# raptorq-pep

A TCP-over-UDP tunnel with RaptorQ forward error correction and ChaCha20-Poly1305 encryption. Built for streaming over unreliable internet links with random packet loss and periodic multi-hundred-millisecond blackouts.

The included test tools exercise byte-exact delivery under random and burst loss. Performance claims should be reproduced for each deployment's bitrate, RTT, loss pattern, and FEC profile.

## How it works

```
OBS/ffmpeg                lossy link                     Twitch
    |                                                        |
    |  RTMP/TCP    +-----------+   FEC+AEAD/UDP   +-----------+   TCP
    +------------->| Local PEP |----------------->| Remote PEP |-------->
                   +-----------+                  +-----------+
                   (your machine)                  (your VPS)
```

The local PEP accepts concurrent TCP connections. Each connection becomes an
independent flow with its own RaptorQ encoder/decoder, repair budget, ordering,
credit, and close/reset lifecycle. A shared authenticated UDP session schedules
all flows without allowing one slow or failed flow to block the others.

The remote PEP authenticates UDP packets, reconstructs each flow from any
sufficient subset of symbols, and writes recovered byte streams to separate TCP
connections to the authorized destination.

If too many symbols are lost in a burst, the receiver requests additional repair symbols from the sender. The sender keeps a cache of recent blocks and can generate fresh repair symbols on demand.

## Requirements

- Rust 1.88+ (edition 2024; required by RaptorQ 2.0.1)
- A VPS or second machine for the remote endpoint
- A pre-shared key file (any file with 16+ bytes)

## Build

```bash
git clone https://github.com/virtuallynathan/raptorq-pep-v2
cd raptorq-pep
cargo build --release
```

The binary is at `target/release/raptorq-pep`.

For best performance, build with native CPU optimizations:

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

## Quick start

### 1. Generate a pre-shared key

```bash
head -c 32 /dev/urandom | base64 > psk.key
chmod 600 psk.key
```

Copy `psk.key` to both machines.

### 2. Start the remote side (on your VPS)

```bash
raptorq-pep \
  --mode remote \
  --udp-listen 0.0.0.0:9000 \
  --allow-target live.twitch.tv:1935 \
  --psk-file psk.key
```

This listens for UDP on port 9000. Each TCP flow requests the local side's
`--forward` target in its encrypted `OPEN` message, checked against each
remote-side `--allow-target` entry. Repeat `--allow-target` for multiple
destinations. Omitting it preserves the permissive single-owner behavior.

### 3. Start the local side (on your streaming machine)

```bash
raptorq-pep \
  --mode local \
  --tcp-listen 127.0.0.1:1935 \
  --peer YOUR_VPS_IP:9000 \
  --forward live.twitch.tv:1935 \
  --psk-file psk.key
```

This listens for TCP on port 1935, tunnels it through UDP, and tells the remote side which upstream destination to connect to via `--forward`.

### 4. Point OBS at the local PEP

In OBS, set the stream server to:

```
rtmp://127.0.0.1:1935/app
```

And enter your Twitch stream key as usual. OBS connects to the local PEP, which handles the rest.

### 5. Or use ffmpeg directly

```bash
ffmpeg -re -i video.mp4 \
  -c:v copy -c:a aac -b:a 160k -ar 44100 -ac 2 \
  -f flv "rtmp://127.0.0.1:1935/app/YOUR_STREAM_KEY"
```

## FEC tuning

The defaults are a production-oriented starting point for a 6 Mbps stream over
a lossy link. Measure and tune them for the actual path.

### Upstream (streamer to VPS)

| Flag | Default | Description |
|---|---|---|
| `--up-k-max` | 10 | Max source symbols per block. Higher = more efficient, but blocks take longer to fill. |
| `--up-r-base` | 5 | Proactive repair symbols per full block (33% of transmitted symbols). |
| `--up-timeout-ms` | 20 | Flush partial blocks after this many ms. Lower = less latency, more overhead for small blocks. |

### Downstream (VPS to streamer)

| Flag | Default | Description |
|---|---|---|
| `--down-k-max` | 5 | Smaller blocks for the low-bandwidth return path (RTMP ACKs). |
| `--down-r-base` | 3 | Proactive return-path repair symbols. |
| `--down-timeout-ms` | 50 | Return-path partial-block timeout. |

### Repair (retransmit fallback)

| Flag | Default | Description |
|---|---|---|
| `--repair-delay-ms` | 50 | Wait this long after first observing a gap before requesting repair. |
| `--repair-retry-ms` | 100 | Spacing between repair retries. |
| `--repair-deadline-ms` | 3000 | Fail only the affected TCP flow after this deadline. |
| `--repair-max-reqs` | 4 | Maximum repair requests per block. |

### Tuning for higher loss

For links with frequent burst loss (e.g., periodic blackouts from handovers or congestion):

```bash
# More proactive FEC, longer repair deadline
raptorq-pep --mode local \
  --tcp-listen 127.0.0.1:1935 \
  --peer YOUR_VPS:9000 \
  --forward live.twitch.tv:1935 \
  --psk-file psk.key \
  --up-r-base 8 \
  --repair-deadline-ms 3000 \
  --repair-max-reqs 4
```

For links with high steady-state loss:

```bash
# Heavy FEC overhead, less reliance on repair
raptorq-pep --mode local \
  --tcp-listen 127.0.0.1:1935 \
  --peer YOUR_VPS:9000 \
  --forward live.twitch.tv:1935 \
  --psk-file psk.key \
  --up-k-max 30 \
  --up-r-base 10
```

## Other options

| Flag | Default | Description |
|---|---|---|
| `--mtu` | 1500 | Network MTU. Symbol size is derived as MTU minus IP/UDP/header overhead. |
| `--ipv6` | false | Use IPv6 overhead calculation (120 bytes instead of 100). Auto-detected from addresses. |
| `--forward` | (none) | Upstream destination for remote-side TCP connect (`host:port` or `rtmp://host[:port]/...`). Required in local mode. |
| `--allow-target` | (permissive) | Remote-side exact target allowlist; repeat for multiple targets. |
| `--reorder-window` | 64 | Maximum out-of-order FEC blocks tracked per flow. |
| `--control-dups` | 2 | Copies of idempotent lifecycle/ACK controls sent with unique packet sequences. |
| `--max-send-mbps` | 50 | Aggregate tunnel send-rate cap. |

## Logging

Set the `RUST_LOG` environment variable:

```bash
RUST_LOG=info raptorq-pep --mode local ...    # session and flow lifecycle
RUST_LOG=debug raptorq-pep --mode local ...   # detailed recovery and scheduling
RUST_LOG=warn raptorq-pep --mode local ...    # failures and denied targets
```

## Firewall

Open UDP on the remote side:

```bash
# On VPS
sudo ufw allow 9000/udp
```

The local side initiates all UDP traffic, so no inbound rules are needed locally.

## Running the tests

```bash
cargo test
tests/local_e2e_test.sh             # unprivileged byte-exact loopback
```

Network namespace integration tests (requires root):

```bash
sudo tests/netns_test.sh            # no-loss byte-exact run
sudo tests/netns_test.sh --loss 5   # selected random-loss rate
sudo tests/burst_test.sh            # 6 Mbps with burst loss
sudo tests/burst_test.sh --baseline # no loss control run
```

## Architecture

```
src/
  main.rs        Entry point and logging setup
  app_v2.rs      Role startup, UDP binding, handshake supervision
  config.rs      CLI, validation, FEC profiles, target policy
  crypto.rs      Transcript-authenticated handshake and directional AEAD keys
  session_v2.rs  Loss-tolerant UDP handshake flights and replay history
  wire_v2.rs     Strict multi-flow wire codec
  runtime_v2.rs  UDP RX/TX, replay protection, pacing, flow registry
  flow_v2.rs     Independent TCP/FEC flow state, credit, FIN/reset lifecycle
  metrics.rs     Structured per-session counters and periodic reporting
  sender.rs      RaptorQ block encoder and bounded repair cache
  receiver.rs    Fail-closed decoder, repair timers, ordered delivery
  pacer.rs       Small-burst aggregate token-bucket pacer
  symbol.rs      Internal FEC symbol representation
```

Supply-chain checks and focused FEC benchmarks:

```bash
cargo deny check
cargo cyclonedx --format json --describe binaries --target all
cargo bench --bench raptorq
```

See `BENCHMARKS.md` for the current baseline.

## License

MIT
