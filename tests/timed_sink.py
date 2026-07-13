#!/usr/bin/env python3
"""TCP sink that records delivery timing and content integrity."""
import hashlib
import json
import socket
import sys
import time

port = int(sys.argv[1]) if len(sys.argv) > 1 else 9999
out = sys.argv[2] if len(sys.argv) > 2 else "/tmp/sink_timeline.json"

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", port))
srv.listen(1)

conn, addr = srv.accept()
conn.setblocking(True)

t0 = time.monotonic()
samples = []       # (relative_ms, cumulative_bytes)
total = 0
buf = bytearray(65536)
digest = hashlib.sha256()

try:
    while True:
        n = conn.recv_into(buf)
        if n == 0:
            break
        total += n
        digest.update(memoryview(buf)[:n])
        t = (time.monotonic() - t0) * 1000.0  # ms
        samples.append((round(t, 2), total))
except (ConnectionResetError, BrokenPipeError):
    pass
finally:
    conn.close()
    srv.close()

with open(out, "w") as f:
    json.dump({"total_bytes": total, "sha256": digest.hexdigest(), "samples": samples}, f)

print(f"sink: {total} bytes, {len(samples)} samples, written to {out}", file=sys.stderr)
