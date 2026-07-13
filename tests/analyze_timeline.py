#!/usr/bin/env python3
"""Analyze delivery timeline from timed_sink.py output.

Reports: stall durations, delivery gaps, buffer requirements,
and whether Twitch RTMP ingest would drop frames.
"""
import json, sys

path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/sink_timeline.json"
target_mbps = float(sys.argv[2]) if len(sys.argv) > 2 else 6.0
target_bps = target_mbps * 1e6 / 8  # bytes/sec

with open(path) as f:
    data = json.load(f)

samples = data["samples"]  # [(ms, cumulative_bytes), ...]
total = data["total_bytes"]

if len(samples) < 2:
    print("Not enough samples for analysis")
    sys.exit(1)

# --- Delivery gaps ---
# Time between consecutive recv() calls that returned data
gaps = []
for i in range(1, len(samples)):
    dt = samples[i][0] - samples[i-1][0]
    db = samples[i][1] - samples[i-1][1]
    gaps.append((samples[i][0], dt, db))

gaps_sorted = sorted(gaps, key=lambda x: -x[1])  # longest first

# --- Stall analysis ---
# A "stall" is a gap where no data arrives for > threshold
STALL_THRESHOLD_MS = 50  # >50ms gap = potential stall
stalls = [(t, dt, db) for t, dt, db in gaps if dt > STALL_THRESHOLD_MS]
stalls_sorted = sorted(stalls, key=lambda x: -x[1])

# --- Ideal vs actual delivery curve ---
# If data arrived at a constant rate, bytes(t) = t * target_bps / 1000
# "Delivery lag" = how far behind ideal the actual delivery is
max_lag_ms = 0
max_lag_at = 0
for t_ms, cum_bytes in samples:
    ideal_bytes = t_ms * target_bps / 1000.0
    if cum_bytes < ideal_bytes:
        lag_bytes = ideal_bytes - cum_bytes
        lag_ms = lag_bytes / target_bps * 1000.0
        if lag_ms > max_lag_ms:
            max_lag_ms = lag_ms
            max_lag_at = t_ms

# --- Buffer requirement ---
# How much buffer would an RTMP decoder need to avoid underrun?
# This is the maximum "delivery debt" in time units.
# If max_lag exceeds the decoder buffer, frames drop.
TYPICAL_OBS_BUFFER_MS = 2000  # OBS default buffer
TWITCH_DISCONNECT_MS = 10000  # Twitch drops after ~10s no data

duration_ms = samples[-1][0] - samples[0][0]
actual_mbps = total * 8 / (duration_ms / 1000) / 1e6 if duration_ms > 0 else 0

# --- Output ---
print("=" * 64)
print(" DELIVERY TIMING ANALYSIS")
print("=" * 64)
print(f"  Duration:        {duration_ms/1000:.1f}s")
print(f"  Total:           {total/1e6:.2f} MB in {len(samples)} recv() calls")
print(f"  Avg throughput:  {actual_mbps:.2f} Mbps (target {target_mbps})")
print()

print("--- Delivery gaps ---")
print(f"  Total gaps:      {len(gaps)}")
print(f"  Median gap:      {sorted([g[1] for g in gaps])[len(gaps)//2]:.1f}ms")
p95 = sorted([g[1] for g in gaps])[int(len(gaps)*0.95)]
p99 = sorted([g[1] for g in gaps])[int(len(gaps)*0.99)]
print(f"  P95 gap:         {p95:.1f}ms")
print(f"  P99 gap:         {p99:.1f}ms")
print(f"  Max gap:         {gaps_sorted[0][1]:.1f}ms at t={gaps_sorted[0][0]:.0f}ms")
print()

print("--- Stalls (gaps > 50ms) ---")
if stalls:
    print(f"  Count:           {len(stalls)}")
    print(f"  Total stall:     {sum(s[1] for s in stalls):.0f}ms")
    for i, (t, dt, db) in enumerate(stalls_sorted[:10]):
        print(f"    #{i+1}: {dt:.0f}ms stall at t={t:.0f}ms ({db} bytes after)")
else:
    print("  None")
print()

print("--- Frame drop risk ---")
print(f"  Max delivery lag: {max_lag_ms:.0f}ms at t={max_lag_at:.0f}ms")
if max_lag_ms < TYPICAL_OBS_BUFFER_MS:
    print(f"  OBS buffer (2s):  SAFE (lag {max_lag_ms:.0f}ms < 2000ms)")
else:
    print(f"  OBS buffer (2s):  FRAMES WOULD DROP (lag {max_lag_ms:.0f}ms > 2000ms)")
if max_lag_ms < TWITCH_DISCONNECT_MS:
    print(f"  Twitch ingest:    SAFE (lag {max_lag_ms:.0f}ms < 10000ms)")
else:
    print(f"  Twitch ingest:    WOULD DISCONNECT (lag {max_lag_ms:.0f}ms > 10000ms)")
print()

# --- Burst recovery profile ---
# For each stall > 100ms, show the recovery: how quickly does delivery
# catch up to the ideal rate after the stall?
big_stalls = [(t, dt, db) for t, dt, db in stalls if dt > 100]
if big_stalls:
    print("--- Burst recovery ---")
    for t_stall, dt_stall, db_after in sorted(big_stalls, key=lambda x: x[0]):
        # Find the delivery rate in the 500ms after the stall
        post_start = t_stall
        post_end = t_stall + 500
        post_bytes = 0
        for t, cum in samples:
            if t > post_start and t <= post_end:
                # Find bytes delivered in this window
                pass
        # Simpler: just report the stall and burst-after
        debt_ms = dt_stall  # how far behind we fell
        burst_bytes = db_after  # how much arrived in the first recv after stall
        burst_mbps = burst_bytes * 8 / (1 * 1e-3) / 1e6 if db_after > 0 else 0  # instantaneous
        print(f"  t={t_stall:.0f}ms: {dt_stall:.0f}ms stall, {db_after/1024:.0f}KB burst-after")
    print()

print("=" * 64)
