# RaptorQ benchmarks

Run the focused Criterion suite with:

```sh
cargo bench --bench raptorq
```

The suite measures encoder and source-symbol formation, proactive repair
generation, requested repair generation, and decoding after deterministic 10%
and 30% source-symbol loss. It covers the application's default `k10/r5`
profile and a larger, validated-safe `k128/r64` profile, both with the default
IPv4 symbol size of 1400 bytes.

It also benchmarks the exported production FEC layer directly:
`BlockSender::form_block`, cached requested repairs, and
`BlockReceiver` decode/reorder behavior under deterministic symbol loss.

## Baseline (2026-07-13)

Apple M4 Max, release profile, Criterion 20-sample run:

- Default k10/r5: block formation 14.19 µs; five proactive repairs 0.974 µs;
  ten requested repairs 2.09 µs; decode under 10–30% source loss
  26.9–27.0 µs.
- Larger k128/r64: block formation 135.0 µs; 64 proactive repairs 18.4 µs;
  128 requested repairs 40.2 µs; decode under 10–30% source loss
  250.8–260.0 µs.
- Production application layer at k10/r5: `BlockSender::form_block` 17.0 µs;
  cached ten-symbol repair request 4.71 µs; `BlockReceiver` decode/reorder
  under deterministic loss 25.4 µs.

Criterion comparisons from a busy development host can report changes even
when the RaptorQ dependency is unchanged. Treat this run as a baseline and use
isolated CI hardware before enforcing regression thresholds.
