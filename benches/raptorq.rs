//! Benchmarks the public `raptorq` primitives used by the application.
//!
//! Keep profile parameters aligned with the application's documented defaults
//! and validated limits.

use std::hint::black_box;
use std::time::Duration;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use raptorq::{
    EncodingPacket, ObjectTransmissionInformation, SourceBlockDecoder, SourceBlockEncoder,
};
use raptorq_pep::{BlockReceiver, BlockSender, FecProfile, RepairConfig};

const SYMBOL_SIZE: u16 = 1_400;

#[derive(Clone, Copy)]
struct Profile {
    name: &'static str,
    source_symbols: u16,
    proactive_repairs: u32,
}

const PROFILES: [Profile; 2] = [
    Profile {
        name: "default-k10-r5",
        source_symbols: 10,
        proactive_repairs: 5,
    },
    Profile {
        name: "larger-safe-k128-r64",
        source_symbols: 128,
        proactive_repairs: 64,
    },
];

fn fixture(profile: Profile) -> (ObjectTransmissionInformation, Vec<u8>) {
    let block_len = usize::from(profile.source_symbols) * usize::from(SYMBOL_SIZE);
    let data = (0..block_len)
        .map(|index| (index.wrapping_mul(31) & 0xff) as u8)
        .collect();
    let config = ObjectTransmissionInformation::new(
        block_len as u64,
        SYMBOL_SIZE,
        1, // source block
        1, // sub-block
        8, // alignment
    );
    (config, data)
}

fn encoder(profile: Profile) -> SourceBlockEncoder {
    let (config, data) = fixture(profile);
    SourceBlockEncoder::new(0, &config, &data)
}

fn bench_block_formation(c: &mut Criterion) {
    let mut group = c.benchmark_group("raptorq/block-formation");
    for profile in PROFILES {
        let (config, data) = fixture(profile);
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_function(BenchmarkId::from_parameter(profile.name), |b| {
            b.iter(|| {
                let encoder = SourceBlockEncoder::new(0, &config, black_box(&data));
                black_box(encoder.source_packets())
            });
        });
    }
    group.finish();
}

fn bench_proactive_repairs(c: &mut Criterion) {
    let mut group = c.benchmark_group("raptorq/proactive-repairs");
    for profile in PROFILES {
        let encoder = encoder(profile);
        group.throughput(Throughput::Elements(u64::from(profile.proactive_repairs)));
        group.bench_function(BenchmarkId::from_parameter(profile.name), |b| {
            b.iter(|| {
                black_box(encoder.repair_packets(0, profile.proactive_repairs));
            });
        });
    }
    group.finish();
}

fn bench_requested_repairs(c: &mut Criterion) {
    let mut group = c.benchmark_group("raptorq/requested-repair-generation");
    for profile in PROFILES {
        let encoder = encoder(profile);
        let requested = u32::from(profile.source_symbols);
        group.throughput(Throughput::Elements(u64::from(requested)));
        group.bench_function(BenchmarkId::from_parameter(profile.name), |b| {
            b.iter(|| {
                black_box(encoder.repair_packets(profile.proactive_repairs, black_box(requested)));
            });
        });
    }
    group.finish();
}

fn lossy_packets(profile: Profile, loss_percent: u32) -> Vec<EncodingPacket> {
    let encoder = encoder(profile);
    let source_symbols = u32::from(profile.source_symbols);
    let lost = source_symbols.saturating_mul(loss_percent).div_ceil(100);
    let mut packets: Vec<_> = encoder
        .source_packets()
        .into_iter()
        .enumerate()
        .filter_map(|(index, packet)| {
            let index = index as u32;
            let dropped = (index + 1).saturating_mul(lost) / source_symbols
                != index.saturating_mul(lost) / source_symbols;
            (!dropped).then_some(packet)
        })
        .collect();
    packets.extend(encoder.repair_packets(0, lost + 2));
    packets
}

fn decode(config: &ObjectTransmissionInformation, packets: Vec<EncodingPacket>) -> Option<Vec<u8>> {
    let mut decoder = SourceBlockDecoder::new(0, config, config.transfer_length());
    decoder.decode(packets)
}

fn bench_decode_under_loss(c: &mut Criterion) {
    let mut group = c.benchmark_group("raptorq/decode-under-source-loss");
    for profile in PROFILES {
        let (config, expected) = fixture(profile);
        for loss_percent in [10, 30] {
            let packets = lossy_packets(profile, loss_percent);
            assert_eq!(
                decode(&config, packets.clone()).as_deref(),
                Some(expected.as_slice()),
                "loss fixture must be decodable"
            );

            group.throughput(Throughput::Bytes(expected.len() as u64));
            group.bench_with_input(
                BenchmarkId::new(profile.name, format!("{loss_percent}-percent")),
                &packets,
                |b, packets| {
                    b.iter_batched(
                        || packets.clone(),
                        |packets| black_box(decode(&config, packets).expect("decodes")),
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }
    group.finish();
}

fn application_profile() -> FecProfile {
    FecProfile {
        k_max: 10,
        r_base: 5,
        timeout_ms: 20,
    }
}

fn application_repair() -> RepairConfig {
    RepairConfig {
        delay_ms: 50,
        retry_ms: 100,
        deadline_ms: 3000,
        max_reqs: 4,
    }
}

fn bench_application_fec(c: &mut Criterion) {
    let payload = vec![0x5a; usize::from(SYMBOL_SIZE) * 10];
    let mut group = c.benchmark_group("application-fec");
    group.throughput(Throughput::Bytes(payload.len() as u64));

    group.bench_function("form-default-block", |b| {
        b.iter_batched(
            || BlockSender::new(application_profile(), SYMBOL_SIZE, 256),
            |mut sender| black_box(sender.form_block(black_box(&payload))),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("requested-repair-batch", |b| {
        b.iter_batched(
            || {
                let mut sender = BlockSender::new(application_profile(), SYMBOL_SIZE, 256);
                sender.form_block(&payload);
                sender
            },
            |mut sender| black_box(sender.handle_repair_req(0, 10)),
            BatchSize::SmallInput,
        );
    });

    let mut sender = BlockSender::new(application_profile(), SYMBOL_SIZE, 256);
    let symbols = sender
        .form_block(&payload)
        .into_iter()
        .enumerate()
        .filter_map(|(index, symbol)| (!index.is_multiple_of(7)).then_some(symbol))
        .collect::<Vec<_>>();
    group.bench_function("decode-default-block-with-loss", |b| {
        b.iter_batched(
            || {
                (
                    BlockReceiver::new(SYMBOL_SIZE, application_repair(), 64, 10),
                    symbols.clone(),
                )
            },
            |(mut receiver, symbols)| {
                for symbol in symbols {
                    black_box(receiver.receive_symbol(symbol));
                }
                black_box(receiver.drain_deliverable())
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn criterion_config() -> Criterion {
    Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3))
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets =
        bench_block_formation,
        bench_proactive_repairs,
        bench_requested_repairs,
        bench_decode_under_loss,
        bench_application_fec
}
criterion_main!(benches);
