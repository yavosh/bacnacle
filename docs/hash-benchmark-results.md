# Whole-file hash experiment, 2026-11-18

**Stop the disk-backed whole-file hash experiment for this generation.** Both disk backends fell short of the frozen 57 MiB memory threshold.

## Setup

Each measurement used a fresh Debian 13.7 arm64 kernel and a private ext4 image on virtio block storage.
The Apple M5 host had 32 GiB RAM and ran macOS 27.2.1.
Apple Virtualization exposed one vCPU and 2 GiB RAM. Host disk-image caching was disabled.
The Linux release binaries used Rust 1.99.1 and the locked dependencies. An internal SSD backed the disk images.
The kernel was `6.12.117+deb13-arm64`. No guest swap was configured.
The scanner cgroup used a 1,400 MiB soft limit, a 1,536 MiB hard limit, and zero swap.
A fresh boot reset the guest page cache. Full index validation charged its file pages to the scanner before lookup.
“Cold” is the first trace after that validation. The warm trace used the same process.
The guest had no network and ran no concurrent application workloads.

The stock daemon used the full verified snapshot. All Rust backends used the same 540,471-key index.
The 65,536 digest queries sampled from 541,991 eligible records before duplicate resolution.
The index SHA-256 was `f6ab2fe6c2e908d4cc0961554e6f71b38c7db643f28eb000c191a65e5e2140bb`.
The digest trace SHA-256 was `78a45a2496c1bfd6eaeaad8aec2ef22d479daf9881c1b6d85df221eeec36a6c1`.
The file corpus and digest input pages were populated in the driver cgroup.
The Rust scanner cgroup included the in-process harness, worker allocations, decoded queries, result buffers, and index cache.
The stock cgroup included clamd and its database cache. Stock timings include its socket client and clean-file cache.
The guest measured local scanner costs in isolation from application workloads and external memory pressure.

Read the [input inventory](whole-file-hashes.md), [measurement protocol](hash-baseline.md), and [reproduction commands](hash-benchmark-run.md).

## Stock threshold

The threshold was frozen at 19:56:11 UTC before timing any Rust matcher.
The median four-request idle reading was 1,188,708,352 bytes. Five percent rounds up to **57 MiB**.
All 81,920 stock requests returned clean. The tables report independent medians of five trials.

| Requests in flight | Cold files/s | Warm files/s | Cold p95 (ms) | Warm p95 (ms) | Idle (MiB) | Peak (MiB) |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 165.5 | 1272.5 | 14.043 | 1.352 | 1113.61 | 1115.61 |
| 4 | 182.7 | 2046.5 | 56.248 | 4.548 | 1133.64 | 1134.76 |

The [frozen threshold](benchmarks/hash-threshold.json) retains the five input readings.

## File trace

| Backend | Requests in flight | Cold files/s | Warm files/s | Cold p95 (ms) | Warm p95 (ms) | Idle (MiB) | Peak (MiB) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| memory | 1 | 6351.8 | 6628.6 | 0.483 | 0.460 | 78.84 | 79.25 |
| memory | 4 | 6351.9 | 6359.2 | 0.504 | 0.492 | 80.12 | 80.28 |
| pread | 1 | 6321.1 | 6407.8 | 0.483 | 0.472 | 40.26 | 40.67 |
| pread | 4 | 6339.4 | 6608.9 | 0.508 | 0.472 | 41.52 | 41.73 |
| mmap | 1 | 6390.7 | 6645.5 | 0.480 | 0.460 | 40.33 | 40.74 |
| mmap | 4 | 6299.0 | 6568.8 | 0.503 | 0.483 | 41.61 | 41.80 |

## Precomputed digests

| Backend | Requests in flight | Cold lookups/s | Warm lookups/s | Cold p95 (µs) | Warm p95 (µs) | Idle (MiB) | Peak (MiB) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| memory | 1 | 2854132.6 | 3010461.9 | 0.458 | 0.417 | 89.96 | 90.07 |
| memory | 4 | 2795954.2 | 2998735.9 | 0.459 | 0.458 | 89.79 | 89.95 |
| pread | 1 | 1146521.0 | 1173918.4 | 1.042 | 1.041 | 51.38 | 53.39 |
| pread | 4 | 1140891.6 | 1192706.6 | 1.041 | 1.000 | 52.74 | 54.11 |
| mmap | 1 | 2765139.7 | 2979022.0 | 0.500 | 0.458 | 51.46 | 51.56 |
| mmap | 4 | 2810030.5 | 3092293.2 | 0.459 | 0.417 | 51.33 | 51.46 |

The Rust harness used up to four closed-loop worker threads on the single vCPU.
File p95 includes reading the corpus bytes, hashing, and looking up all applicable keys.
Digest p95 measures direct calls against the resident index. It excludes query decoding and IPC.

The [per-run measurements](benchmarks/hash-samples.csv) include startup, CPU time, disk reads, major faults, and guest memory headroom.
Each file pass presented 356,515,840 bytes, or 0.33203125 GiB, including repeated files.
Peak covers scanner startup and both passes. Idle is the reading ten seconds after the warm pass.
The two phase rows repeat cumulative CPU and I/O counters and final guest memory headroom. `pass_cpu_us` covers each pass.

## Acceptance

Each disk backend must save 57 MiB, retain 95% throughput, and stay within 110% of memory-backend p95.
Each ratio compares medians for the same trace, pass, and concurrency. Ratios use unrounded observations.

| Backend | Minimum idle saving (MiB) | Maximum idle saving (MiB) | Lowest throughput ratio | Highest p95 ratio |
| --- | ---: | ---: | ---: | ---: |
| pread | 37.05 | 38.60 | 38.99% | 249.64% |
| mmap | 38.45 | 38.51 | 96.88% | 109.83% |

Every file pass reported 0 hits and the ordered result checksum `ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7`.
Every digest pass reported 32,768 hits and the ordered result checksum `295d8e717cf56802d56f5e8fe2ee48f42c6822ea6778ea02ce88dbdbfcdc08cb`.

Across all five repetitions, Rust completed 245,760 file requests and 3,932,160 digest requests.
`mmap` met every throughput and p95 gate. `pread` also missed the digest throughput and p95 gates at both concurrency levels.

The encoded index occupies 38.51 MiB. The in-memory backend keeps a private copy alongside the file cache.
Both disk backends retain the cached index pages charged to the scanner.

On the four-request file trace, `pread` saved 38.60 MiB, equivalent to 3.40% of stock warm idle.
On the four-request file trace, `mmap` saved 38.51 MiB, equivalent to 3.40% of stock warm idle.
Stock includes different indexes, caches, and other matchers. Its end-to-end savings require a complete engine measurement.

## Build and update memory

Each row comes from a separate cold boot. Build time includes archive verification, extraction, compilation, and publication.
For updates, the old index stayed open while the builder wrote a new generation from the same snapshot.
Every scan used its previously opened index. Activation of the completed generation is a separate operation.
The driver verified the new bytes against the old index after measurement.

| Old generation | Files scanned | Elapsed (s) | Scanner peak (MiB) | Guest available after build (MiB) |
| --- | ---: | ---: | ---: | ---: |
| None | 0 | 1.03 | 256.95 | 1764.66 |
| memory | 0 | 1.03 | 338.78 | 1693.13 |
| pread | 0 | 1.09 | 299.49 | 1739.55 |
| mmap | 0 | 1.08 | 299.27 | 1746.04 |
| memory | 28672 | 5.31 | 336.29 | 1691.62 |
| pread | 28672 | 5.40 | 298.89 | 1738.92 |
| mmap | 28672 | 5.76 | 298.97 | 1732.64 |

Active updates replayed complete four-request file traces on the old generation until the builder exited.
Elapsed time for those rows includes draining the final trace. Every scan returned unmatched.
See the [build and update counters](benchmarks/hash-update-samples.csv) for CPU, I/O, and end-of-build cgroup memory.
Each build or update had one sample. Production reload orchestration and activation remain separate concerns.
