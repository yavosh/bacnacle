# Barnacle

Barnacle is an experimental Rust scanner for ClamAV signatures. Its first matcher detects whole-file MD5, SHA-1, and SHA-256 signatures.
A match reports the stock signature name. A miss leaves the file pending a complete scan by clamd.

Build and test the executable with `cargo build --release --locked` and `cargo test --locked`.
Run a private daemon with `barnacle serve --foreground --config-file /path/to/clamd.conf`. [Daemon guide](docs/daemon.md)
See the [offline matcher guide](docs/whole-file-hashes.md), [benchmark protocol](docs/hash-baseline.md), and [measured results](docs/hash-benchmark-results.md).

Use the [Rust compatibility runner](docs/compatibility/replay.md) to compare a candidate daemon with the pinned Debian clamd.
The [compatibility matrix](docs/compatibility-matrix.md) links measured behavior and remaining coverage gaps.

The [stock memory profile](docs/stock-memory-profile.md) measures clamd during scans and reloads and compares signature-family storage costs.
