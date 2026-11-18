# Barnacle

Barnacle is an experimental Rust scanner for ClamAV signatures. Its first matcher detects whole-file MD5, SHA-1, and SHA-256 signatures.
A match reports the stock signature name. A miss leaves the file pending a complete scan by clamd.

Build and test the matcher with `cargo build --release --locked` and `cargo test --locked`.
See the [offline matcher guide](docs/whole-file-hashes.md), [benchmark protocol](docs/hash-baseline.md), and [measured results](docs/hash-benchmark-results.md).
