# Reproduce the PE section storage experiment

Use the full verified databases, harmless corpus, Linux guest, and cgroups from the [stock profiling protocol](profile-vm.md).
Keep original databases and generated tables outside Git. Use a new directory for each generation.

## Prepare the section index and traces

Set `data` to the preparation directory from the stock profile. Its `db` directory contains the extracted database members.
The preparation tool checks eight member digests. It copies the ignore lists and verifies the disabled PUA files.
For each active section rule, it exchanges the size and digest fields. It preserves the rest of the line.
The two pinned ignore files contain only unconditional entries. A conditional ignore requires the original line and stops conversion.

```sh
cargo build --release --locked --bin barnacle --example hash_bench --example section_prepare --example section_profile
target/release/examples/section_prepare "$data/db" "$data/section-inputs"
rules="$data/section-inputs"
set -- "$rules/daily.ign" "$rules/daily.ign2" "$rules/daily.mdb.hsb" "$rules/daily.msb.hsb" \
       "$rules/main.mdb.hsb" "$rules/main.msb.hsb"
target/release/barnacle build "$data/section.bhi" --official "$@"
target/release/examples/hash_bench prepare "$data/section-queries" "$@"
sha256sum "$data/section.bhi" "$data/section-queries" "$data/corpus"
```

The active members contain 2,670,550 rows. Six match unconditional ignore entries, and two eligible rows repeat a key.
The index retains 2,670,542 distinct keys. The disabled PUA members contain 316 rows.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Section index | 187,974,640 | `262930ac167f6f65007ab3b8eaa7f16eadaea8f78a184176e6df40343a2e9496` |
| Digest queries | 2,424,832 | `2f85f8cd34e06d0f1c7fbbdfc2b83c5f1eda516d395f3d59df3e288732dc09cf` |
| Payload corpus | 352,325,632 | `ceb040d353d99e018381733c3331f2cffe2f4f8489e400865823d562aaad199d` |

The table uses the same records, name blob, and sparse search directory for both backends.
The memory backend copies the encoded records and names into a private buffer. The mapped backend reads immutable file pages.
Both validate the entire generation at startup. Active file-backed pages count toward scanner memory.
This experiment restricts the hash table to PE sections. Whole-file rules belong in a separate table.

## Run each backend in a fresh guest

Install the Linux release executables and the three immutable artifacts before boot. Set `data` to their directory in the guest.
Set `cg` to `/sys/fs/cgroup` and enter the driver cgroup using the stock profiling protocol.
Choose `memory` or `mmap`, `file` or `digest`, and one or four concurrent requests.

```sh
"$data/section_profile" "$backend" "$data/section.bhi" "$data/section-queries" "$data/corpus" \
  "$trace" "$concurrency" "$cg/scanner" "$data/hash_bench"
```

Run three repetitions of each combination. Alternate the backend order between repetitions.
The supervisor reads the input trace in the driver cgroup. The scanner cgroup pays for the index and worker allocations.
A 120-second deadline covers scanner startup, both passes, the ten-second idle sample, and shutdown.
The first pass starts after index validation. The second pass uses the same worker process and page cache.

`file` processes 4,096 harmless section payloads. Each request reads and hashes the payload, then checks the section table.
`digest` issues 65,536 section-key lookups. Half use a pinned positive key, sampled across the eligible input records before duplicate reduction.
The other half flip the first digest bit. Each pass records the ordered result checksum, throughput, and nearest-rank p95 latency.

## Check section matching against clamd

The Rust test generates an inert PE32 image containing one 512-byte read-only data section.
Local section signatures deliberately share a key. Both storage backends return the same winner as stock clamd.
The stock daemon detects the signature in the PE image and reports the separate raw data file as clean.
Run the live test as an ordinary user on Debian with the pinned daemon installed.

```sh
cargo test --locked --test section_profile
cargo test --locked --test section_profile live_clamd -- --ignored
```
