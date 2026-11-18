# Profile clamd memory on the reference guest

The reference is Debian arm64 `clamav-daemon` 1.4.3+dfsg-1 on one vCPU and 2 GiB RAM without swap. The scanner cgroup has a 1,400 MiB soft limit and a 1,536 MiB hard limit. Clean-file caching is enabled. The verified database snapshots are main 63, daily 28187, and bytecode 339. [Archive digests](whole-file-hashes.md#reproduce-the-pinned-generation) · [Reference daemon configuration](hash-benchmark-run.md#prepare-the-disk-image)

## Measurement method

Start each trial in a fresh guest. Launch clamd inside the scanner cgroup so that loading the database charges that cgroup. The Rust driver lives in a separate cgroup. It checks the file corpus before timing. The 4,096 requests replay the same objects and order as the [whole-file experiment](hash-baseline.md). The packed corpus contains 352,325,632 bytes with SHA-256 `ceb040d353d99e018381733c3331f2cffe2f4f8489e400865823d562aaad199d`.

The full-feed trials use the signed archives and the stock daemon's full scan pipeline. Record readiness after the first successful `PING`. Replay a cold pass and a warm pass. Read warm idle memory ten seconds after the warm pass. Request a serial database reload during a third pass. Check daemon activation and scan a harmless file after reload.

`memory.current` measures total cgroup memory. `anon` and `file` come from `memory.stat`. Other memory charges account for the difference. `memory.peak`, storage reads, and major page faults are cumulative since cgroup creation. The sampled active high point is the largest observed `memory.current` during each pass. It can miss brief peaks between samples. Cold measurements include a loaded engine and a fresh scan-result cache.

## How to interpret a family comparison

Compare the diagnostic configuration with every family present against an otherwise identical configuration omitting one family. Each difference measures the marginal cost of loading that family alongside the others. Subtract anonymous and file-backed bytes separately. The results include shared compiled tables, allocator overhead, and changes in allocation behavior. Adding the marginal costs does not reconstruct the total.

The diagnostic runs use extracted main and daily members so individual families can be omitted. They retain the signed bytecode archive, configuration, file types, ignore entries, and allowlists. Extracted names can acquire an unofficial suffix, and input caching and load order can change. Use the full signed-feed trials for actual scanner memory and speed.

## Storage candidate

The storage experiment uses PE section hashes. A section lookup has a well-defined input, the bytes and length of a PE section, and a named result that stock clamd can verify. Logical signatures also require compiled pattern and expression evaluators. Fetching their source text would measure a different operation.

Both candidate backends use the same full section table. The payload trace times hashing and lookups on harmless section-sized buffers. The digest trace times lookups for known keys and modified digests. Full-file parsing and the rest of clamd's pipeline are outside those timings. Compare the two backends within each trace, pass, and concurrency level.

Before collecting candidate timings, we chose to report the observed memory saving, throughput ratio, and p95 ratio for every workload. A claim of unchanged speed requires throughput at least as high and p95 at most as high across all measured conditions. Mixed results stay visible. Three repetitions describe this guest and generation. The complete daemon has a separate release test. [Candidate inputs and reproduction](section-storage-run.md)
