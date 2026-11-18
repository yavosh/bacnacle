# Establish the whole-file hash baseline

## Capture reference matches

Run the following command as an ordinary user on an isolated Debian 13 machine with the reference `clamav-daemon` package.
Save the JSON outside the checkout.

```sh
python3 scripts/hash_reference.py > /tmp/barnacle-hash-reference.json
```

The runner creates two local signature files and starts a private clamd.
It sends nine harmless binary inputs over `INSTREAM`.
The cases cover exact and wildcard sizes, incorrect sizes, absent hashes, duplicate keys and names, and competing algorithms.
The report preserves each reply, including the winning signature's suffix.
The command exits unsuccessfully on a daemon error or unexpected result.

The [Debian 13 reference report](hash-reference-debian13.json) records the observed winner, package revision, configuration, database digests, and fixture digests.
Compare each Rust result against the recorded result and signature, including the exact winner for competing names.
Here, `unmatched` describes the hash lookup only.
These fixtures test hash semantics. The performance runs below use a full verified generation.

## Fix the inputs before measuring the indexes

Use an isolated Debian 13 VM with one vCPU, 2 GB RAM, and the deployed scanner limits.
Record its architecture, kernel, filesystem, storage type, swap setting, and cgroup limits.
Pin the package revisions and effective scan options.
Keep the verified FreshClam snapshot frozen during the runs. Record each database file's name, generation, and SHA-256 digest.
Record the count of eligible whole-file signatures by algorithm and size constraint.
Both Rust indexes must load every eligible signature in that snapshot.

Use the same ordered stream of 4,096 harmless files for each implementation.
Submit requests in increasing order from zero through 4,095.
For request number `i`, use file ID zero when `i % 4 == 0`. Otherwise use file ID `i`.
Choose its byte length with `(4096, 16384, 65536, 262144)[file_id % 4]`.
Generate each file with Python's `hashlib.shake_256(b"barnacle-v1/" + str(file_id).encode("ascii")).digest(length)`.
Generate the files before timing. Keep the driver and corpus cache outside the scanner's cgroup.
Record throughput in files per second. Measure each file from request submission through the result, including hashing.
Run with one outstanding request, then four. Use one driver and the same submission order for all variants.

Also run the two disk-backed matchers and the in-memory matcher on precomputed digest lookups.
Sort the full eligible rule set by algorithm, lowercase hexadecimal digest, numeric size (wildcard first), and name.
For lookup `i` from zero through 65,535, hash its ASCII decimal representation with SHA-256.
Interpret the first eight bytes as a big-endian integer. Select the rule at that index modulo the rule count.
Query its algorithm, digest, and size. Use 65,536 bytes for wildcard rules.
For odd `i`, flip the first digest bit to exercise misses. Compare the results across all three matchers.
Report lookups per second and per-lookup p95. Run this trace independently at both concurrency levels.

Replay the file trace against stock clamd with the full snapshot and deployed options.
Start the dedicated daemon using the cold conditions below. Run the driver in a separate cgroup.
For example, run one repetition at concurrency four:

```sh
python3 scripts/stock_baseline.py --socket /run/clamav/clamd.ctl --concurrency 4 \
  --memory-current /sys/fs/cgroup/system.slice/clamav-daemon.service/memory.current \
  > /tmp/barnacle-stock-c4-run1.json
```

Use the scanner's actual socket and cgroup paths. The driver generates its corpus in a temporary file before timing.
It records both passes and exits unsuccessfully on any detection, timeout, or scan error.
Omitting `--memory-current` produces a timing-only report.
Record clamd's cache setting. Keep the full-engine measurements separate from the Rust matcher comparison.
Record startup time, cgroup memory peak, and the warm idle reading described below.
Record CPU time, disk reads, major faults, and host memory headroom alongside the timings.
Measure build and update peaks in separate runs.

## Driver scope for the measured runs

The Rust runs time the same in-process driver for all three backends.
An external process prepares the file corpus and preloads the digest trace outside the scanner cgroup.
The Rust process owns its worker buffers, decoded queries, and result allocations. Its cgroup accounts for those bytes.
The stock run uses the external `INSTREAM` driver. Its timings include client and socket costs as well as full scanning.
Compare Rust timings only across Rust backends. Use stock warm idle memory to set the memory threshold.

## Decide whether to continue

Complete five runs per implementation and concurrency. Rotate implementation order between repetitions.
Start every run from the same cold VM snapshot with the input data on disk and empty storage caches.
Have the scanner load its database inside its own cgroup so that cgroup accounts for its database pages.
Record the first trace as cold. Immediately repeat the trace in the same process and record it as warm.
For each trace, record throughput and nearest-rank p95 latency across all requests.
Ten seconds after the warm trace ends, record `memory.current` in bytes, including file-backed pages.
Use the median of the five readings for each metric, implementation, concurrency, and cache condition.

Require at least 50 MiB of warm memory savings.
Before running either Rust index, freeze the threshold at the larger of 50 MiB and `ceil(0.05 × stock warm idle bytes / 1048576)`.
Use the median from the five four-request stock runs. Record the resulting integer with the run inputs.
This assigns hash storage at least five percentage points of the proposed 30% whole-engine saving.

A disk-backed implementation passes when all of the following hold against the in-memory Rust implementation:

- Warm idle memory falls by at least the frozen MiB threshold at each concurrency.
- Cold and warm throughput each reach at least 95% of the corresponding in-memory throughput on both traces.
- Cold and warm p95 latency each stay within 110% of the corresponding in-memory p95.
- Every reference case agrees, all three matchers return identical lookup results, and every benchmark request completes without error.

Report both disk-backed implementations separately. Continue if at least one passes all criteria.
Without the full stock baseline or a complete comparison, leave the decision pending.
