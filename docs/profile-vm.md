# Reproduce the stock memory profile

Use a fresh Debian 13 arm64 guest for each trial. Enable cgroup v2, one vCPU, 2 GiB RAM, and zero swap.
Use ext4 with virtio block storage. Install Debian `clamav-daemon=1.4.3+dfsg-1` and the matching library.
The measurements used kernel `6.12.117+deb13-arm64` and an isolated guest on Apple Virtualization.
The host opened each cloned disk without a host file cache. The guest had no network.

## Prepare immutable inputs before boot

Use the [pinned official CVD files](whole-file-hashes.md). Verify their signatures and recorded SHA-256 digests before creating the guest image.
Install them in `/var/lib/clamav`. Retain that directory for every official workload run.
Build and install the release Rust benchmark executable and generate the corpus outside the cold guest.

```sh
cargo build --release --locked --example stock_profile --example hash_bench
target/release/examples/hash_bench prepare-files "$data/corpus"
sha256sum "$data/corpus"
```

The concatenated corpus is 352,325,632 bytes. Its SHA-256 is `ceb040d353d99e018381733c3331f2cffe2f4f8489e400865823d562aaad199d`.
The driver reuses the first 4,096-byte object on every fourth request. Each pass submits 4,096 uploads.

Prepare diagnostic files on a separate disk. Use a new directory for this extraction.

```sh
mkdir "$data/db"
for archive in main daily; do
    tail -c +513 "$snapshot_dir/$archive.cvd" | tar -xzf - -C "$data/db" --exclude=COPYING --exclude='*.info'
done
cp "$snapshot_dir/bytecode.cvd" "$data/db/bytecode.cvd"
chmod 444 "$data/db/"*
```

The selector hard-links members into a new directory on the same filesystem. `all` retains every classified member.
`base` keeps signed bytecode, dynamic settings, file types, certificate rules, ignores, and allowlists.
Each `omit-*` profile removes one additional family from `all`. PUA detection stays disabled throughout.

| Diagnostic group | Database extensions |
| --- | --- |
| `section` | `.mdb`, `.msb`, `.mdu`, `.msu` |
| `logical` | `.ldb`, `.ldu` |
| `body` | `.ndb`, `.ndu` |
| `whole` | `.hdb`, `.hsb`, `.hdu`, `.hsu` |
| `other` | `.cdb`, `.idb`, `.pdb`, `.wdb` |

## Run one fresh guest per observation

Use the [stock daemon configuration](hash-benchmark-run.md). The measurement uses serial reloads and the stock clean-file cache.
Disable the normal service in the image. Initialize the private socket directory and scanner cgroup as root on boot.

```sh
install -d -o clamav -g clamav /run/clamav
cg=/sys/fs/cgroup
mkdir -p "$cg/driver" "$cg/scanner"
echo '+memory +cpu +io' > "$cg/cgroup.subtree_control"
echo 1468006400 > "$cg/scanner/memory.high"
echo 1610612736 > "$cg/scanner/memory.max"
echo 0 > "$cg/scanner/memory.swap.max"
echo $$ > "$cg/driver/cgroup.procs"
```

For official trials, use the stock configuration without editing its database directory.
Run concurrency one and four in separate guests. Save each JSON result before shutdown.

```sh
stock_profile full "$config" /run/clamav/clamd.ctl "$cg/scanner" "$data/corpus" "$concurrency"
```

For diagnostic trials, select the profile inside the guest. Leave the corpus untouched.

```sh
scripts/bench/select_profile_db.sh "$data/db" "$data/selected" "$profile"
sed "s|^DatabaseDirectory .*|DatabaseDirectory $data/selected|" "$config" > /tmp/selected-clamd.conf
stock_profile ready /tmp/selected-clamd.conf /run/clamav/clamd.ctl "$cg/scanner" "$data/corpus" 1
```

`ready` completes after stock responds to `PING` and its version is checked. `full` records the same startup boundary first.
An official run reads the corpus in the driver cgroup before timed scans. The daemon loads its database in the scanner cgroup.

The `stages` object records instantaneous memory charges, cumulative disk reads and major faults, and lifetime cgroup memory peak.
`*_active_peak` selects the largest observed `memory.current` from samples during that pass.
Its anonymous and file-backed readings come from the same sample. Summed components can differ from `memory.current` due to kernel charges and sampling time.
The kernel peak can include a short-lived maximum between samples. Counters accumulate within one boot.
Use the corresponding stage differences when calculating pass-specific activity.

The warm idle observation follows a ten-second wait. During the third pass, the driver issues `RELOAD` under traffic.
It checks the daemon's reload and activation messages and sends another harmless scan.
The `passes` object retains request count, throughput, and nearest-rank p95 for each pass.

For the published series, each guest received a fresh copy-on-write clone of the prepared root and data disks.
Run three repetitions of each scenario. Alternate the starting concurrency across repetitions.
Rotate the diagnostic family order. Run one guest at a time. A fresh kernel resets guest page-cache charges before each measurement.

Keep extracted-family runs separate from deployment measurements. Stock treats unpacked rules as unofficial and may load them in a different order.
Plaintext database pages also have a different size from compressed CVD pages. Report anonymous memory and total memory separately.
The difference between `all` and one `omit-*` profile is the marginal cost with all other groups still loaded.
The sum of marginal costs can differ from `all` minus `base` because structures and allocator pages are shared.

The [stage samples](benchmarks/stock-profile-stages.csv) flatten each stock report's `stages` object.
The [pass samples](benchmarks/stock-profile-passes.csv) flatten its `passes` object.
Join them by profile, repetition, and concurrency. Startup and reload times repeat across stage rows from the same boot.
`requests_before_reload` and `requests_at_activation` count completed requests in the third pass.
The driver samples them immediately before requesting reload and when it observes activation.

The first four-request full trial ran before the driver recorded `requests_at_activation`.
A fresh replacement trial at the end supplied that repetition. The tables include only trials with the final instrumentation.
