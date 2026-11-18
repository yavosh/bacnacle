# Reproduce the whole-file hash measurements

Use a disposable Debian 13 arm64 guest with one vCPU, 2 GiB RAM, no swap, and a cgroup v2 hierarchy.
Keep the host, compiler flags, disk image, database generation, and package versions fixed across trials.
Use the database snapshot and rule inventory in [Whole-file hashes](whole-file-hashes.md).

## Prepare the disk image

Build the release executable and benchmark driver. Generate both artifacts outside Git.

```sh
cargo build --release --locked --bin barnacle --example hash_bench
python3 scripts/build_pinned_hash_index.py target/release/barnacle "$snapshot_dir" "$data_dir/full.bhi"
python3 - "$snapshot_dir" "$data_dir/queries" <<'PY'
from pathlib import Path
from subprocess import run
from tempfile import TemporaryDirectory
import sys
sys.path.insert(0, "scripts")
from build_pinned_hash_index import extract_inputs

with TemporaryDirectory() as work:
    inputs = extract_inputs(Path(sys.argv[1]), Path(work))
    run(["target/release/examples/hash_bench", "prepare", sys.argv[2], *inputs], check=True)
PY
```

Install the binaries, input files, Python 3, and scripts in the guest image.
Install Debian package `clamav-daemon=1.4.3+dfsg-1`. Disable the distribution daemon in this image.
The stock trial starts its own clamd in the scanner cgroup.
Set `DatabaseDirectory` to the verified CVD directory. Use this private daemon configuration.

```text
Foreground yes
User clamav
DatabaseDirectory /var/lib/clamav
LocalSocket /run/clamav/clamd.ctl
LocalSocketGroup clamav
LocalSocketMode 666
StreamMaxLength 250M
MaxFileSize 250M
MaxScanSize 500M
ConcurrentDatabaseReload no
```

The remaining options use Debian package defaults, including the clean-file cache.
Create the socket directory with the clamav user and group as owners.

## Run one trial per boot

Start an independent guest from the prepared disk image for every trial.
Keep the measured index immutable while any process holds it open.
Use a separate scanner cgroup and driver cgroup. Run these commands as root in the disposable guest.

```sh
cg=/sys/fs/cgroup
mkdir -p "$cg/scanner" "$cg/driver"
echo '+cpu +io +memory' > "$cg/cgroup.subtree_control"
echo 1468006400 > "$cg/scanner/memory.high"
echo 1610612736 > "$cg/scanner/memory.max"
echo 0 > "$cg/scanner/memory.swap.max"
echo $$ > "$cg/driver/cgroup.procs"
```

Start ten stock trials. Run five at concurrency four, then five at concurrency one.
Save each JSON report outside the guest before shutting it down.
Use filenames `stock-C-N.json`, where C is the concurrency and N is the repetition.

```sh
python3 scripts/bench/stock_trial.py /usr/sbin/clamd "$config" "$socket" "$concurrency" --cgroup "$cg/scanner"
```

Freeze the threshold after the five four-request stock trials and before measuring any Rust matcher.
Record the ordered idle readings, their median, the UTC time, and the threshold.
The [frozen record](benchmarks/hash-threshold.json) shows the format.

For each of five repetitions, run the file trace and the digest trace at both concurrency levels.
Rotate the starting backend each repetition. Save reports as `BACKEND-TRACE-C-N.json`.

```sh
python3 scripts/bench/hash_trial.py "$bench" "$index" "$backend" "$trace" "$concurrency" \
  --queries "$queries" --cgroup "$cg/scanner"
```

Run the verified build in a fresh guest. Repeat once for each resident backend.

```sh
python3 scripts/bench/hash_build.py "$binary" "$snapshot_dir" "$index" --cgroup "$cg/scanner"
python3 scripts/bench/hash_build.py "$binary" "$snapshot_dir" "$index" --cgroup "$cg/scanner" \
  --resident "$backend" --bench "$bench" --queries "$queries"
```

For three further boots, add `--traffic` to the resident command. This drives four concurrent whole-file scans during compilation.
The resident process holds the previous generation. The builder validates the archives and creates a separate output.
The driver checks that the output matches the prepared index after measuring peak memory.

Collect all 70 stock and matcher trial reports. Generate the table and compare the recorded gates.

```sh
python3 scripts/bench/summarize.py "$results_dir" "$frozen_json" "$results_dir/samples.csv"
```

The comparison requires 4,096 file requests or 65,536 digest requests per pass.
The outcome checksum covers a one-byte match flag for each request in trace order.
Each match also contributes its eight-byte little-endian name length and the UTF-8 name.
