# Body matcher benchmark

Barnacle used 73 MiB after a warm pass. Stock clamd used 101 MiB.
With four clients, Barnacle completed 1,073 warm scans per second. Stock completed 887.
Barnacle's warm p95 was 13.77 ms. Stock's was 17.82 ms.
Database builds peaked at 78–79 MiB for Barnacle and 94 MiB for stock.
These figures cover the body database and a single raw-binary workload.

## Results

Each cell shows the median of three fresh boots. Throughput includes Unix socket transfers and the daemon response.
Each request had to return `Barnacle.Body.Benchmark.UNOFFICIAL FOUND`. All 7,680 requests passed.

| Clients | Pass | Stock files/s | Barnacle files/s | Stock MiB/s | Barnacle MiB/s | Stock p95 ms | Barnacle p95 ms |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | First | 624 | 1,038 | 51.80 | 86.16 | 5.67 | 2.89 |
| 1 | Warm | 815 | 998 | 67.69 | 82.87 | 4.15 | 2.93 |
| 4 | First | 820 | 1,064 | 68.09 | 88.34 | 18.56 | 14.07 |
| 4 | Warm | 887 | 1,073 | 73.61 | 89.06 | 17.82 | 13.77 |

Memory figures use the scanner cgroup and include file-backed pages.
The build peak is the kernel's `memory.peak` from daemon launch through its first successful `PING`.
Warm figures were read immediately after the last reply.

| Daemon | Clients | Startup ms | Ready MiB | Build peak MiB | Warm MiB | Warm anon MiB | Warm file MiB | Peak through warm MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Stock | 1 | 243 | 93.9 | 94.2 | 100.7 | 62.7 | 37.2 | 101.4 |
| Barnacle | 1 | 269 | 72.7 | 78.6 | 72.9 | 47.4 | 25.2 | 78.6 |
| Stock | 4 | 232 | 93.9 | 94.2 | 101.1 | 63.0 | 37.2 | 103.4 |
| Barnacle | 4 | 268 | 72.4 | 78.0 | 73.3 | 47.7 | 25.2 | 78.0 |

The raw samples include stage times and cgroup counters in bytes. [Raw samples](benchmarks/body-profile-samples.csv)

## Reproduce

Use the reference Debian arm64 guest with kernel `6.12.117+deb13-arm64` and `clamav-daemon=1.4.3+dfsg-1`.
Use one vCPU, 2 GiB RAM, no swap, and ext4 on virtio storage.
The scanner cgroup has a 1,400 MiB soft limit and a 1,536 MiB hard limit.
Run the Rust driver in a separate cgroup. [VM configuration](profile-vm.md)

Prepare the data disk before boot. Build the release executables for Linux arm64.
Extract the indicated members from verified main 63 and daily 28187 archives.
The two databases contain 101,744 active body rules before adding the local marker. [Input verification](whole-file-hashes.md#reproduce-the-pinned-generation)

```sh
cargo build --release --locked --bin barnacle --example body_bench
mkdir -p "$data/db"
tail -c +513 "$snapshot_dir/main.cvd" | tar -xzf - -C "$data/db" main.ndb
tail -c +513 "$snapshot_dir/daily.cvd" | tar -xzf - -C "$data/db" daily.ndb daily.ign daily.ign2
cp target/release/barnacle target/release/examples/body_bench "$data/"
"$data/body_bench" rule > "$data/db/marker.ndb"
```

Mount the prepared disk at `/data`. Create `/run/clamav` with owner `clamav`.
Use this configuration for both daemons.

```conf
Foreground yes
LocalSocket /run/clamav/clamd.ctl
LocalSocketMode 666
DatabaseDirectory /data/db
TemporaryDirectory /tmp
User clamav
DisableCache yes
SelfCheck 0
```

Run each observation in a freshly booted guest. Use fresh clones of the same root and data disks.
Use a single guest at a time and disable host caching for virtual disks.
Select either `/data/barnacle` or `/usr/sbin/clamd`. Use one or four clients.
Start the driver as root after creating the two cgroups and configuring their limits.

```sh
echo $$ > /sys/fs/cgroup/driver/cgroup.procs
/data/body_bench "$daemon" /data/clamd.conf /run/clamav/clamd.ctl "$clients"
```

The driver generates 128 distinct objects in memory before daemon startup.
Sizes cycle through 4, 16, 64, and 256 KiB. Each object ends with the same harmless marker.
The first pass sends every object once, for 10.625 MiB. The warm pass repeats the corpus four times, for 42.5 MiB.
Each request uses a fresh connection and streams 64 KiB chunks. Latency uses nearest-rank p95.
The host rotated daemon and concurrency order across three repetitions.
The measured Linux executable had SHA-256 `8faa36a90120b558d03fde5d28867bfcf3e4cc46ae37c514be9251d5d68b5978`.
