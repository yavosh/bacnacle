"""Measure one resident whole-file hash matcher in an isolated Linux cgroup."""

import argparse
import json
import select
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from stock_baseline import prepare


def read_reply(process, timeout):
    if not select.select([process.stdout], [], [], timeout)[0]:
        raise TimeoutError("matcher failed to reply before the deadline")
    reply = process.stdout.readline().strip()
    if not reply:
        raise RuntimeError(f"matcher closed its output, return code {process.poll()}")
    return reply


def startup(command, cgroup, stdout=subprocess.PIPE):
    def enter():
        (cgroup / "cgroup.procs").write_text("0")

    return subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=stdout, text=True, preexec_fn=enter
    )


def counters(cgroup):
    report = {}
    for name in ("memory.current", "memory.peak", "io.stat", "cpu.stat", "memory.events"):
        report[name] = (cgroup / name).read_text().strip()
    stats = dict(row.split() for row in (cgroup / "memory.stat").read_text().splitlines())
    report["pgmajfault"] = int(stats["pgmajfault"])
    with Path("/proc/meminfo").open() as source:
        report["available_kib"] = next(int(line.split()[1]) for line in source if line.startswith("MemAvailable:"))
    return report


def usage(cgroup):
    return int(dict(line.split() for line in (cgroup / "cpu.stat").read_text().splitlines())["usage_usec"])


def measure(args, source):
    command = [args.binary, args.backend, args.index, args.trace, source, str(args.concurrency)]
    start = time.monotonic()
    process = startup(command, args.cgroup)
    try:
        if read_reply(process, 90) != "READY":
            raise RuntimeError("unexpected startup reply")
        report = {"startup_s": time.monotonic() - start}
        for phase in ("cold", "warm"):
            cpu = usage(args.cgroup)
            process.stdin.write("run\n")
            process.stdin.flush()
            count, elapsed, p95, hits, checksum = read_reply(process, 120).split()
            report[phase] = {
                "requests": int(count),
                "elapsed_ns": int(elapsed),
                "p95_ns": int(p95),
                "per_second": int(count) * 1e9 / int(elapsed),
                "hits": int(hits),
                "checksum": checksum,
                "cpu_usec": usage(args.cgroup) - cpu,
            }
        time.sleep(10)
        return report | counters(args.cgroup)
    finally:
        process.stdin.close()
        try:
            code = process.wait(10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise
        if code:
            raise RuntimeError(f"matcher exited {code}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("index", type=Path)
    parser.add_argument("backend", choices=("memory", "pread", "mmap"))
    parser.add_argument("trace", choices=("file", "digest"))
    parser.add_argument("concurrency", type=int, choices=(1, 4))
    parser.add_argument("--queries", type=Path)
    parser.add_argument("--cgroup", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.NamedTemporaryFile() as corpus:
        if args.trace == "file":
            prepare(corpus)
            source = Path(corpus.name)
        else:
            if args.queries is None:
                parser.error("--queries is required for the digest trace")
            source = args.queries
            source.read_bytes()  # Charge benchmark inputs to the driver cgroup.
        print(json.dumps(measure(args, source)), flush=True)


if __name__ == "__main__":
    main()
