"""Write per-run CSV measurements and compare medians against the frozen gates."""

import argparse
import csv
import json
import math
import statistics
from pathlib import Path

BACKENDS = ("memory", "pread", "mmap")
TRACES = ("file", "digest")
PHASES = ("cold", "warm")
MIB = 2**20


def usage(text, field):
    return int(dict(line.split() for line in text.splitlines())[field])


def io_total(text, field):
    return sum(int(dict(item.split("=") for item in row.split()[1:])[field]) for row in text.splitlines())


def run_counters(run):
    if usage(run["memory.events"], "oom_kill") or usage(run["memory.events"], "oom"):
        raise ValueError("OOM during trial")
    return {
        "idle_bytes": int(run["memory.current"]),
        "peak_bytes": int(run["memory.peak"]),
        "user_cpu_us": usage(run["cpu.stat"], "user_usec"),
        "system_cpu_us": usage(run["cpu.stat"], "system_usec"),
        "read_bytes": io_total(run["io.stat"], "rbytes"),
        "write_bytes": io_total(run["io.stat"], "wbytes"),
        "major_faults": run["pgmajfault"],
        "available_kib": run["available_kib"],
    }


def read_trace(directory, backend, trace, concurrency, rep):
    name = f"stock-{concurrency}-{rep}" if backend == "stock" else f"{backend}-{trace}-{concurrency}-{rep}"
    run = json.loads((directory / (name + ".json")).read_text())
    expected = 4096 if trace == "file" else 65536
    for phase in PHASES:
        data = run[phase]
        hits = data.get("hits", 0)
        if data.get("errors") or data["requests"] != expected:
            raise ValueError(f"{name}: incomplete trace or scan error")
        if (trace == "file" and hits != 0) or (trace == "digest" and hits < expected // 2):
            raise ValueError(f"{name}: unexpected hit count")
        yield {
            "backend": backend,
            "trace": trace,
            "concurrency": concurrency,
            "rep": rep,
            "phase": phase,
            "requests": expected,
            "elapsed_ns": data["elapsed_ns"],
            "per_second": expected * 1e9 / data["elapsed_ns"],
            "p95_ns": data["p95_ns"],
            "hits": hits,
            "result_sha256": data.get("checksum", ""),
            "pass_cpu_us": data["cpu_usec"],
            "startup_s": run["startup_s"],
            **run_counters(run),
        }


def compare(rows, stock, threshold):
    def median(backend, trace, concurrency, phase, key):
        return statistics.median(
            row[key] for row in rows
            if (row["backend"], row["trace"], row["concurrency"], row["phase"]) == (backend, trace, concurrency, phase)
        )
    for trace in TRACES:
        checksums = {row["result_sha256"] for row in rows if row["backend"] != "stock" and row["trace"] == trace}
        if len(checksums) != 1 or not next(iter(checksums)):
            raise ValueError(f"{trace}: matcher verdicts differ")
    actual = [r["idle_bytes"] for r in rows if (r["backend"], r["concurrency"], r["phase"]) == ("stock", 4, "warm")]
    if actual != stock or max(50, math.ceil(statistics.median(actual) * .05 / MIB)) != threshold:
        raise ValueError("frozen threshold differs from stock input")
    for backend in BACKENDS[1:]:
        print(f"\n{backend} versus memory")
        passed = True
        for trace in TRACES:
            for concurrency in (1, 4):
                for phase in PHASES:
                    def pair(key):
                        return tuple(median(b, trace, concurrency, phase, key) for b in ("memory", backend))
                    m, d = pair("idle_bytes")
                    saved = (m - d) / MIB
                    m, d = pair("per_second")
                    throughput = d / m
                    m, d = pair("p95_ns")
                    latency = d / m
                    cell = saved >= threshold and throughput >= .95 and latency <= 1.10
                    passed &= cell
                    print(f"{trace:6} c{concurrency} {phase} {saved:7.2f} MiB {throughput:8.3%} rate {latency:8.3%} p95 {'PASS' if cell else 'FAIL'}")
        print("PASS" if passed else "FAIL")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    parser.add_argument("frozen", type=Path)
    parser.add_argument("csv", type=Path)
    args = parser.parse_args()
    frozen = json.loads(args.frozen.read_text())
    rows = [
        row
        for backend in ("stock", *BACKENDS)
        for trace in (("file",) if backend == "stock" else TRACES)
        for concurrency in (1, 4)
        for rep in range(1, 6)
        for row in read_trace(args.results, backend, trace, concurrency, rep)
    ]
    compare(rows, frozen["stock_c4_idle_bytes"], frozen["threshold_mib"])
    with args.csv.open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=rows[0], lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    main()
