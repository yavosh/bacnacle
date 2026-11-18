"""Measure a verified index build with an optional resident or scanning generation."""

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from hash_trial import counters, prepare, read_reply, startup


def checksum(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.digest()


def build(command, cgroup, scanner):
    def enter():
        (cgroup / "cgroup.procs").write_text("0")

    start = time.monotonic()
    count = 0
    empty_results = hashlib.sha256(bytes(4096)).hexdigest()
    with subprocess.Popen(command, preexec_fn=enter, stdout=sys.stderr, start_new_session=True) as builder:
        try:
            while scanner and builder.poll() is None:
                if time.monotonic() - start > 140:
                    raise TimeoutError("index build exceeded deadline")
                scanner.stdin.write("run\n")
                scanner.stdin.flush()
                requests, _, _, hits, result = read_reply(scanner, 120).split()
                if (requests, hits, result) != ("4096", "0", empty_results):
                    raise ValueError("old generation produced an unexpected scan result")
                count += int(requests)
            remaining = max(0.1, 140 - (time.monotonic() - start))
            if builder.wait(timeout=remaining):
                raise RuntimeError("index build failed")
            if scanner and not count:
                raise RuntimeError("build completed without any concurrent scans")
            return {"elapsed_s": time.monotonic() - start, "files_scanned": count} | counters(cgroup)
        finally:
            if builder.poll() is None:
                os.killpg(builder.pid, signal.SIGKILL)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("cvd_directory", type=Path)
    parser.add_argument("index", type=Path)
    parser.add_argument("--cgroup", required=True, type=Path)
    parser.add_argument("--resident", choices=("memory", "pread", "mmap"))
    parser.add_argument("--bench", type=Path)
    parser.add_argument("--queries", type=Path)
    parser.add_argument("--traffic", action="store_true", help="scan four files concurrently during the rebuild")
    args = parser.parse_args()
    if args.traffic and not args.resident:
        parser.error("--traffic requires --resident")
    if args.resident and not (args.bench and (args.traffic or args.queries)):
        parser.error("--resident requires --bench and either --queries or --traffic")
    builder = Path(__file__).resolve().parents[1] / "build_pinned_hash_index.py"
    resident = None
    with tempfile.TemporaryDirectory() as dest, tempfile.NamedTemporaryFile() as corpus:
        result = Path(dest) / "new.bhi"
        try:
            if args.resident:
                if args.traffic:
                    prepare(corpus)
                    trace = ["file", corpus.name, "4"]
                else:
                    args.queries.read_bytes()
                    trace = ["digest", args.queries, "1"]
                resident = startup([args.bench, args.resident, args.index, *trace], args.cgroup)
                if read_reply(resident, 90) != "READY":
                    raise RuntimeError("unexpected resident startup reply")
            report = build(
                [sys.executable, builder, args.binary, args.cvd_directory, result],
                args.cgroup,
                resident if args.traffic else None,
            )
            if checksum(result) != checksum(args.index):
                raise RuntimeError("rebuilt generation differs")
            print(json.dumps(report))
        finally:
            if resident:
                resident.stdin.close()
                resident.wait(10)


if __name__ == "__main__":
    main()
