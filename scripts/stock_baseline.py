"""Replay one cold and warm file trace against a dedicated stock clamd socket."""

import argparse
import hashlib
import json
import math
import os
import socket
import sys
import tempfile
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path


def request(path, command):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(str(path))
        connection.sendall(command)
        reply = bytearray()
        while len(reply) < 4096:
            chunk = connection.recv(4096 - len(reply))
            if not chunk:
                raise ValueError(f"unterminated clamd reply: {bytes(reply)!r}")
            reply.extend(chunk)
            if reply.endswith(b"\0"):
                return reply[:-1].decode("ascii")
        raise ValueError("clamd reply exceeds 4096 bytes")


def stream_request(path, data):
    frame = len(data).to_bytes(4, "big") + data + bytes(4)
    return request(path, b"zINSTREAM\0" + frame)


def prepare(corpus):
    trace = []
    sizes = (4096, 16384, 65536, 262144)
    for i in range(4096):
        if i and i % 4 == 0:
            trace.append(trace[0])
            continue
        length = sizes[i % 4]
        seed = b"barnacle-v1/" + str(i).encode("ascii")
        trace.append((corpus.tell(), length))
        corpus.write(hashlib.shake_256(seed).digest(length))
    corpus.flush()
    return trace


def scan_file(path, fd, span, submitted):
    offset, length = span
    try:
        data = os.pread(fd, length, offset)
        if len(data) != length:
            raise OSError("short read from generated corpus")
        reply = stream_request(path, data)
        error = None if reply == "stream: OK" else reply
    except (OSError, ValueError) as exc:
        error = str(exc)
    return time.perf_counter_ns() - submitted, error


def replay(path, fd, trace, concurrency):
    latencies = [None] * len(trace)
    errors = []
    next_index = 0
    pending = {}
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        start = time.perf_counter_ns()
        while pending or (next_index < len(trace) and not errors):
            while len(pending) < concurrency and next_index < len(trace) and not errors:
                future = pool.submit(
                    scan_file, path, fd, trace[next_index], time.perf_counter_ns()
                )
                pending[future] = next_index
                next_index += 1
            done, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                index = pending.pop(future)
                latency, error = future.result()
                latencies[index] = latency
                if error is not None:
                    errors.append({"request": index, "error": error})
        elapsed = time.perf_counter_ns() - start
    latencies = latencies[:next_index]
    return {
        "requests": next_index,
        "elapsed_ns": elapsed,
        "files_per_second": None if errors else next_index * 1e9 / elapsed,
        "p95_ns": None if errors else sorted(latencies)[math.ceil(0.95 * next_index) - 1],
        "request_latency_ns": latencies,
        "errors": sorted(errors, key=lambda row: row["request"]),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--concurrency", type=int, choices=(1, 4), required=True)
    parser.add_argument("--memory-current", type=Path, help="scanner cgroup v2 memory.current")
    args = parser.parse_args()
    report = {
        "trace": "barnacle-v1",
        "concurrency": args.concurrency,
        "version_reply": request(args.socket, b"zVERSION\0"),
    }
    with tempfile.TemporaryFile() as corpus:
        trace = prepare(corpus)
        for phase in ("cold", "warm"):
            report[phase] = replay(args.socket, corpus.fileno(), trace, args.concurrency)
            if report[phase]["errors"]:
                print(json.dumps(report))
                return 1
        if args.memory_current is not None:
            time.sleep(10)
            report["warm_idle_bytes"] = int(args.memory_current.read_text())
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        sys.exit(f"stock baseline failed: {error}")
