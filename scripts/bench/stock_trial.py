"""Start one isolated stock daemon and measure its two file passes and idle memory."""

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

from hash_trial import counters, prepare, startup, usage
from hash_reference import request
from stock_baseline import replay


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("clamd", type=Path)
    parser.add_argument("config", type=Path)
    parser.add_argument("socket", type=Path)
    parser.add_argument("concurrency", choices=(1, 4), type=int)
    parser.add_argument("--cgroup", type=Path, required=True)
    args = parser.parse_args()
    started = time.monotonic()
    process = startup([args.clamd, "-c", args.config], args.cgroup, stdout=sys.stderr)
    try:
        while True:
            if process.poll() is not None or time.monotonic() - started > 150:
                raise RuntimeError("clamd exited or missed its startup deadline")
            try:
                if request(args.socket, b"zPING\0") == "PONG":
                    break
            except OSError:
                pass
            time.sleep(0.1)
        report = {"startup_s": time.monotonic() - started, "version": request(args.socket, b"zVERSION\0")}
        with tempfile.TemporaryFile() as f:
            trace = prepare(f)
            for phase in ("cold", "warm"):
                cpu = usage(args.cgroup)
                result = replay(args.socket, f.fileno(), trace, args.concurrency)
                if result["errors"]:
                    raise RuntimeError(result["errors"])
                result["cpu_usec"] = usage(args.cgroup) - cpu
                del result["request_latency_ns"]
                report[phase] = result
        time.sleep(10)
        print(json.dumps(report | counters(args.cgroup)))
    finally:
        process.terminate()
        process.wait(15)


if __name__ == "__main__":
    main()
