"""Compare each Barnacle index backend with the recorded stock clamd replies."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from hash_reference import fixture, write_database


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    repo = Path(__file__).resolve().parents[1]
    reference = json.loads((repo / "docs/hash-reference-debian13.json").read_text())
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        database = root / "db"
        if write_database(database) != reference["database_sha256"]:
            raise SystemExit("fixture databases differ from the stock reference")
        index = root / "fixture.idx"
        subprocess.run([binary, "build", index, *sorted(database.iterdir())], check=True)
        for case in reference["cases"]:
            body = root / "body"
            data = fixture(case["case"])
            if hashlib.sha256(data).hexdigest() != case["sha256"]:
                raise SystemExit(f"{case['case']}: fixture bytes differ from stock")
            body.write_bytes(data)
            expected = case["result"]
            if expected == "matched":
                expected += "\t" + case["signature"]
            for backend in ("memory", "pread", "mmap"):
                actual = subprocess.check_output(
                    [binary, "scan", backend, index, body], text=True
                ).removesuffix("\n")
                if actual != expected:
                    raise SystemExit(f"{case['case']} ({backend}): {actual!r}, expected {expected!r}")
    print(f"{len(reference['cases'])} stock reference cases passed on all three backends")


if __name__ == "__main__":
    main()
