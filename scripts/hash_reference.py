"""Capture stock clamd results for harmless whole-file hash fixtures on Debian."""

import hashlib
import json
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


# Each rule specifies its hash algorithm, size constraint, and signature name.
CASES = {
    "exact": [("md5", "exact", "Barnacle.Exact")],
    "wildcard": [("sha256", "*", "Barnacle.Wildcard")],
    "wrong-size": [("sha1", "wrong", "Barnacle.WrongSize")],
    "no-rule": [],
    "competing": [
        ("sha1", "*", "Barnacle.CompetingWildcard"),
        ("sha1", "exact", "Barnacle.CompetingExact"),
    ],
    "duplicate-key": [
        ("md5", "exact", "Barnacle.First"),
        ("md5", "exact", "Barnacle.Second"),
        ("md5", "exact", "Barnacle.Third"),
    ],
    "duplicate-name": [
        ("sha256", "exact", "Barnacle.Repeated"),
        ("sha256", "exact", "Barnacle.Repeated"),
    ],
    "cross-algorithm": [
        ("sha256", "exact", "Barnacle.SHA256"),
        ("sha1", "exact", "Barnacle.SHA1"),
        ("md5", "exact", "Barnacle.MD5"),
    ],
    "wildcard-versus-algorithm": [
        ("sha256", "exact", "Barnacle.SizedSHA256"),
        ("md5", "*", "Barnacle.WildMD5"),
    ],
}

CONFIG = """Foreground yes
DatabaseDirectory {root}/db
LocalSocket {root}/socket
TemporaryDirectory {root}
DisableCache yes
SelfCheck 0
"""


def fixture(case):
    return bytes(range(256)) + case.encode("ascii")


def write_database(directory):
    directory.mkdir()
    databases = {}
    for case, rules in CASES.items():
        data = fixture(case)
        sizes = {"exact": len(data), "wrong": len(data) + 1, "*": "*"}
        for algorithm, size, name in rules:
            digest = hashlib.new(algorithm, data).hexdigest()
            filename = "fixture.hdb" if algorithm == "md5" else "fixture.hsb"
            suffix = ":73" if size == "*" else ""
            line = f"{digest}:{sizes[size]}:{name}{suffix}\n"
            databases.setdefault(filename, []).append(line)
    digests = {}
    for filename, lines in databases.items():
        content = "".join(lines).encode("ascii")
        (directory / filename).write_bytes(content)
        digests[filename] = hashlib.sha256(content).hexdigest()
    return digests


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


def scan(path, case, rules):
    data = fixture(case)
    row = {"case": case, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    names = {name + ".UNOFFICIAL" for _, size, name in rules if size != "wrong"}
    try:
        reply = stream_request(path, data)
        row["reply"] = reply
        if reply == "stream: OK":
            row.update(result="unmatched", passed=not names)
        elif reply.startswith("stream: ") and reply.endswith(" FOUND"):
            signature = reply[len("stream: "):-len(" FOUND")]
            row.update(result="matched", signature=signature, passed=signature in names)
        else:
            row.update(result="error", error=reply, passed=False)
    except (OSError, ValueError) as error:
        row.update(result="error", error=str(error), passed=False)
    return row


def run(root):
    database = write_database(root / "db")
    config = root / "clamd.conf"
    config.write_text(CONFIG.format(root=root), encoding="ascii")
    package = subprocess.check_output(
        ["dpkg-query", "-W", "-f=${Version}", "clamav-daemon"], text=True
    )
    with (root / "daemon.log").open("w+") as log:
        daemon = subprocess.Popen(
            ["/usr/sbin/clamd", "--config-file", str(config)],
            stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            path = root / "socket"
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if daemon.poll() is not None:
                    log.seek(0)
                    raise RuntimeError(f"clamd exited {daemon.returncode}: {log.read()}")
                try:
                    if request(path, b"zPING\0") == "PONG":
                        break
                except (FileNotFoundError, ConnectionRefusedError):
                    pass
                time.sleep(0.1)
            else:
                raise TimeoutError("private clamd did not answer PING within 30 seconds")
            return {
                "clamav-daemon": package,
                "version_reply": request(path, b"zVERSION\0"),
                "config_template": CONFIG,
                "database_sha256": database,
                "cases": [scan(path, case, rules) for case, rules in CASES.items()],
            }
        finally:
            daemon.terminate()
            try:
                daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait()


if __name__ == "__main__":
    try:
        with tempfile.TemporaryDirectory(prefix="barnacle-", dir="/tmp") as directory:
            report = run(Path(directory))
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(f"hash reference failed: {error}")
    print(json.dumps(report, indent=2))
    sys.exit(0 if all(row["passed"] for row in report["cases"]) else 1)
