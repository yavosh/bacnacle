"""Build an index from the verified ClamAV generation used by the hash experiment."""

import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile


# Daily is loaded before main in the pinned engine. Members retain archive order.
ARCHIVES = {
    "daily": "423f7774182bfbc82b50c7796c68a93f8b1817ef7ebbc88d7def444bc2c8f35b",
    "main": "0b2182d229f46981ec8f535382222f7c9dfdd656b250ad47988b910a8d302365",
    "bytecode": "6d4aa01f219e988060fc419f495d07f27e0cdf1a2cccc065971da922c76f7ffb",
}
EXTENSIONS = ("hdb", "hsb", "hdu", "hsu", "ign", "ign2", "fp", "sfp")


def extract_inputs(directory, temporary):
    inputs = []
    for name, expected in ARCHIVES.items():
        source = directory / (name + ".cvd")
        with source.open("rb") as archive:
            checksum = hashlib.sha256()
            for chunk in iter(lambda: archive.read(1024 * 1024), b""):
                checksum.update(chunk)
            if checksum.hexdigest() != expected:
                raise ValueError(f"{source}: SHA-256 differs from the verified generation")
            archive.seek(512)
            members = {f"{name}.{ext}" for ext in EXTENSIONS}
            with tarfile.open(fileobj=archive, mode="r|gz") as stream:
                for item in stream:
                    if item.name in members and item.isfile():
                        target = temporary / item.name
                        with target.open("xb") as output:
                            shutil.copyfileobj(stream.extractfile(item), output)
                        inputs.append(target)
    return inputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("database_directory", type=Path)
    parser.add_argument("index", type=Path)
    args = parser.parse_args()
    try:
        with tempfile.TemporaryDirectory(prefix="barnacle-cvd-") as tmp:
            inputs = extract_inputs(args.database_directory, Path(tmp))
            subprocess.run(
                [args.binary.resolve(), "build", args.index, "--official", *inputs], check=True
            )
    except (OSError, ValueError, tarfile.TarError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"index build failed: {error}\n")


if __name__ == "__main__":
    main()
