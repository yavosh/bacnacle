# Run the Barnacle daemon

Build the service, compiler, and validator with one command. The release executable is `target/release/barnacle`.

```sh
cargo build --locked --release --bin barnacle
barnacle serve --foreground --config-file /path/to/clamd.conf
```

Barnacle reads external databases from `DatabaseDirectory`. Use `TemporaryDirectory` for the compiled index during startup and reload.
Keep FreshClam responsible for downloads. The current loader verifies the three [pinned archives](whole-file-hashes.md#reproduce-the-pinned-generation) before activation.
A different official generation requires the update support tracked in [#11](https://github.com/yavosh/bacnacle/issues/11).
The Linux arm64 executable links to libc and the GCC runtime. It starts its own scanner and listeners.

For offline use, compile a local whole-file signature database and verify the resulting index.

```sh
barnacle build index.bhi local.hdb
barnacle validate index.bhi
```

## Service and clients

The default configuration path is `/etc/clamav/clamd.conf`. Barnacle accepts the packaged service's `--foreground=true` argument.
For a separate test installation, place the executable at `/usr/local/bin/barnacle`.
The [systemd drop-in](../packaging/systemd/barnacle.conf) selects that executable for the packaged `clamav-daemon.service`.
The existing socket unit supplies the listener. The service account needs database read access and a writable temporary directory.
For a private foreground instance, specify a separate configuration, socket, and runtime directory.

`PING` reports readiness after the initial generation validates. Each scan pins its generation.
An unsuccessful reload leaves the previous generation active. Use `RELOAD` or SIGUSR2 to request a reload.
Use SIGHUP to reopen logs and SIGTERM to stop the service.

## Scan results

Barnacle can report a confirmed local whole-file signature with its stock name.
A hash miss, an unsupported detection stage, or an ambiguous winner produces an error.
Keep stock clamd authoritative for complete scan verdicts. An ordinary unmatched upload produces the following NUL-terminated reply.

```text
stream: Incomplete scan: unsupported detection coverage. ERROR
```

The unmodified Depot upload client reported the same local signature over Unix and TCP with Barnacle and stock clamd.
Both daemons returned the same size-limit error for a 1,025-byte upload with `StreamMaxLength 1K`.
Depot treated an incomplete Barnacle scan as an error. The reference clamd returned clean on that fixture.
During partial uploads, Depot preserved both context cancellation and deadline expiry. A subsequent ping succeeded on both transports.
The test used Depot revision `531704866a5d1881f23a4beb633dcdefb0da6bb9` in an isolated Debian 13 arm64 container.

## Verification

Run the ordinary Rust tests with `cargo test --locked --all-targets`.
Use the pinned Debian environment for the stock lifecycle and systemd socket activation tests.

```sh
cargo test --locked --test daemon -- --ignored
```

The activation test invokes the packaged `systemd-socket-activate` launcher on a private Unix socket.
Both daemons accept the inherited listener and leave its path under launcher ownership.
The [compatibility matrix](compatibility-matrix.md) tracks command and option coverage.
The [replay guide](compatibility/replay.md) explains how to reproduce the comparison.
