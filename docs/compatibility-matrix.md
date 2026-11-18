# Clamd compatibility matrix

This matrix targets Debian 13 arm64, ClamAV 1.4.3+dfsg-1, and engine functionality level 213.
The daemon, libclamav12, clamdscan, clamav-base, and scanning utilities use that package revision.
The local and official profiles use the [same daemon configuration](compatibility/oracle.conf.in).
Each run creates a private directory and binds an available loopback port. [Replay instructions](compatibility/replay.md)

Stock clamd supplies the full-scan verdicts. The Barnacle executable currently performs offline whole-file lookups.
A missing daemon capability is a coverage gap. A hash miss leaves the object pending a complete scan.

## Daemon and client coverage

The runner captures a raw reply for each wire probe. It records the unmodified client's output and exit status separately.
Compare each transport and client mode with its own reference. The pinned daemon's command list defines the command surface.

| Surface | Stock observation or test | Remaining Barnacle work |
| --- | --- | --- |
| `PING`, `VERSION`, `VERSIONCOMMANDS` | Query the running daemon. Compare the version and full advertised command list. | Implement command replies and framing. [#8](https://github.com/yavosh/bacnacle/issues/8) |
| NUL, newline, and legacy frames | Check reply termination with `zPING\0` and `nPING\n`. | Test unprefixed legacy commands, partial reads, and disconnects. [#8](https://github.com/yavosh/bacnacle/issues/8) |
| Unix socket and loopback TCP | Send raw ping and clean stream requests. | Test TCP path semantics, configuration, deadlines, and cancellation. [#8](https://github.com/yavosh/bacnacle/issues/8) |
| `INSTREAM` | Submit clean, detected, nested, competing, and limit fixtures over Unix. Run clamdscan with `--stream`. | Compare candidate bytes, errors, and client exit status for each case. [#8](https://github.com/yavosh/bacnacle/issues/8) |
| `FILDES` | Run unmodified clamdscan with `--fdpass` on a detected file over Unix. | Implement descriptor ownership, errors, and cancellation. [#8](https://github.com/yavosh/bacnacle/issues/8) |
| `SCAN`, `CONTSCAN`, `MULTISCAN`, `ALLMATCHSCAN` | Exercise the client's local path mode, including a missing path. | Test each explicit command, directory traversal, permissions, symlinks, all-match results, and partial failures. [#8](https://github.com/yavosh/bacnacle/issues/8) |
| `IDSESSION`, `END` | Inventory from stock. | Exercise sequential and concurrent requests, IDs, ordering, and session-specific errors. [#8](https://github.com/yavosh/bacnacle/issues/8) |
| `STATS`, `DETSTATS`, `DETSTATSCLEAR` | Stock advertises all three. The two legacy detection statistics commands close the connection without a payload. | Test framing and stable fields using a private daemon. [#8](https://github.com/yavosh/bacnacle/issues/8) |
| `SHUTDOWN`, `QUIT`, signals | The harness starts its own foreground daemon and checks readiness. | Test both aliases, SIGTERM, SIGHUP, exit status, log reopening, and stale socket cleanup. [#8](https://github.com/yavosh/bacnacle/issues/8) |
| `RELOAD`, SIGUSR2, timed self-check | The profile disables timed checks to freeze the inputs. | Compare reloads during active scans, invalid updates, and generation age. [#11](https://github.com/yavosh/bacnacle/issues/11) |
| Service startup | The runner supplies a private clamd.conf and uses packaged clients. | Compare background startup, systemd socket activation, permissions, and service shutdown. [#8](https://github.com/yavosh/bacnacle/issues/8) |

Use the pinned command table for legacy framing and command availability. Later releases can advertise different commands.
[ClamAV 1.4.3 command dispatch](https://github.com/Cisco-Talos/clamav/blob/clamav-1.4.3/clamd/session.c) · [Protocol guide](https://docs.clamav.net/manual/Usage/ClamdProtocol.html)

## Configuration coverage

The [effective option list](compatibility/clamd-options.txt) contains all 135 entries that the pinned `clamconf` reports for this profile.
It includes hidden development options, compatibility aliases, and settings consumed by the on-access client.
The list substitutes `/oracle` and port `3310` for the temporary directory and ephemeral port.
`disabled` is the vendor tool's rendering, including zero-valued numeric options.

The nine settings in the template override the empty-configuration defaults or explicitly select an endpoint.
The oracle exercises socket creation, database selection, foreground startup, streaming, and the 1,024-byte transport ceiling.
For every other option, [#8](https://github.com/yavosh/bacnacle/issues/8) tracks parsing and behavioral tests.
Engine limits and alerts additionally require object or detection fixtures under [#9](https://github.com/yavosh/bacnacle/issues/9) and [#4](https://github.com/yavosh/bacnacle/issues/4).
A recorded setting alone does not establish behavioral parity.

The upstream parser accepts several obsolete directives outside the effective report. These include
`AllowSupplementaryGroups`, `ArchiveBlockMax`, `ArchiveLimitMemoryUsage`, `ArchiveMaxCompressionRatio`, `ArchiveMaxFiles`, `ArchiveMaxRecursion`,
`ArchiveMaxScanSize`, `DetectBrokenExecutables`, `MailFollowURLs`, `MailMaxRecursion`, and `ScanOnAccess`.
It lists the hidden build-dependent `DevCollectHashes` option. The sample configuration's `Example` marker prevents startup.
Check warnings, rejection behavior, and build-specific support under [#8](https://github.com/yavosh/bacnacle/issues/8).
[ClamAV 1.4.3 option parser](https://github.com/Cisco-Talos/clamav/blob/clamav-1.4.3/common/optparser.c)

The packaged daemon advertises `--help`, `--version`, `--foreground`, `--debug`, `--log`, `--config-file`, `--fail-if-cvd-older-than`, `--datadir`, and `--pid`.
The launcher uses `--config-file`. Exercise flag precedence, default paths, and startup failures under [#8](https://github.com/yavosh/bacnacle/issues/8).

## Database coverage

All three archive signatures passed `sigtool --info`. Their header functionality level is 90.
The [pinned SHA-256 digests](whole-file-hashes.md#reproduce-the-pinned-generation) identify the exact input bytes.

| Archive | Generation | Signatures in header | File members |
| --- | ---: | ---: | ---: |
| main.cvd | 63 | 3,287,027 | 12 |
| daily.cvd | 28187 | 355,874 | 25 |
| bytecode.cvd | 339 | 80 | 87 |

These counts include one COPYING file per archive. Bytecode contains 85 CBC members. Member counts differ from header signature counts.
The local fixture profile uses harmless custom hashes. The official profile runs with the pinned generation.
Use each profile's recorded database digests when comparing results.

| Family and extensions | Archives containing these members | Coverage and next test |
| --- | --- | --- |
| Whole-file hashes, `.hdb .hsb` | main, daily | The offline matcher compares exact sizes, wildcards, miss behavior, duplicates, and competing names with stock. |
| PUA-only hashes and rules, `.hdu .hsu .mdu .msu .ndu .ldu` | daily | The profile disables PUA. Test enabling the appropriate categories. [#10](https://github.com/yavosh/bacnacle/issues/10) |
| Ignore names and file allowlists, `.ign .ign2 .fp .sfp` | daily has all four. Main has `.fp .sfp`. | Hash loading applies ignore entries. Test full-scan allowlist and competing-match precedence. [#10](https://github.com/yavosh/bacnacle/issues/10) |
| Extended and logical patterns, `.ndb .ldb` | main, daily | Exercise byte ranges, offsets, conditions, and normalized objects. [#2](https://github.com/yavosh/bacnacle/issues/2) · [#3](https://github.com/yavosh/bacnacle/issues/3) |
| PE section hashes, `.mdb .msb` | main, daily | Exercise benign sections and signed-file metadata. [#10](https://github.com/yavosh/bacnacle/issues/10) |
| Container metadata and certificates, `.cdb .crb` | main, daily | Exercise nested object metadata and certificate decisions. [#9](https://github.com/yavosh/bacnacle/issues/9) · [#10](https://github.com/yavosh/bacnacle/issues/10) |
| PE icons and URL rules, `.idb .pdb .wdb` | daily | Exercise benign local icon and URL fixtures. [#10](https://github.com/yavosh/bacnacle/issues/10) |
| File types and dynamic settings, `.ftm .cfg` | daily | Check type reclassification at each layer and feature selection. [#9](https://github.com/yavosh/bacnacle/issues/9) · [#10](https://github.com/yavosh/bacnacle/issues/10) |
| Bytecode, `.cbc` | bytecode | Compare supported hooks, execution limits, and detection names. [#4](https://github.com/yavosh/bacnacle/issues/4) |
| Generation metadata, `.info` | main, daily, bytecode | Validate signed archives before activation. Exercise CVD and CLD update behavior. [#11](https://github.com/yavosh/bacnacle/issues/11) |

The pinned loader also recognizes `.db .sdb .imp .zmd .rmd .gdb .cat .ioc .pwdb .cud` and build-dependent `.yar .yara`.
The frozen official archives contain none of these members. Track local-format qualification under [#10](https://github.com/yavosh/bacnacle/issues/10).
[ClamAV 1.4.3 database loader](https://github.com/Cisco-Talos/clamav/blob/clamav-1.4.3/libclamav/readdb.c) · [Signature formats](https://docs.clamav.net/manual/Signatures.html)

## Object handling coverage

The [dynamic module inventory](compatibility/engine-modules.txt) records the engine switches with the official feed.
The daemon's scan options and installed libraries also affect dispatch.
For example, the RAR switch is on. The pinned Debian image lacks the optional UnRAR interface.
ARM JIT, SWIZZOR, and the statistics module show as off in the dynamic settings.

| Handler group | Representative inputs and outstanding tests |
| --- | --- |
| Raw, text, script, and HTML | The oracle scans harmless bytes. Compare ASCII and Unicode text, scripts, HTML normalization, and embedded objects. |
| Archives and installers | The nested fixture exercises gzip extraction. Cover ZIP, tar, CPIO, bzip2, 7z, XZ, ARJ, RAR availability, ALZ, EGG, LHA, CAB, CHM, SZDD, and self-extractors. |
| Executables | Compare PE packers and metadata, section hashes, ELF, and thin and universal Mach-O files. |
| Documents and mail | Cover PDF, XDP, RTF, OLE2, Office XML, HWP, OneNote, HTML mail, mbox, BinHex, TNEF, and uuencoding. |
| Media, disk, and other embedded formats | Cover image metadata and fuzzy hashes, SWF, partition tables, UDF, ISO, HFS+, DMG, XAR, SIS, and compiled scripts. |

Every remaining object handler needs a benign behavioral fixture under [#9](https://github.com/yavosh/bacnacle/issues/9).
Each extracted object must retain its parent context and receive all eligible rules.
For the complete dispatch cases, see the [pinned scanner](https://github.com/Cisco-Talos/clamav/blob/clamav-1.4.3/libclamav/scanners.c).

## Reproduce the inventories

Run these commands inside the isolated Debian reference environment with the pinned packages installed.
Use only the oracle configuration and the verified databases.

```sh
mkdir -p /tmp/barnacle-options
sed -e 's|{root}|/oracle|g' -e 's|{port}|3310|g' docs/compatibility/oracle.conf.in \
  > /tmp/barnacle-options/clamd.conf
clamconf --config-dir=/tmp/barnacle-options | sed -n '/^Config file: clamd.conf$/,/^$/p' \
  | sed '1,2d;/^$/d' > /tmp/barnacle-options/actual.txt
diff -u docs/compatibility/clamd-options.txt /tmp/barnacle-options/actual.txt

printf 'reference probe\n' > /tmp/barnacle-options/sample.txt
clamscan --debug -d "$database_dir" /tmp/barnacle-options/sample.txt > /tmp/barnacle-options/scan.log 2>&1
sed -n -E 's/^LibClamAV debug: (Module .*|   \* Submodule .*)/\1/p' /tmp/barnacle-options/scan.log \
  > /tmp/barnacle-options/modules.txt
diff -u docs/compatibility/engine-modules.txt /tmp/barnacle-options/modules.txt

for name in main daily bytecode; do
  sigtool --info "$database_dir/$name.cvd" || exit 1
  sha256sum "$database_dir/$name.cvd"
  tail -c +513 "$database_dir/$name.cvd" | tar -tzf -
done
```
