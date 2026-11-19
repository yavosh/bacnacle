# Object handling and scan limits

The reference uses Debian 13 arm64 and ClamAV `1.4.3+dfsg-1`. The scan order depends on the object type.
Stock clamd supplies complete upload verdicts during development. [Pinned configuration and engine inventory](compatibility-matrix.md)

## Reference handlers

The following groups reflect the pinned engine configuration. An enabled handler still requires a fixture comparison.
The raw engine inventory lists individual submodules, including disabled entries. [Engine modules](compatibility/engine-modules.txt)

| Stage | Formats or features in the reference | Comparison coverage |
| --- | --- | --- |
| Archives and compressed streams | ZIP, gzip, bzip2, XZ, TAR, CPIO, 7z, RAR, ARJ, CAB, SZDD, CHM, BinHex, EGG, LHA, ALZ and SIS | Rust fixtures cover all listed families, including stored and compressed legacy SIS members. The RAR comparison checks the reference installation without UnRAR. [Archive comparisons](../tests/object_archives.rs) |
| Disk images and partitions | ISO 9660, UDF, DMG, XAR, HFS+, MBR, GPT and APM | Tests cover ISO 9660, Joliet directories, and XAR catalogs and members. Other disk image formats need further comparisons. [ISO comparisons](../tests/object_iso.rs) |
| Installers and embedded files | NSIS, AutoIt, InstallShield and embedded file recognition | These handlers need individual fixtures. |
| Documents | OLE2, OOXML, Word/Excel XML, HWP, OneNote, PDF, RTF and SWF | Tests cover ordinary PDF, Office, RTF and Flash documents, including competing child detections and scan limits. [PDF comparisons](../tests/object_pdf.rs) · [OLE comparisons](../tests/object_ole.rs) |
| Text and mail | HTML, UTF-16 HTML, script normalization, JavaScript, script encoding, mbox/MIME, TNEF and uuencoding | Rust fixtures exercise ordinary scripts, HTML, MIME, TNEF, uuencoded files, and data URLs. [Text comparisons](../tests/object_text.rs) |
| Executables and graphics | PE, ELF, Mach-O, universal Mach-O, RIFF, GIF, PNG, JPEG and TIFF | BMP and GIF fixtures compare raw body and whole-file winners. Full image heuristics and executable unpacking remain open. [Image comparisons](../tests/object_images.rs) · [Executable offsets](body-patterns.md) |

The engine also enables password support for archives and format-specific detection heuristics.
The reference image lacks an installed UnRAR helper even though its engine configuration lists RAR.
The reference applies format settings and limits individually. [Effective clamd options](compatibility/clamd-options.txt)

### ISO 9660 disk images

The tests cover cooked sectors and raw CD sectors of 2,352 and 2,448 bytes.
The samples use 512-, 1,024-, and 2,048-byte logical blocks. They include member data spanning sectors.
Stock scans the outer image before its files. Within each volume, it follows directory order and descends into subdirectories.
Barnacle borrows contiguous file bytes and skips framing bytes when reading raw sectors.
Hybrid bootable images remain unverified. [Rust fixtures](../tests/object_iso.rs)

### PDF objects

Stock scans the raw PDF before extracting objects. The first matching indirect object wins in the tested document.
Barnacle scans decoded streams with fresh object contexts. Page content can also produce a normalized text child.
Document names come from the winning signature. [End-to-end fixtures](../tests/object_pdf.rs)

| PDF feature | Observed coverage |
| --- | --- |
| Page streams and embedded files | Unfiltered, Flate, ASCIIHex, ASCII85, run-length and chained ASCIIHex/Flate data. |
| Page text | Parenthesized strings in page text arrays. The normalized bytes can match a whole-file hash. |
| Nested inputs | ZIP containing a PDF and a PDF with competing raw and child rules. |
| Policies and truncated input | Parser disabled, recursion and expanded-size alerts, a missing final trailer, and a truncated stream. |
| Additional PDF stages | Encryption, compressed object streams, JavaScript actions and other stream filters require further comparisons. |

### UDF optical images

Stock scans the raw disc before its UDF members. An outer whole-file hash takes precedence.
The reference visits file entries in physical descriptor order. The test rearranges entries while preserving their directory names and references.
Barnacle checks each recorded extent against the image length and scans it directly. [UDF comparisons](../tests/object_udf.rs)

The Rust fixtures cover single short, long, and extended allocation descriptors, cross-sector data, truncation, and nested ZIP input.
Stock supplies an empty original filename and sets the scan parent to `CL_TYPE_UDF` for these members.
An extent exceeding the remaining scan budget ends the UDF pass. A later smaller file receives no scan.
The reference also stops at an unsupported allocation layout. Images with fragmented or embedded extents need further comparisons.

Two independent control images contain the same harmless text files. Apple `hdiutil makehybrid` produced both with UDF version 1.02.
Stock reported `OK` on the pure UDF control with the two local member hashes loaded.
The ISO/UDF bridge detected the first text file and assigned `CL_TYPE_ISO9660` as its parent.
The checked-in images are gzip-compressed and the Rust tests expand them before scanning. [Authoring controls](../tests/fixtures/udf)

### XAR archives

Stock checks the decompressed XML catalog first. It then visits XML subdocuments, heap entries, and the raw archive.
Catalog order selects the first matching extended attribute or file. Heap offsets can appear in a different order.
Stock serializes a subdocument’s inner XML before matching it. [XAR comparisons](../tests/object_xar.rs)

Barnacle scans stored data, zlib, and LZMA directly. Bzip2 and XZ entries pass through their respective archive handlers.
An incorrect entry checksum does not suppress a detection. A damaged zlib member can precede a valid matching file.
An oversized catalog prevents scanning its heap. Byte, file count, and recursion limits use the daemon configuration.

Catalog decoding spills to a private file after 64 KiB. The pinned allocation ceiling is one GiB, including the terminating byte.
LZMA dictionary estimates above 64 MiB and subdocuments needing namespace or extended XML serialization still return incomplete coverage.

### OLE compound documents

Stock scans an ordinary compound document’s streams before checking the outer file hash.
It visits each directory node before its right and left siblings. Storage children precede those siblings.
A child inside a nested storage still has the enclosing compound file as its scan parent. [Rust comparisons](../tests/object_ole.rs)

| OLE feature | Observed coverage |
| --- | --- |
| Ordinary streams | Mini sectors, regular sectors, nested storage, three competing streams, and a single-stream version 4 file. |
| Embedded Package | A root Package payload wins against its envelope. In a nested storage, the envelope hash can win first. |
| Nested formats | ZIP inside OLE, OLE inside ZIP, and parent-type matching on extracted streams and attachments. |
| Limits | File count, storage depth, scan recursion, remaining scan bytes, and scanning with `ScanOLE2 no`. |
| Coverage gaps | VBA, XLM, embedded Office images, HWP, encryption, and larger version 4 directories require further comparisons. |

Rust tests compare competing raw streams and embedded packages in macro-free Word, Excel, and PowerPoint documents.
They cover flat directories, nested storages, shared stream names, and the underlying filesystem’s scan order.
Barnacle creates empty private directory entries when it needs that order. It reads each payload from the compound file.
Barnacle reads streams with the MIT-licensed `cfb` crate. [Dependency license](https://github.com/mdsteele/rust-cfb/blob/master/LICENSE)

## Reference order and limits

The Rust runner generates two benign local signature files. It sends every sample through `INSTREAM` over a private Unix socket.
It enables extended detection logs, disables caching, and repeats each configuration with `AlertExceedsMax` off and on.
The 250 rows cover 24 profiles under both alert settings.
Both the protocol and log observations identify the signature. [Rust runner](../examples/object_reference.rs)

Barnacle matched 165 protocol and log rows exactly, including every stock detection and limit alert.
The remaining 85 stock `OK` replies produced Barnacle's explicit incomplete-coverage error.

| Observation | Stock result |
| --- | --- |
| A raw document matches a body rule and a whole-file hash. Its gzip layers also have matching hashes. | The innermost body rule wins in all three forms. The log reports the outer input's MD5 and size. |
| A two-entry ZIP has distinct child detections and reversed central directory order. | The first local entry wins on this fixture. |
| A truncated gzip contains an ordinary document without a local signature. | Stock returns `OK` on this fixture. |
| A local hash matches a five-byte input. | Stock returns `OK`. |
| `MaxRecursion` or `MaxFiles` is 1, 2 or 3. | The input counts as the first object. One gzip child needs 2. A gzip within gzip needs 3. |
| An expanded member is exactly `MaxFileSize` bytes. | Stock detects the member. The same gzip loses that detection when the limit is one byte lower. |
| The input and its expanded member total exactly `MaxScanSize`. | Stock detects the member. Reducing the limit by one byte produces a limit outcome. |
| One ZIP entry exceeds `MaxFileSize` and a later entry matches. | The later detection wins with both alert settings. An outer hash can also win after a child limit. |
| The scan reaches both the file count and recursion limit. | The ZIP fixture reports `MaxFiles` when alerts are enabled. |
| The scan exceeds its 1 ms deadline on a 2 MiB document collection. | Stock returns `OK` with alerts off and reports `Heuristics.Limits.Exceeded.MaxScanTime` with alerts on. |

The pinned defaults are 100 MiB per object, 400 MiB total, 17 recursion levels, and 10,000 objects.
The default scan timer and limit alerts are disabled. Zero disables the byte and file count limits.
Stock treats `MaxRecursion 0` as a request for the engine default. [Effective options](compatibility/clamd-options.txt) · [Reference limit code](https://github.com/Cisco-Talos/clamav/blob/clamav-1.4.3/libclamav/others.c)

With alerts enabled, limits can yield `Heuristics.Limits.Exceeded.MaxFileSize`, `MaxScanSize`, `MaxFiles`, `MaxRecursion`, or `MaxScanTime`.
An earlier definitive signature can take precedence. An oversized top-level file takes a separate path.
Stock omits the extended MD5 and size when that initial file-size check produces the detection.
An internal limit logs the outer input's MD5 and size. [Reference scan pipeline](https://github.com/Cisco-Talos/clamav/blob/clamav-1.4.3/libclamav/scanners.c)

## Replay

Run the following commands as an ordinary user in the pinned Debian environment.
The two output files record the profile, alert setting, sample, input size, protocol result, and extended log result.
The 1 ms observations depend on elapsed wall time. Use the reference VM when reproducing them.

```sh
cargo build --release --locked --bin barnacle --example object_reference
target/release/examples/object_reference /usr/sbin/clamd > /tmp/stock-objects.tsv
target/release/examples/object_reference target/release/barnacle > /tmp/barnacle-objects.tsv
diff -u /tmp/stock-objects.tsv /tmp/barnacle-objects.tsv
```

The official profile uses verified main 63, daily 28187, and bytecode 339. It includes a harmless nested gzip.
The stock replay compares both local and official databases against the frozen protocol observations. [Official replay steps](compatibility/replay.md)

## Concurrent nested scans

The benchmark uses the same 128 benign payloads and 101,744 active body rules as the body benchmark.
Half the inputs have one gzip layer. The other half have two.
Both daemons scanned the same bytes on one vCPU with 2 GiB RAM and no swap.
Each value is a median of three fresh guest boots. [VM configuration and database preparation](body-benchmark.md)

| Concurrent clients | Pass | Stock scans/s | Barnacle scans/s | Stock p95 ms | Barnacle p95 ms |
| ---: | --- | ---: | ---: | ---: | ---: |
| 1 | First | 676 | 960 | 4.51 | 2.97 |
| 1 | Warm | 715 | 964 | 4.40 | 2.97 |
| 4 | First | 669 | 936 | 21.32 | 12.73 |
| 4 | Warm | 705 | 957 | 20.49 | 12.74 |

A separate pass repeats 128 objects after the timed workload.
Its scanner cgroup peak includes file-backed pages. The driver resets the kernel counter before this pass.
The driver samples allocated blocks on the temporary filesystem every millisecond.
Scratch growth includes unlinked files. Individual spikes between samples can exceed the reported growth.

| Clients | Daemon | Build peak MiB | Warm current MiB | Scan peak MiB | Sampled scratch growth MiB |
| ---: | --- | ---: | ---: | ---: | ---: |
| 1 | Stock | 94.16 | 100.87 | 103.21 | 0.75 |
| 1 | Barnacle | 79.11 | 73.27 | 74.29 | 0.75 |
| 4 | Stock | 94.16 | 101.51 | 108.22 | 3.02 |
| 4 | Barnacle | 79.14 | 73.64 | 76.23 | 2.25 |

All 9,216 responses returned the expected local signature. Barnacle took 271–272 ms to become ready. Stock took 243–244 ms.
These measurements cover this gzip workload and the body database. [Raw observations](benchmarks/object-profile-samples.csv)

Use the body benchmark's data disk and private daemon configuration. Build the current Rust driver.
Pass `gzip` after the client count. The driver runs the first, warm, and pressure passes in that order.

```sh
/data/body_bench "$daemon" /data/clamd.conf /run/clamav/clamd.ctl "$clients" gzip
```

The gzip benchmark used Barnacle binary SHA-256 `9b416808ed0f741d5d1ec8745d224ab67f49d6db9d90262f002043cb6cb02062`.

### Nested XZ streams

Six fresh guest boots alternated stock clamd and Barnacle. Four clients scanned the same 128 files per boot.
Each file had one or two XZ layers, encoded at preset 5. All 4,608 replies returned the expected local signature.

| Median of three boots | Stock clamd | Barnacle |
| --- | ---: | ---: |
| Warm scans/s | 349.19 | 489.20 |
| Warm p95 ms | 32.40 | 22.67 |
| Scan peak MiB | 113.83 | 75.56 |
| Sampled scratch growth MiB | 2.34 | 2.26 |
| Ready ms | 244.97 | 273.75 |

Run the same benchmark command with `xz` as its last argument. The body-rule database and VM settings match the gzip experiment.
The measured Barnacle binary had SHA-256 `e2e85a9bdc8ffb909bc3c704b0025316163ad4ad0490ccd6a1d3a66dc91a5d3c`. [Raw observations](benchmarks/object-xz-profile-samples.csv)
