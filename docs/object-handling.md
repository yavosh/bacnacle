# Object handling and scan limits

The reference uses Debian 13 arm64 and ClamAV `1.4.3+dfsg-1`. The scan order depends on the object type.
Stock clamd supplies complete upload verdicts during development. [Pinned configuration and engine inventory](compatibility-matrix.md)

## Reference handlers

The following groups reflect the pinned engine configuration. An enabled handler still requires a fixture comparison.
The raw engine inventory lists individual submodules, including disabled entries. [Engine modules](compatibility/engine-modules.txt)

| Stage | Formats or features in the reference | Comparison coverage |
| --- | --- | --- |
| Archives and compressed streams | ZIP, gzip, bzip2, XZ, TAR, CPIO, 7z, RAR, ARJ, CAB, SZDD, CHM, BinHex, EGG, LHA, ALZ and SIS | Rust fixtures cover all listed families, including stored and compressed legacy SIS members. The RAR comparison checks the reference installation without UnRAR. [Archive comparisons](../tests/object_archives.rs) |
| Disk images and partitions | ISO 9660, UDF, DMG, XAR, HFS+, MBR, GPT and APM | Tests cover optical images, XAR, DMG, three partition maps, and files inside HFS+ and HFSX. [ISO comparisons](../tests/object_iso.rs) · [DMG comparisons](../tests/object_dmg.rs) · [Partition comparisons](../tests/object_partition.rs) |
| Installers and embedded files | NSIS, AutoIt, InstallShield and embedded file recognition | Tests exercise NSIS, InstallShield and embedded PE resources. AutoIt still needs a separate comparison. [Installer comparisons](../tests/object_installers.rs) · [Embedded comparisons](../tests/object_embedded.rs) |
| Documents | OLE2, OOXML, Word/Excel XML, HWP, OneNote, PDF, RTF and SWF | Tests cover ordinary PDF, Office, RTF and Flash documents, including competing child detections and scan limits. [PDF comparisons](../tests/object_pdf.rs) · [OLE comparisons](../tests/object_ole.rs) |
| Text and mail | HTML, UTF-16 HTML, script normalization, JavaScript, script encoding, mbox/MIME, TNEF and uuencoding | Rust fixtures exercise ordinary scripts, HTML, MIME, TNEF, uuencoded files, and data URLs. [Text comparisons](../tests/object_text.rs) |
| Executables and media | PE, ELF, Mach-O, universal Mach-O, Java, RIFF, GIF, PNG, JPEG and TIFF | Tests cover Mach-O slices, ELF sections, Java classes, WAVE audio, and five image formats. Image heuristics and executable unpacking remain open. [Executable comparisons](../tests/object_macho.rs) · [Media comparisons](../tests/object_images.rs) |

The engine also enables password support for archives and format-specific detection heuristics.
The reference image lacks an installed UnRAR helper even though its engine configuration lists RAR.
The reference applies format settings and limits individually. [Effective clamd options](compatibility/clamd-options.txt)

`ScanXMLDOCS no` leaves ZIP member scanning enabled in packaged Word, Excel, PowerPoint, and HWP documents.
Both daemons detect the same member hash with this setting. [Office container comparisons](../tests/object_parents.rs)

In the authored Word and PowerPoint packages, the document XML signature wins over the picture and package hashes.
In the spreadsheet, stock classifies the stylesheet as HTML at the `<tableStyles` element.
Its 879-byte normalized markup wins over the worksheet, picture, and package hashes.
Disabling HTML scanning makes the worksheet win. Disabling archive scanning makes each package hash win.
[Office package comparisons](../tests/object_office_packages.rs) · [Fixture provenance](../tests/fixtures/ooxml/README.md) · [Throughput and memory](benchmarks/object-office-packages.md)

HWPX assets under `BinData/` can trigger a central-directory lookup for `Contents/content.hpf`.
Stock accepts a prefix in the first three local headers and requires the complete filename in the directory.
Both daemons preserve the resulting HWPX or ZIP parent type. [HWPX comparisons](../tests/object_parents.rs)

### ZIP Deflate64 members

Both daemons detect the first member of a 7-Zip archive containing an 81,000-byte ledger and a later text file.
The ledger hash wins over the archive hash. Stock metadata preserves both filenames in local-header order.
At file limits of 16,383 and 16,384 bytes, the scanned prefixes contain 8,192 and 16,384 bytes respectively.
The comparisons also cover nested ZIPs, streaming descriptors, a short final block, and count, recursion, and scan-size limits.
[Rust comparisons](../tests/object_zip_deflate64.rs) · [Fixture provenance](../tests/fixtures/zip/README.md)

Barnacle limits each decoder call to 8 KiB of input and output. It releases the fixed dictionary before scanning the child.
Stock checks the file count first. Outputs through five bytes bypass the scan-size and recursion limits.
For larger outputs, the scan-size limit precedes recursion. If available scan bytes might run out, Barnacle counts past 64 KiB before using disk.
A member that fits can then be decoded again. Unconstrained members need one pass.
An invalid Deflate64 stream that the decoder rejects returns incomplete coverage. Encrypted entries and ZIP64 layouts remain outside these comparisons.
The Rust decoder uses the MIT license. [deflate64 0.1.12](https://docs.rs/crate/deflate64/0.1.12)

Four clients scanned the ledger ZIP at 4,489 scans/s with Barnacle `be9927b` and 3,541 scans/s with stock.
Median p95 latency was 1.52 ms and 2.47 ms respectively. Median peak cgroup memory was 3.74 MiB and 5.50 MiB.
All 15,360 requests across both concurrency levels returned the ledger signature.
Use the Office benchmark's container settings with 512 requests per client and `ledger-deflate64.zip` as the input.
The sole rule was `40e674895de36362c65153f79fa06d45:81000:Workspace.Reference`.
[Raw ZIP measurements](benchmarks/object-zip-deflate64.csv) · [Benchmark procedure](benchmarks/object-office-packages.md#reproduction)

### Small ZIP64 archives

Stock scans stored and deflated members in libarchive ZIP64 files with usable 32-bit directory fields.
The first eligible member wins over the archive. The ZIP parent carries each member’s basename.
Classic count and directory-size sentinels preserve scanning order, including when central records appear in reverse.
A sentinel in the classic directory offset suppresses all members, including with file-count and recursion alerts enabled.
The Apache fixtures exercise per-member sentinels. Stock skips those members and continues with later eligible entries.
The comparisons cover single-disk archives with a fixed ZIP64 trailer. Large offsets, split archives, and extended trailers remain unverified.
[Rust comparisons](../tests/object_zip64.rs) · [Writer settings](../tests/fixtures/zip64/README.md)

### Executable containers

Stock scans a universal Mach-O file's architecture slices in descriptor order before checking the whole-file hash.
Each slice has its own offsets and an unnamed layer under `CL_TYPE_MACHO_UNIBIN`.
The reference skipped the FAT64 and swapped-endian controls. [Apple-authored object files](../tests/fixtures/macho)

Both daemons match raw hashes and section-relative rules on ordinary ELF files with either `ScanELF` setting.
Both also match an outer PE hash before processing a nested PE resource.
`ScanPE no` disables nested PE extraction. `MaxEmbeddedPE` includes an exact-size resource, and zero disables the size cap.
[ELF comparisons](../tests/object_macho.rs) · [Embedded PE comparisons](../tests/object_embedded.rs)

A Java 17 interface matched its target-12 body signature both directly and inside a JAR.
A Java 11 class matched its whole-file hash in both locations. Stock treated the Java 21 control as generic data.
Both daemons selected its whole-file hash over a target-12 rule. [Java fixtures](../tests/fixtures/java)

Little-endian and big-endian WAVE files matched generic body and whole-file signatures both directly and inside ZIP files.
PNG, JPEG, TIFF, GIF, and BMP controls matched graphics signatures before whole-file hashes. [Media comparisons](../tests/object_images.rs)

### Unicode HTML

Both daemons matched hashes of normalized markup and plain text from little-endian and big-endian UTF-16 pages.
The comparisons cover multilingual text, a ZIP attachment, and a 2,500-paragraph page.
For little-endian pages, the HTML size limits apply to the converted bytes. Conversion also consumes one recursion level.
For big-endian pages with a byte order mark, the limits apply to the original bytes.
When limits compete, stock checks normalized output size before file count or recursion. Barnacle counts excluded views without storing their output.
The tests cover file count, scan size, recursion, and disabling HTML scans. [Unicode HTML comparisons](../tests/object_unicode_html.rs) · [Memory and throughput measurements](benchmarks/object-unicode-html.md)

### HTML character references and links

Barnacle reproduces the pinned markup and text hashes for ordinary company names, ampersands in prose, and URL query parameters.
The reference recognized 662 of the 2,125 semicolon-terminated WHATWG names. These include all 252 HTML 4 names.
Seven names use older numeric assignments. Barnacle stores the measured subset in a read-only 9,268-byte table.
[Table provenance and notices](../THIRD-PARTY-NOTICES.md) · [HTML 4 character references](https://www.w3.org/TR/html401/sgml/entities.html) · [WHATWG named references](https://html.spec.whatwg.org/entities.json)

The markup view preserves unknown names in lowercase. The text view omits references in prose and retains links from anchors and images.
URL comparisons cover literal ampersands, escaped separators, mixed-case query values, accented characters, and the 1,024-byte capture limit.
After a second space run, stock truncates the captured URL and retains subsequent reference spellings in markup.
Pending multibyte text can resume in the next attribute, even across tags.
Certain combinations of literal controls and tag delimiters in quoted attributes remain incomplete. Entity coverage outside the WHATWG list remains unverified.
[HTML character reference comparisons](../tests/object_html_entities.rs)

### Forwarded email

Barnacle and pinned clamd scan Base64 and quoted-printable `message/rfc822` multipart attachments as child mail objects.
A decoded `forward.eml` can match its receipt before a later contact card.
An oversized forward leaves the contact eligible. At the size boundary, the forwarded file can match its own hash.
A plain forward without a transfer marker or a uuencoded attachment is skipped, including one containing a raw PNG.
Stock recovers a uuencoded note as a direct child of the enclosing mail. A contact attachment wins before the note.
The note wins before a raw body signature or the mail hash. Stock assigns the note a private temporary filename.
Notes of five bytes or fewer are skipped before checking file count. Larger notes check decoded size before count and depth.
For an 8bit or binary forward with one note and a transfer marker, stock retains the `end` line.
It scans that revised forward immediately. A following contact remains eligible before the deferred note.
Multiple notes and mixed forwards with an absent or 7bit declaration remain incomplete after direct attachments miss.
The marker is a case-insensitive line prefix, `Content-Transfer-Encoding`, including in prose. A lowercase `7bit` anywhere on that line suppresses it. With a marker, 8bit or binary members are scanned immediately.
An absent or 7bit declaration defers the saved forward until after ordinary attachments.
Multiple deferred forwards and the extra recovery file produced by explicit 7bit remain incomplete after direct attachments miss.

A standalone `message/rfc822` uses the literal embedded headers. A Base64 body without headers produced no mail child.
A simple quoted-printable-wrapped text message retained its literal body. More complex standalone quoted-printable layouts remain incomplete.
[Forwarded mail comparisons](../tests/object_mail_forward.rs) · [Throughput and memory](benchmarks/object-forwarded-mail.md)

### Binary HWP documents

HWP5 stores document streams in an OLE compound file. A `FileHeader` stream starts with the HWP signature and contains compression flags.
An unrelated stream named `FileHeader` remains ordinary OLE data. [Hancom HWP5 format](https://cdn.hancom.com/link/docs/%ED%95%9C%EA%B8%80%EB%AC%B8%EC%84%9C%ED%8C%8C%EC%9D%BC%ED%98%95%EC%8B%9D_5.0_revision1.2.pdf)

Both daemons scan HWP5 streams before the document hash in compound-directory order.
Compressed paragraphs, document properties, and binary attachments use raw DEFLATE. Preview streams retain their original bytes.
Raw streams receive lowercase names. Inflated streams have no filename. Both retain `CL_TYPE_MSOLE2` as their parent.
An embedded `CL_TYPE_HWPOLE2` wrapper scans the compound file after its four-byte length, including when the length differs.
`ScanOLE2` controls HWP5 and wrapped OLE extraction. [Binary HWP comparisons](../tests/object_hwp.rs)

HWP3 uses a separate paragraph and attachment format. Stock scans the information records before the uncompressed document content and the whole-file hash.
The fixtures cover stored and compressed paragraphs, OLE data, images, hyperlink data, background images, and ZIP ancestry.
`ScanHWP3 no` preserves the outer hash, and `MaxRecHWP3 0` suppresses paragraph parsing.
Rich paragraph controls, protected documents, and HWP5 streams with competing Office macro passes still have incomplete coverage. [HWP3 comparisons](../tests/object_hwp/v3.rs)

### Word 2003 XML, Excel 2003 XML, and HWPML

The reference recognizes Word and Excel XML markers within the first 1,024 bytes.
Its HWPML marker includes the UTF-8 byte order mark.
Both daemons scan attachments in document order before the XML document hash.
The document supplies the parent type. Decoded attachments have no original filename.
Turning off `ScanXMLDOCS` preserves the document hash. [XML comparisons](../tests/object_xml.rs)

Word and Excel store binary data in Base64 text. The reference detects line-wrapped data and skips single-line data without a newline.
It skips CDATA and contents beneath Office style and font elements.
The tests cover numeric character references, nesting, and a 100,000-byte attachment.
The reference stops parsing after a text node exceeds 10,000,000 bytes. [Word 2003 XML reference](https://learn.microsoft.com/en-us/previous-versions/office/developer/office-2003/aa196310(v=office.11))

HWPML supports plain text, Base64, and raw DEFLATE attachments.
With a 12,000-byte file limit, both daemons detect a hash of the first 8,192 expanded bytes.
Barnacle streams expansion into a private spool. DTDs, names exceeding 1,024 bytes, and nesting beyond 256 levels produce incomplete coverage.
The HWPML marker can precede a document with a declared legacy encoding. [Hancom HWPML specification](https://cdn.hancom.com/link/docs/%ED%95%9C%EA%B8%80%EB%AC%B8%EC%84%9C%ED%8C%8C%EC%9D%BC%ED%98%95%EC%8B%9D3.0_HWPML_revision1.2.pdf)

Both daemons scan plain XML attachment text as UTF-8 and preserve the original bytes inside Base64 attachments.
Comparisons cover UTF-8, ASCII, ISO-8859-1, ISO-8859-2, Windows-1251, Windows-1252, Shift_JIS, CP932, EUC-KR, and CP949.
They verify encoding aliases, numeric references, and the distinction between Latin-1 controls and Windows punctuation.
The file-size limit uses the UTF-8 child length. The cumulative limit also includes the original XML byte count.
The text-node limit applies after conversion. Barnacle checks XML characters, references, and duplicate attributes before releasing an attachment.
It returns incomplete coverage for unsupported declarations or elements with more than 1,024 attributes. [Encoding comparisons](../tests/object_xml.rs)

Stock's XML reader pushes 512-byte input blocks. The final block can contain a conversion error after a matching attachment.
Both scanners preserved the same result across 4,980 such Windows-1252, ASCII, and CP932 controls.
A further 6,640 controls placed UTF-8 errors, undefined entities, invalid references, and control characters around block boundaries.
Barnacle withheld 514 attachment matches from stock and produced no extra matches across the 11,620 controls.
In one reproducible Workbook, the attachment starts at byte 430 and an invalid character reference starts at byte 515.
Stock detects that attachment. Barnacle returns incomplete coverage. Stock can also detect the raw document hash after a metadata error.
Barnacle returns incomplete coverage when the earlier matching stage remains uncertain. [Rust controls](../tests/object_xml.rs) · [Pinned libxml2 reader](https://github.com/GNOME/libxml2/blob/v2.9.14/xmlreader.c)

Barnacle reuses ASCII-compatible input when its bytes need no conversion.
For the supported encodings, each conversion spool uses at most three bytes per admitted input byte.
With scan limits enabled, concurrent conversion spools within one scan use at most three times its cumulative scan-byte limit.
Four concurrent Windows-1252 ledger scans peaked at 30.3 MiB for Barnacle and 79.6 MiB for stock.
The UTF-8 control and throughput measurements use the same attachment hash. [Benchmark results](benchmarks/object-xml-charset.md)

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
| LZW | Embedded files, page streams, resets, code-width changes, and chained ASCIIHex/LZW filters. [LZW comparisons](../tests/object_pdf_lzw.rs) |
| Page text | Parenthesized strings in page text arrays. The normalized bytes can match a whole-file hash. |
| Nested inputs | ZIP containing a PDF and a PDF with competing raw and child rules. |
| Policies and truncated input | Parser disabled, recursion and expanded-size alerts, a missing final trailer, and a truncated stream. |
| Packed indirect objects | Stored and Flate object streams, packed page dictionaries, content arrays, indirect lengths, and physical stream order. [Object-stream comparisons](../tests/object_pdf_streams.rs) |
| Additional PDF stages | Encryption, JavaScript actions and other stream filters require further comparisons. |

For physical objects, both daemons scan the referenced page dictionary for an explicit catalog opening destination.
An inline local GoTo exposes the catalog. An indirect local action exposes the referenced object at its physical position.
The child contains the bytes between `obj` and `endobj`, including surrounding line endings.
Barnacle indexes only the requested object IDs. The PDF parser admits at most 65,536 physical objects.
The tests cover all eight explicit destination modes, local named destinations, sparse IDs, backward references, and ZIP attachments.
Chained actions and unresolved or ambiguous destinations remain incomplete.
[Destination comparisons](../tests/object_pdf_destinations.rs) · [PDF 1.7 sections 12.3.2 and 12.6.4.2](https://opensource.adobe.com/dc-acrobat-sdk-docs/standards/pdfstandards/pdf/PDF32000_2008.pdf)

Stock uses early LZW code-width changes for both `/LZWDecode` and `/LZW`, even with `/EarlyChange 0`.
Both daemons matched the same 2,724 output bytes from a 7,500-byte late-change attachment. qpdf 12.4.2 decoded all 7,500 original bytes.
The sampled unreferenced stream and grayscale image did not produce a decoded match.
Both daemons scan a decoded page stream before its normalized text.
Stock skips normalized page text of five bytes or fewer before testing file count or byte limits.
For longer text, the normalized size can trigger a scan-size alert before the file-count alert. [Page-text tests](../tests/object_pdf.rs)
The physical and packed-page comparisons include text spanning multiple 8,192-byte normalized output blocks.
Barnacle counts the text before using scratch storage when the source could exceed the remaining scan budget.

At 262,143 expanded bytes, a 10,000-byte file limit suppresses the LZW output and records a size alert.
At 262,144 bytes, stock requests another 256 KiB block. If that request exceeds the limit, both scanners scan the LZW input.
For an ASCIIHex/LZW chain this input is the ASCIIHex output. Later filters are skipped.
Barnacle uses a fixed 4,096-entry dictionary and spools at most the remaining object budget.
It counts terminal output without writing it when file count or recursion excludes the child.
The decoded size can still trigger a size alert. [LZW comparisons](../tests/object_pdf_lzw.rs) · [Sustained scan measurements](benchmarks/object-pdf-lzw-sustained.md)

Both daemons scan PDF attachments in Adobe XDP forms. They visit the first matching PDF in XML order.
If the form type appears in the first 1,024 bytes, its attached PDF can win over the form hash.
A later type marker allows the outer hash to win first. Both paths give the PDF a `CL_TYPE_XDP` parent.
`ScanPDF no` disables attachment extraction. `ScanArchive no` leaves it enabled. [PDF form comparisons](../tests/object_pdf.rs)

Both daemons match the decoded object stream before later physical streams.
Clamd reads the packed directory for the compact spelling `/Type/ObjStm`.
A packed page can mark a later physical stream for text extraction.
Packed dictionaries selected for scanning follow all physical streams, including the cross-reference stream.
A packed catalog with a local opening destination exposes the earlier of the catalog and the referenced member.
An inline GoTo exposes the catalog. Barnacle resolves one opening catalog per carrier. It checks cancellation while reading borrowed dictionary bytes.
The paired tests include a 1 MiB catalog, a large backward page reference, and the exact remaining scan budget.
References across carriers remain incomplete.
With the spaced spelling `/Type /ObjStm`, only the carrier stream participates in this stage.
The independent control uses qpdf 12.4.2 and contains one page and a text attachment. [qpdf control](../tests/fixtures/pdf/qpdf-object-stream.pdf)

The tests cover Flate expansion across the reference's initial 256 KiB buffer.
An oversized decoded directory can still supply a page reference when it fits this buffer.
If the next allocation exceeds the limit, the reference can scan the encoded carrier instead.
Barnacle stores deferred arrays and selected dictionaries in one private spool, bounded by the initial remaining object budget.
If the spool fills, a later selected object can produce incomplete coverage. [Object-stream layout](https://qpdf.readthedocs.io/en/stable/object-streams.html)

### Apple disk images

Stock scans the raw DMG, then its XML catalog, then each partition listed in the catalog.
An outer hash wins over a catalog hash. A catalog hash wins over a partition hash.
Stock preserves catalog order across partitions. Within a partition, it sorts stripes by starting sector.
The reconstructed partition has no filename and has `CL_TYPE_DMG` as its parent. [DMG comparisons](../tests/object_dmg.rs)

Four read-only images from Apple `hdiutil` reproduce the same harmless partition.
They cover stored data (UDRO), ADC (UDCO), zlib (UDZO), and bzip2 (UDBZ).
Rust fixtures cover zero-filled stripes, sparse-only partitions, multiple maps, and a DMG inside ZIP.
A catalog or projected partition exceeding its size budget stops the pass, including when alerts are disabled.
Segmented images, resource-only catalogs, and additional codecs need separate comparisons. [Control images](../tests/fixtures/dmg)

### MBR, GPT, and Apple partition tables

All three parsers run with `ScanArchive yes`. Barnacle checks partition extents and scans them directly from the image.
Apple `hdiutil` authored three independent images using the MBRSPUD, GPTSPUD, and SPUD layouts.
Both daemons found the same harmless text file inside all three HFS+ volumes. [Authoring controls](../tests/fixtures/partition)

| Layout | Stock scan order and selection |
| --- | --- |
| MBR | Whole image, 512-byte boot sector, then primary entries in table order. Extended entries lead to logical partitions. |
| GPT with 512-byte sectors | Partitions precede the whole image. A valid backup supplies entries if the primary checksum fails. Differing valid tables are scanned in primary then backup order. |
| GPT with 4096-byte sectors | The protective MBR triggers GPT after the raw scan. A matching whole-image hash wins. |
| Apple partition map | Partitions precede the whole image. Stock counts the map itself, then scans the named data partitions in table order. |

`MaxPartitions 0` suppresses partition scans. Empty MBR and GPT slots count toward the limit.
The MBR boot sector also consumes a file slot. An oversized first APM partition stops traversal before a later smaller partition.
Stock finds the legacy APM with a map at byte 512. It misses the same payload with a native map at byte 2048.
ZIP ancestry, container signatures, recursion, scan size, and file-count limits have paired controls. [Partition comparisons](../tests/object_partition.rs)

Stock-only controls record the three intersection heuristic names and their order against a matching partition signature.
Barnacle's heuristic matcher still needs that coverage. Vendor-specific extended layouts and non-ASCII partition names need additional comparisons.

### HFS+ and HFSX partitions

Both daemons visit regular files in catalog leaf order inside a DMG partition.
They scan the decompressed file, data fork, and resource fork in that order.
The original basename applies to each fork. The HFS partition supplies the parent type.
A DMG hash wins over a file hash. A file hash wins over a partition hash.
Apple's `hdiutil` control verifies detection of a root file and a nested file. [Control image](../tests/fixtures/dmg/hdiutil-hfsplus.dmg.gz)

Rust fixtures cover HFSX, fragmented data, Unicode names, symbolic links, and zlib data in attributes and resource forks.
Stock skips an inline stored attachment until it has inflated another file in the same catalog.
The comparisons also cover `ScanArchive`, recursion depth, file count, and the exact cumulative byte limit. [HFS comparisons](../tests/object_hfs.rs)

Barnacle reads contiguous forks directly and streams fragmented forks and compressed resources.
It handles eight extents per fork and indexes up to 32,768 compression attributes per partition.
Forks requiring overflow extents and larger attribute indexes produce incomplete coverage.
When an allocation block exceeds the catalog node size, both daemons skip file extraction and match the partition.

### UDF optical images

Stock scans the raw disc before its UDF members. An outer whole-file hash takes precedence.
The reference visits file entries in physical descriptor order. The test rearranges entries while preserving their directory names and references.
Barnacle checks each recorded extent against the image length and scans it directly. [UDF comparisons](../tests/object_udf.rs)

The Rust fixtures cover single short, long, and extended allocation descriptors, cross-sector data, truncation, and nested ZIP input.
Stock supplies an empty original filename and sets the scan parent to `CL_TYPE_UDF` for these members.
An extent exceeding the remaining scan budget ends the UDF pass. A later smaller file receives no scan.

Three UDF 1.02 controls place an ordinary text file before and after the ledger under test.
They derive from an Apple-authored disc with its volume descriptors ordered for stock's reader.
The single-extent control stores the 5,830-byte ledger contiguously.
The fragmented control stores the same ledger in two short allocation descriptors at nonconsecutive offsets.
The inline control stores 61 bytes inside the file entry. Debian 7-Zip 25.01 extracted all nine files byte-for-byte.

Stock and Barnacle stop the UDF pass at the fragmented or inline entry. The later ordinary file receives no scan.
Hashes for the joined ledger, each individual extent, and the inline payload all miss on their respective controls.
The earlier file still matches with parent `CL_TYPE_UDF`. A competing whole-disc hash wins in every layout.
With `MaxFiles 2`, the disc and its first member consume both slots. Only the single-extent control raises `MaxFiles`.
With exactly 40 bytes left after the disc, only the single-extent control raises `MaxScanSize`.
All three raise `MaxRecursion` at depth one when limit alerts are enabled.
Stock reports `OK` on a member-hash miss. Barnacle reports incomplete detection coverage. [Allocation tests](../tests/object_udf.rs)

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
| Coverage gaps | VBA, XLM, embedded Office images, protected HWP documents, encryption, and larger version 4 directories require further comparisons. |

Rust tests compare competing raw streams and embedded packages in macro-free Word, Excel, and PowerPoint documents.
They cover flat directories, nested storages, shared stream names, and the underlying filesystem’s scan order.
Barnacle creates empty private directory entries when it needs that order. It reads each payload from the compound file.

The Excel control contains a generated PNG in a macro-free workbook saved by Spreadsheet::WriteExcel 2.40.
Benchmarks compare the embedded PNG hash with one and four clients. [Excel picture measurements](benchmarks/object-pdf-excel.md)
Stock scans its BIFF report, the original PNG bytes, and then the outer file. It skips the raw Workbook stream.
The short report contains a 117-byte preamble. Generic body and whole-file signatures match it before the picture.
A report miss leaves the file count and scan-byte budget available for the picture.
Stock metadata describes an unnamed PNG under `CL_TYPE_MSXL`. Its parent signature matches `CL_TYPE_MSOLE2`. [Excel tests](../tests/object_ole_xls.rs)

Barnacle joins drawing-group and continuation records in a private spool. The controls cover PNG, JPEG, TIFF, and a multi-record DIB.
A bare JPEG followed by another store entry includes its next 17 bytes in the tested one-identifier layout.
The first image exceeding the byte budget stops picture traversal. Disabling `ScanImage` preserves picture hashes. Disabling `ScanOLE2` skips them.
The authored formula control contains `2+3` and `SQRT(A1*2)`. Both daemons match its 117-byte report before the PNG.
Barnacle bounds the report text for common arithmetic, references, ranges, and worksheet functions without evaluating the cells.
Stock exposes another 4,096 report bytes only after formatting one more byte. Barnacle matches the same complete blocks for ordinary worksheet records.
A 350-term sum produced a 4,213-byte report. An independently authored 120-row numeric ledger ending in SUM produced a 16,501-byte report.
Both report hashes beat the embedded picture. A matching generic body signature beat the competing report hash.
Barnacle counts output first when the report might exceed the remaining budget. A rejected report can still leave a smaller picture eligible.
Unverified text inside a visible block returns incomplete coverage. This includes unsupported records and formula suffixes inside earlier blocks. [BIFF formula example](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/bccb00ac-67a1-490a-9f0b-5ce59978eb9a)
Delayed picture data, metafiles, multiple Workbook streams, and mixed Office extraction passes remain unverified. [OfficeArt picture records](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/c67b883b-8136-4e91-a1a3-2981d16e934f)

Both daemons scan top-level PowerPoint `ExOleObjStg` zlib payloads before the root presentation stream and its file hash.
A root native Package still wins. A presentation inside a storage receives its attachment pass after the root raw-stream pass.
Stock records the original attachment name as `ppt0000000c.doc` when the compressed data starts at byte 12.
An uncompressed external object produced no child match. [PowerPoint controls](../tests/object_ole_ppt.rs) · [Microsoft record definition](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ppt/305e541f-2c91-49c5-a742-4955330fd2b9)

Temporary-directory order selects among competing attachments. On the pinned Linux filesystem, reversing two records reversed the winning signature.
Stock stops the attachment pass when an expanded object exceeds a size limit. The tested 8,192-byte prefix never matched.
Barnacle keeps at most 4,096 record offsets per presentation stream, including with `MaxFiles 0`.
If the stream needs traversal, the next record returns incomplete coverage. The tests verify scratch cleanup after success, overflow, and cancellation.
Stock checks each attachment's byte limit before its file count and recursion depth.
A smaller blocked attachment can therefore report its limit before a later oversized attachment.
When both depth and file count exclude an attachment, stock reports the file count.
Barnacle reads streams with the MIT-licensed `cfb` crate. [Dependency license](https://github.com/mdsteele/rust-cfb/blob/master/LICENSE)

## Reference order and limits

The Rust runner generates two benign local signature files. It sends every sample through `INSTREAM` over a private Unix socket.
It enables extended detection logs, disables caching, and repeats each configuration with `AlertExceedsMax` off and on.
The 250 rows cover 24 profiles under both alert settings.
Both the protocol and log observations identify the signature. [Rust runner](../examples/object_reference.rs)

Barnacle matched 165 protocol and log rows exactly, including every stock detection and limit alert.
The remaining 85 stock `OK` replies produced Barnacle's explicit incomplete-coverage error.
The daemon returns this error for both unsupported objects and completed traversals with no matcher hit.
These 85 replies therefore do not measure how many object handlers remain unfinished.

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
