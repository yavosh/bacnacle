# Office package scan performance

Both daemons scanned the same three Office packages and detected the same embedded PNG in all 23,040 requests.
On the XLSX with four clients, Barnacle processed 4,386 scans/s and stock clamd processed 1,461 scans/s.
Each batch used one pinned Linux ARM64 CPU, 2 GiB of RAM, no swap, and a fresh daemon.
The database contained one MD5 rule. [Fixture provenance](../../tests/fixtures/ooxml/README.md)

Each value is the median of three batches. Each client submitted 256 requests with the scan cache disabled.
The Rust driver recorded each request's latency and checked every reply. Cgroup peak memory includes the driver and charged file-backed pages.
The raw observations include the daemon's separate peak RSS. [Raw measurements](object-office-packages.csv)

| Format | Clients | Barnacle scans/s | Barnacle p95 ms | Barnacle peak MiB | Stock scans/s | Stock p95 ms | Stock peak MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DOCX | 1 | 3033 | 0.42 | 4.00 | 1200 | 0.89 | 5.14 |
| DOCX | 4 | 3172 | 2.35 | 3.84 | 1212 | 7.22 | 5.80 |
| PPTX | 1 | 6843 | 0.17 | 4.07 | 2025 | 0.53 | 4.83 |
| PPTX | 4 | 5269 | 1.61 | 3.82 | 2033 | 4.13 | 6.03 |
| XLSX | 1 | 4202 | 0.26 | 4.18 | 950 | 1.76 | 4.91 |
| XLSX | 4 | 4386 | 1.64 | 3.40 | 1461 | 6.01 | 5.82 |

## Reproduction

Build the release daemon and `archive_workspace` example. For each package, create a directory containing `input` and `db/picture.hdb`.
Copy the corresponding package to `input`. Use this rule in all three databases.

```text
b8bde3e503a52c3239ab107b1ff268b6:4556:Workspace.Reference
```

Use the documented container limits and mounts. Run each daemon separately with one and four clients.
Alternate daemon order across three rounds. [Container command](object-pdf-excel.md#reproduction)

```sh
/probe run "/fixtures/$format/input" "$clients" "$daemon" 256
```

Stock used Debian clamd `1.4.3+dfsg-1`. The Barnacle executable had SHA-256 `469e916eaa7c57107b03dbd2c282d60a5ef4e6e442ab1b6ebb97381fa82dd64a`.
