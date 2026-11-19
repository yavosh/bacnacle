# XAR inventory fixture

Apple's `/usr/bin/xar` (1.8dev) created `inventory.xar` from the included passive inventory catalog and receipt.
The archive contains a named subdocument, a gzip-compressed receipt, and SHA-1 checksums.

To build an equivalent archive on macOS, run this command in the fixture directory.

```sh
xar --prop-include=name --prop-include=type --prop-include=data \
  -n stockroom -s catalog.xml -cf inventory.xar receipt.txt
```

File timestamps and the ordering of declarations in the archived XML can differ between runs.
The Rust comparison checks the exact bytes stored in the checked-in archive and each competing scan result.
