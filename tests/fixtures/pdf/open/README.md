# Openable PDF controls

qpdf 12.4.2 rewrote the repository's harmless `qpdf-object-stream.pdf` with classic xref tables.
The plain file contains the original 36-byte accounting statement.
The R4 fixture uses AES-128. The R5 and R6 fixtures use AES-256.
These three documents open with the default empty user password and permit extraction.
The two-attachment R6 document adds a 45-byte dispatch slip. A separate locked control requires a credential.
Each artifact stays fixed because qpdf generates new salts and encryption values when writing a file.
The stored control keeps both streams uncompressed. The restricted control permits opening and disallows extraction.
The CSV manifest uses qpdf’s attachment writer. Its Flate filter follows the nested attachment parameters.
The MIME fixture uses qpdf’s text/plain attachment option and an ordinary escaped PDF name.
The larger fixture contains a synthetic shipment table. The Rust test reproduces all 13,000 rows. qpdf compressed and encrypted the attachment.

The R2, R3, and R4 RC4 controls use the same 36-byte statement. qpdf created them from `ordinary.pdf` with classic cross-reference tables.
The R4 and R6 cleartext metadata controls also contain that statement. All five documents open with an empty user credential.

```sh
qpdf --allow-weak-crypto --object-streams=disable --encrypt '' '' 40 -- ordinary.pdf r2-rc4.pdf
qpdf --allow-weak-crypto --object-streams=disable --encrypt '' '' 128 --use-aes=n -- ordinary.pdf r3-rc4.pdf
qpdf --allow-weak-crypto --object-streams=disable --encrypt '' '' 128 --use-aes=n --force-V4 -- ordinary.pdf r4-rc4.pdf
qpdf --object-streams=disable --encrypt '' '' 128 --use-aes=y --cleartext-metadata -- ordinary.pdf r4-clear-metadata.pdf
qpdf --object-streams=disable --encrypt '' '' 256 --allow-insecure --cleartext-metadata -- ordinary.pdf r6-clear-metadata.pdf
```

`r6-flate-hex.pdf` and `r6-identity.pdf` are Rust-authored controls using the qpdf R6 security metadata.
The first uses Flate followed by ASCIIHex and yields the 36-byte note.
The second uses direct `Crypt` with `Identity`. Stock passes the same note with its trailing LF.
`r6-explicit-eff.pdf` uses `/EFF /StdCF` for its receipt. Stock, qpdf, and Poppler recover the same 52 bytes.
`r6-stored-mime.pdf` uses the same explicit default with an uncompressed receipt. Stock scans its 81 physical stream bytes.
`r6-explicit-name.pdf` selects a named crypt filter on its receipt and page. Stock scans 96 bytes of the stored page stream.
