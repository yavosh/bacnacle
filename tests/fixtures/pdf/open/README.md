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
