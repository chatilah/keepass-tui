# Local patches

This is the MIT OR MulanPSL-2.0 licensed `keepass-rs` 0.2.0 crate, vendored
because the published release's KDBX key derivation and KDBX4 authentication
did not interoperate with standard KeePass databases.

The local changes correct composite-key hashing, KDBX4 header hash/HMAC and
block-stream derivation/layout, and preserve the file's actual version bytes
when validating the header. XML output uses standard padded Base64 UUIDs and
valid timestamps for unset dates; the reader also accepts UUIDs written by
older versions without padding. The app's tests cross-check KDBX4 reading and
writing, including protected fields, and XML keyfile authentication with the
independent `keepass` crate. ChaCha20 inner-stream derivation hashes the
complete key material, without assuming that it is exactly 32 bytes.
