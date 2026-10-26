//! KDBX 4.0 complete read pipeline
//!
//! Pipeline: signature → outer header → header HMAC → HMAC block stream
//!           → decrypt → inner header → decompress → inner stream → XML → Database

use std::io::Read;

use byteorder::{LittleEndian, ReadBytesExt};

use crate::crypto::compression::CompressionAlgorithm;
use crate::crypto::inner_stream::create_inner_stream;
use crate::kdbx::file::header::{
    header_field_4, inner_header_field_4, CrsAlgorithm, KdbxHeader4, KdbxInnerHeader4,
};
use crate::kdbx::file::reader::DatabaseReader;
use crate::kdbx::kdf::create_kdf;
use crate::kdbx::stream::hmac_block_stream::{compute_header_hmac, read_hmac_block_stream};
use crate::kdbx::xml::KdbxXmlReader;
use crate::model::db::composite_key::CompositeKey;
use crate::model::db::database::{Database, DatabaseVersion};
use crate::model::exception::{DatabaseError, DatabaseResult};

/// Read a KDBX 4.0 database from a reader.
pub fn read_kdbx4<R: Read>(
    reader: &mut R,
    composite_key: &CompositeKey,
) -> DatabaseResult<Database> {
    // 1. Detect version and consume signature (12 bytes)
    let mut version_bytes = [0u8; 12];
    reader.read_exact(&mut version_bytes)?;
    let version = DatabaseReader::detect_version(&mut std::io::Cursor::new(version_bytes))?;
    if version != DatabaseVersion::KDBX4 {
        return Err(DatabaseError::InvalidVersion(format!(
            "Expected KDBX4, got {version:?}"
        )));
    }

    // 2. Read outer header (capturing bytes for HMAC verification)
    // Note: Writer computes HMAC over signature(12) + outer_header.
    // detect_version consumed 12 bytes of signature, so we prepend them.
    let mut header_buf = version_bytes.to_vec();
    let header = {
        let mut tee = TeeReader::new(reader, &mut header_buf);
        let version_number = u32::from_le_bytes([
            version_bytes[8],
            version_bytes[9],
            version_bytes[10],
            version_bytes[11],
        ]);
        read_kdbx4_outer_header_from(&mut tee, version_number)?
    };

    // 3. Derive master key
    let (master_key, hmac_base_key) = derive_master_key(composite_key, &header)?;

    // 4. Verify the header hash, then the keyed HMAC.
    let mut stored_header_hash = [0u8; 32];
    reader.read_exact(&mut stored_header_hash)?;
    let expected_header_hash = crate::crypto::HashEngine::sha256(&header_buf);
    if stored_header_hash != expected_header_hash {
        return Err(DatabaseError::DecryptionError(
            "Header SHA-256 mismatch".into(),
        ));
    }

    let mut stored_hmac = [0u8; 32];
    reader.read_exact(&mut stored_hmac)?;
    let expected_hmac = compute_header_hmac(&hmac_base_key, &header_buf)?;
    if stored_hmac != expected_hmac {
        return Err(DatabaseError::DecryptionError(
            "Header HMAC mismatch".into(),
        ));
    }

    // 5. Read HMAC block stream → encrypted data
    let encrypted = read_hmac_block_stream(reader, &hmac_base_key).map_err(|error| {
        DatabaseError::InvalidFormat(format!("Could not read authenticated payload: {error}"))
    })?;

    // 6. Decrypt
    let cipher = crate::crypto::cipher_engine::create_cipher_engine(header.encryption_algorithm);
    let decrypted = cipher
        .decrypt(&master_key, &header.encryption_iv, &encrypted)
        .map_err(|e| {
            DatabaseError::DecryptionError(format!(
                "Could not decrypt {} payload: {e}",
                header.encryption_algorithm
            ))
        })?;
    // 7. Decompress the payload, which contains both the inner header and XML.
    let payload = match header.compression {
        CompressionAlgorithm::Gzip => {
            crate::crypto::compression::decompress(&decrypted).map_err(|error| {
                DatabaseError::InvalidFormat(format!("Could not decompress KDBX4 payload: {error}"))
            })?
        }
        CompressionAlgorithm::None => decrypted,
    };

    // 8. Parse inner header
    let mut cursor = std::io::Cursor::new(&payload);
    let inner = read_kdbx4_inner_header(&mut cursor).map_err(|error| {
        DatabaseError::InvalidFormat(format!(
            "Could not parse KDBX4 inner header ({} payload bytes): {error}",
            payload.len()
        ))
    })?;

    // 9. Read XML after the inner header.
    let xml_bytes = &payload[cursor.position() as usize..];

    // 10. Parse XML with inner stream cipher
    let mut inner_stream =
        create_inner_stream(inner.inner_random_stream, &inner.inner_random_stream_key)?;
    let xml_str =
        std::str::from_utf8(xml_bytes).map_err(|e| DatabaseError::InvalidFormat(e.to_string()))?;
    let db = KdbxXmlReader::read(xml_str, inner_stream.as_mut())?;

    Ok(db)
}

/// Derive the master key from composite key and header.
fn derive_master_key(
    composite_key: &CompositeKey,
    header: &KdbxHeader4,
) -> DatabaseResult<(Vec<u8>, Vec<u8>)> {
    let raw_key = composite_key.build_raw_key();
    if raw_key.is_empty() {
        return Err(DatabaseError::InvalidKey);
    }

    let kdf_uuid = header
        .kdf_parameters
        .as_ref()
        .map(|p| p.kdf_uuid)
        .ok_or_else(|| DatabaseError::InvalidFormat("No KDF parameters".into()))?;

    let kdf =
        create_kdf(&kdf_uuid).ok_or_else(|| DatabaseError::InvalidFormat("Unknown KDF".into()))?;
    let params = header
        .kdf_parameters
        .as_ref()
        .ok_or_else(|| DatabaseError::InvalidFormat("No KDF parameters".into()))?;

    let transformed = kdf.transform(&raw_key, params)?;

    let mut combined = Vec::with_capacity(header.master_seed.len() + transformed.len());
    combined.extend_from_slice(&header.master_seed);
    combined.extend_from_slice(&transformed);
    let encryption_key = crate::crypto::HashEngine::sha256(&combined).to_vec();
    combined.push(0x01);
    let hmac_base_key = crate::crypto::HashEngine::sha512(&combined).to_vec();
    Ok((encryption_key, hmac_base_key))
}

/// Read KDBX 4.0 outer header from reader, TeeReader captures all bytes.
fn read_kdbx4_outer_header_from<R: Read>(
    reader: &mut R,
    version: u32,
) -> DatabaseResult<KdbxHeader4> {
    let mut header = KdbxHeader4 {
        version,
        encryption_algorithm: crate::crypto::encryption_algorithm::EncryptionAlgorithm::AesRijndael,
        compression: CompressionAlgorithm::Gzip,
        master_seed: Vec::new(),
        encryption_iv: Vec::new(),
        kdf_parameters: None,
        public_custom_data: Vec::new(),
    };

    loop {
        let field_id = reader.read_u8()?;
        let field_size = reader.read_u32::<LittleEndian>()? as usize;

        if field_size > 0 {
            let mut data = vec![0u8; field_size];
            reader.read_exact(&mut data)?;

            match field_id {
                header_field_4::END_OF_HEADER => break,
                header_field_4::CIPHER_ID => {
                    let uuid = uuid::Uuid::from_slice(&data)
                        .map_err(|e| DatabaseError::InvalidFormat(e.to_string()))?;
                    header.encryption_algorithm =
                        crate::crypto::encryption_algorithm::EncryptionAlgorithm::from_uuid(&uuid)
                            .unwrap_or(
                            crate::crypto::encryption_algorithm::EncryptionAlgorithm::AesRijndael,
                        );
                }
                header_field_4::COMPRESSION_FLAGS => {
                    if data.len() >= 4 {
                        let flags = u32::from_le_bytes(data[..4].try_into().map_err(|_| {
                            DatabaseError::InvalidFormat("Invalid COMPRESSION_FLAGS".into())
                        })?);
                        header.compression = CompressionAlgorithm::from_id(flags)
                            .unwrap_or(CompressionAlgorithm::Gzip);
                    }
                }
                header_field_4::MASTER_SEED => header.master_seed = data,
                header_field_4::ENCRYPTION_IV => header.encryption_iv = data,
                header_field_4::KDF_PARAMETERS => {
                    header.kdf_parameters =
                        crate::kdbx::kdf::kdf_parameters::KdfParameters::deserialize(&data);
                }
                header_field_4::PUBLIC_CUSTOM_DATA => header.public_custom_data = data,
                _ => {}
            }
        } else if field_id == header_field_4::END_OF_HEADER {
            break;
        }
    }

    Ok(header)
}

/// Read KDBX 4.0 inner header.
fn read_kdbx4_inner_header<R: Read>(reader: &mut R) -> DatabaseResult<KdbxInnerHeader4> {
    let mut inner = KdbxInnerHeader4 {
        inner_random_stream: CrsAlgorithm::ChaCha20,
        inner_random_stream_key: Vec::new(),
        binaries: Vec::new(),
    };

    let mut field_offset = 0usize;
    loop {
        let field_id = reader.read_u8().map_err(|error| {
            DatabaseError::InvalidFormat(format!(
                "Could not read KDBX4 inner-header field ID at offset {field_offset}: {error}"
            ))
        })?;
        let field_size = reader
            .read_u32::<LittleEndian>()
            .map_err(|error| {
                DatabaseError::InvalidFormat(format!(
                    "Could not read size of KDBX4 inner-header field {field_id} at offset {field_offset}: {error}"
                ))
            })? as usize;
        field_offset = field_offset.saturating_add(5).saturating_add(field_size);

        if field_size > 0 {
            let mut data = vec![0u8; field_size];
            reader.read_exact(&mut data).map_err(|error| {
                DatabaseError::InvalidFormat(format!(
                    "Could not read {field_size} bytes of KDBX4 inner-header field {field_id}: {error}"
                ))
            })?;

            match field_id {
                inner_header_field_4::END_OF_HEADER => break,
                inner_header_field_4::INNER_RANDOM_STREAM_ID => {
                    if data.len() >= 4 {
                        let id = u32::from_le_bytes(data[..4].try_into().map_err(|_| {
                            DatabaseError::InvalidFormat("Invalid INNER_RANDOM_STREAM_ID".into())
                        })?);
                        inner.inner_random_stream =
                            CrsAlgorithm::from_id(id).unwrap_or(CrsAlgorithm::ChaCha20);
                    }
                }
                inner_header_field_4::INNER_RANDOM_STREAM_KEY => {
                    inner.inner_random_stream_key = data;
                }
                inner_header_field_4::BINARY if data.len() > 1 => {
                    inner.binaries.push(crate::kdbx::file::header::KdbxBinary {
                        flags: data[0],
                        data: data[1..].to_vec(),
                    });
                }
                _ => {}
            }
        } else if field_id == inner_header_field_4::END_OF_HEADER {
            break;
        }
    }

    Ok(inner)
}

/// TeeReader copies all read bytes to a sink buffer.
/// Borrows the inner reader instead of owning it.
struct TeeReader<'a, R> {
    inner: &'a mut R,
    sink: &'a mut Vec<u8>,
}

impl<'a, R: Read> TeeReader<'a, R> {
    fn new(inner: &'a mut R, sink: &'a mut Vec<u8>) -> Self {
        Self { inner, sink }
    }
}

impl<'a, R: Read> Read for TeeReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.sink.extend_from_slice(&buf[..n]);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::db::composite_key::CompositeKey;

    #[test]
    fn test_invalid_version_rejected() {
        // Write KDBX 3.1 signature
        let mut data = Vec::new();
        data.extend_from_slice(&crate::kdbx::file::header::KDBX_SIGNATURE_1.to_le_bytes());
        data.extend_from_slice(&crate::kdbx::file::header::KDBX_SIGNATURE_2.to_le_bytes());
        data.extend_from_slice(&0x00030001u32.to_le_bytes()); // v3.1

        let mut cursor = std::io::Cursor::new(data);
        let key = CompositeKey::new().with_password(b"test");
        assert!(read_kdbx4(&mut cursor, &key).is_err());
    }
}
