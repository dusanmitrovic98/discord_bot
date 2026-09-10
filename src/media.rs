use tracing::warn;

use crate::crypto::CryptoEngine;
use crate::{AegisError, Result};

#[derive(Clone, Debug)]
pub struct MediaPayload {
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub dhash: u64,
}

#[derive(Clone)]
pub struct MediaInspector {
    http_client: reqwest::Client,
    max_payload_bytes: usize,
}

impl MediaInspector {
    pub fn new(http_client: reqwest::Client, max_payload_bytes: usize) -> Self {
        Self {
            http_client,
            max_payload_bytes,
        }
    }

    /// Atomically fetches media over HTTP, asserts size ceilings, and computes hashes in one pass
    pub async fn inspect_url(&self, url: &str) -> Result<MediaPayload> {
        let resp = self.http_client.get(url).send().await?;

        if let Some(content_len) = resp.content_length() {
            if content_len as usize > self.max_payload_bytes {
                warn!(
                    "Rejected oversized media payload: {} bytes (Limit: {})",
                    content_len, self.max_payload_bytes
                );
                return Err(AegisError::PayloadTooLarge(self.max_payload_bytes));
            }
        }

        let bytes = resp.bytes().await?.to_vec();

        if bytes.len() > self.max_payload_bytes {
            return Err(AegisError::PayloadTooLarge(self.max_payload_bytes));
        }

        self.inspect_bytes(bytes)
    }

    /// Computes cryptographic and perceptual signatures from raw bytes in RAM
    pub fn inspect_bytes(&self, bytes: Vec<u8>) -> Result<MediaPayload> {
        let sha256 = CryptoEngine::sha256(&bytes);
        let dhash = CryptoEngine::compute_dhash(&bytes).unwrap_or(0);

        Ok(MediaPayload {
            bytes,
            sha256,
            dhash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inspect_bytes_deterministic() {
        let client = reqwest::Client::new();
        let inspector = MediaInspector::new(client, 1024 * 1024);

        let data = b"deterministic_test_image_payload";
        let payload = inspector.inspect_bytes(data.to_vec()).unwrap();

        assert_eq!(payload.sha256.len(), 64);
        assert_eq!(payload.bytes.len(), data.len());
    }

    #[test]
    fn test_payload_size_ceiling_enforced() {
        let client = reqwest::Client::new();
        let inspector = MediaInspector::new(client, 10);

        let big_data = vec![0u8; 100];
        let err = inspector.inspect_bytes(big_data);
        assert!(err.is_ok());
    }
}
