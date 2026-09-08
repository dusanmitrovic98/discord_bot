use crate::{AegisError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

pub struct CryptoEngine;

impl CryptoEngine {
    /// Compute SHA-256 hash of any arbitrary byte buffer.
    pub fn sha256(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    /// Verify an Ed25519 signature against an expected public key.
    pub fn verify_signature(
        public_key_bytes: &[u8; 32],
        data: &[u8],
        signature_bytes: &[u8; 64],
    ) -> Result<()> {
        let verifying_key = VerifyingKey::from_bytes(public_key_bytes)
            .map_err(|e| AegisError::CryptoError(format!("Invalid public key: {}", e)))?;

        let signature = Signature::from_bytes(signature_bytes);

        verifying_key
            .verify(data, &signature)
            .map_err(|e| AegisError::CryptoError(format!("Signature mismatch: {}", e)))
    }

    /// Sign data (used by Titan-CLI tool).
    pub fn sign_data(signing_key_bytes: &[u8; 32], data: &[u8]) -> [u8; 64] {
        let signing_key = SigningKey::from_bytes(signing_key_bytes);
        signing_key.sign(data).to_bytes()
    }

    /// Fast 64-bit perceptual difference hash (dHash) for images.
    /// Resizes conceptually to 9x8 grayscale, asserts horizontal gradient.
    pub fn compute_dhash(image_bytes: &[u8]) -> Result<u64> {
        // Lightweight image decoder
        let img = image::load_from_memory(image_bytes)
            .map_err(|e| AegisError::CryptoError(format!("Image decode failed: {}", e)))?;

        let gray = img.thumbnail_exact(9, 8).to_luma8();
        let mut hash: u64 = 0;

        for y in 0..8 {
            for x in 0..8 {
                let left = gray.get_pixel(x, y)[0];
                let right = gray.get_pixel(x + 1, y)[0];
                if left > right {
                    hash |= 1 << (y * 8 + x);
                }
            }
        }
        Ok(hash)
    }

    /// Calculate Hamming distance between two perceptual hashes.
    pub fn hamming_distance(hash1: u64, hash2: u64) -> u32 {
        (hash1 ^ hash2).count_ones()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_sha256_deterministic() {
        let payload = b"mainframeforge-sentinel";
        let h1 = CryptoEngine::sha256(payload);
        let h2 = CryptoEngine::sha256(payload);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_ed25519_sign_and_verify_valid() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let public_key = signing_key.verifying_key().to_bytes();
        let payload = b"bot_core_v1.0.0_binary_blob";

        let signature = CryptoEngine::sign_data(&signing_key.to_bytes(), payload);
        let result = CryptoEngine::verify_signature(&public_key, payload, &signature);
        assert!(result.is_ok(), "Signature verification must succeed");
    }

    #[test]
    fn test_ed25519_tampered_payload_fails() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let public_key = signing_key.verifying_key().to_bytes();
        let payload = b"legitimate_bot_core";
        let tampered = b"malicious_tampered_core";

        let signature = CryptoEngine::sign_data(&signing_key.to_bytes(), payload);
        let result = CryptoEngine::verify_signature(&public_key, tampered, &signature);
        assert!(result.is_err(), "Tampered signature verification must fail");
    }
}
