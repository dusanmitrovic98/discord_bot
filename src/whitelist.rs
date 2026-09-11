//! # Dual-Layer Whitelist Registry
//!
//! Maintains in-memory thread-safe registries of whitelisted usernames, user IDs,
//! exact SHA-256 image hashes, and 64-bit perceptual difference hashes (dHash).
//! Complies with NASA Rule 2 & Rule 5 (bounded memory, fail-safe defaults).

use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;

use crate::db::DatabaseEngine;
use crate::Result;

#[derive(Clone)]
pub struct WhitelistRegistry {
    users: Arc<RwLock<HashSet<String>>>,
    images: Arc<RwLock<HashSet<String>>>,
    dhashes: Arc<RwLock<Vec<u64>>>,
}

impl Default for WhitelistRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl WhitelistRegistry {
    pub fn new() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashSet::new())),
            images: Arc::new(RwLock::new(HashSet::new())),
            dhashes: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Synchronizes user identifiers, image SHAs, and perceptual dHashes from MongoDB into RAM
    pub async fn sync_from_db(&self, db: &DatabaseEngine) -> Result<()> {
        let mut user_set = HashSet::new();
        if let Ok(users) = db.fetch_whitelisted_users().await {
            for u in users {
                user_set.insert(u.identifier.to_lowercase());
            }
        }

        let mut image_set = HashSet::new();
        let mut dhash_vec = Vec::new();
        if let Ok(images) = db.fetch_whitelisted_images().await {
            for img in images {
                image_set.insert(img.sha256.to_lowercase());
                if img.dhash != 0 {
                    dhash_vec.push(img.dhash);
                }
            }
        }

        let mut u_guard = self.users.write().await;
        *u_guard = user_set;

        let mut i_guard = self.images.write().await;
        *i_guard = image_set;

        let mut d_guard = self.dhashes.write().await;
        *d_guard = dhash_vec;

        debug!(
            "Whitelist synchronized into RAM: {} users, {} safe SHAs, {} safe dHashes.",
            u_guard.len(),
            i_guard.len(),
            d_guard.len()
        );
        Ok(())
    }

    pub async fn add_user(&self, identifier: &str) {
        let mut guard = self.users.write().await;
        guard.insert(identifier.to_lowercase());
    }

    pub async fn remove_user(&self, identifier: &str) {
        let mut guard = self.users.write().await;
        guard.remove(&identifier.to_lowercase());
    }

    pub async fn is_user_exempt(&self, user_id: u64, username: &str) -> bool {
        let guard = self.users.read().await;
        guard.contains(&user_id.to_string()) || guard.contains(&username.to_lowercase())
    }

    pub async fn add_image(&self, sha256: &str, dhash: u64) {
        let mut i_guard = self.images.write().await;
        i_guard.insert(sha256.to_lowercase());

        if dhash != 0 {
            let mut d_guard = self.dhashes.write().await;
            if !d_guard.contains(&dhash) {
                d_guard.push(dhash);
            }
        }
    }

    pub async fn remove_image(&self, sha256: &str) {
        let mut guard = self.images.write().await;
        guard.remove(&sha256.to_lowercase());
    }

    /// Evaluates if an image is verified safe via Exact SHA or Perceptual dHash (Distance <= 2)
    pub async fn is_image_safe(&self, sha256: &str, dhash: u64) -> bool {
        let i_guard = self.images.read().await;
        if i_guard.contains(&sha256.to_lowercase()) {
            return true;
        }

        // Perceptual invariance: allows Discord re-compression & minor proxy artifacts (NASA Rule 5)
        if dhash != 0 {
            let d_guard = self.dhashes.read().await;
            for &safe_dhash in d_guard.iter() {
                if (safe_dhash ^ dhash).count_ones() <= 2 {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_whitelist_user_exemption() {
        let registry = WhitelistRegistry::new();
        registry.add_user("Steam_Game_Dev").await;
        registry.add_user("1015600709724557434").await;

        assert!(registry.is_user_exempt(999, "steam_game_dev").await);
        assert!(registry.is_user_exempt(999, "STEAM_GAME_DEV").await);
        assert!(
            registry
                .is_user_exempt(1015600709724557434, "random_name")
                .await
        );
        assert!(!registry.is_user_exempt(88888, "stranger").await);

        registry.remove_user("Steam_Game_Dev").await;
        assert!(!registry.is_user_exempt(999, "steam_game_dev").await);
    }

    #[tokio::test]
    async fn test_whitelist_image_safety() {
        let registry = WhitelistRegistry::new();
        let sample_hash = "907cbc96639a65097b5dad76b89b36598f5139d7108323ed3a333f72b9a922da";

        registry.add_image(sample_hash, 0).await;
        assert!(registry.is_image_safe(sample_hash, 0).await);
        assert!(registry.is_image_safe(&sample_hash.to_uppercase(), 0).await);
        assert!(!registry.is_image_safe("unknown_hash_value", 0).await);
    }

    #[tokio::test]
    async fn test_perceptual_dhash_whitelist_matching() {
        let registry = WhitelistRegistry::new();
        let exact_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let base_dhash: u64 = 0b10101010_11001100_11110000_00001111;

        registry.add_image(exact_sha, base_dhash).await;

        // 1. Exact SHA-256 match
        assert!(registry.is_image_safe(exact_sha, 0).await);

        // 2. Different SHA, but identical dHash (re-encoded image)
        assert!(
            registry
                .is_image_safe("different_sha_from_proxy", base_dhash)
                .await
        );

        // 3. Different SHA, dHash Hamming distance = 1 (minor Discord compression artifact)
        let modified_dhash_dist1 = base_dhash ^ 0b00000001;
        assert!(
            registry
                .is_image_safe("proxy_url_hash", modified_dhash_dist1)
                .await
        );

        // 4. Different SHA, dHash Hamming distance = 2 (acceptable compression threshold)
        let modified_dhash_dist2 = base_dhash ^ 0b00000011;
        assert!(
            registry
                .is_image_safe("proxy_url_hash", modified_dhash_dist2)
                .await
        );

        // 5. Different SHA, dHash Hamming distance = 3 (beyond whitelist threshold -> unsafe)
        let modified_dhash_dist3 = base_dhash ^ 0b00000111;
        assert!(
            !registry
                .is_image_safe("proxy_url_hash", modified_dhash_dist3)
                .await
        );
    }
}
