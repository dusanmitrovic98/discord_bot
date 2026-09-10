use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use crate::db::DatabaseEngine;
use crate::Result;

#[derive(Clone)]
pub struct WhitelistRegistry {
    users: Arc<RwLock<HashSet<String>>>,
    images: Arc<RwLock<HashSet<String>>>,
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
        }
    }

    /// Synchronizes both whitelist collections from MongoDB Atlas into RAM
    pub async fn sync_from_db(&self, db: &DatabaseEngine) -> Result<()> {
        let mut user_set = HashSet::new();
        if let Ok(users) = db.fetch_whitelisted_users().await {
            for u in users {
                user_set.insert(u.identifier.to_lowercase());
            }
        }

        let mut image_set = HashSet::new();
        if let Ok(images) = db.fetch_whitelisted_images().await {
            for img in images {
                image_set.insert(img.sha256.to_lowercase());
            }
        }

        let mut u_guard = self.users.write().await;
        *u_guard = user_set;

        let mut i_guard = self.images.write().await;
        *i_guard = image_set;

        info!(
            "Whitelist synchronized into RAM: {} users, {} verified safe image hashes.",
            u_guard.len(),
            i_guard.len()
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

    /// Evaluates if an author (by User ID or username) is exempt from Tier 2 soft rules
    pub async fn is_user_exempt(&self, user_id: u64, username: &str) -> bool {
        let guard = self.users.read().await;
        guard.contains(&user_id.to_string()) || guard.contains(&username.to_lowercase())
    }

    pub async fn add_image(&self, sha256: &str) {
        let mut guard = self.images.write().await;
        guard.insert(sha256.to_lowercase());
    }

    pub async fn remove_image(&self, sha256: &str) {
        let mut guard = self.images.write().await;
        guard.remove(&sha256.to_lowercase());
    }

    /// Evaluates if an image SHA-256 is explicitly verified safe (skips AI inference)
    pub async fn is_image_safe(&self, sha256: &str) -> bool {
        let guard = self.images.read().await;
        guard.contains(&sha256.to_lowercase())
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

        // Exact match & case-insensitive match
        assert!(registry.is_user_exempt(999, "steam_game_dev").await);
        assert!(registry.is_user_exempt(999, "STEAM_GAME_DEV").await);
        assert!(
            registry
                .is_user_exempt(1015600709724557434, "random_name")
                .await
        );

        // Non-whitelisted user fails
        assert!(!registry.is_user_exempt(88888, "stranger").await);

        registry.remove_user("Steam_Game_Dev").await;
        assert!(!registry.is_user_exempt(999, "steam_game_dev").await);
    }

    #[tokio::test]
    async fn test_whitelist_image_safety() {
        let registry = WhitelistRegistry::new();
        let sample_hash = "907cbc96639a65097b5dad76b89b36598f5139d7108323ed3a333f72b9a922da";

        registry.add_image(sample_hash).await;
        assert!(registry.is_image_safe(sample_hash).await);
        // Case-insensitive hex matching
        assert!(registry.is_image_safe(&sample_hash.to_uppercase()).await);
        assert!(!registry.is_image_safe("unknown_hash_value").await);
    }
}
