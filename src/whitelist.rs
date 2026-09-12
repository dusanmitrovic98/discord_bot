//! # Dual-Layer Whitelist Registry
//!
//! Maintains in-memory registries of whitelisted usernames, user IDs,
//! exact SHA-256 image hashes, and perceptual difference hashes.

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
                if !img.dhash.is_empty() {
                    if let Ok(val) = u64::from_str_radix(&img.dhash, 16) {
                        dhash_vec.push(val);
                    }
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

    pub async fn is_image_safe(&self, sha256: &str, dhash: u64) -> bool {
        let i_guard = self.images.read().await;
        if i_guard.contains(&sha256.to_lowercase()) {
            return true;
        }

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
