use crate::{AegisError, Result};
use mongodb::{
    bson::{doc, Binary, DateTime as BsonDateTime, Document},
    Client, Collection, Database,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AdminUser {
    pub username: String,
    pub password_hash: String,
    pub role: String,
    pub created_at: BsonDateTime,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DynamicRule {
    pub pattern: String,
    pub description: String,
    pub action: String,
    pub enabled: bool,
    pub added_by: String,
    pub created_at: BsonDateTime,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WhitelistedUser {
    pub identifier: String,
    pub added_by: String,
    pub reason: String,
    pub created_at: BsonDateTime,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WhitelistedImage {
    pub sha256: String,
    #[serde(default)]
    pub dhash: u64,
    pub label: String,
    pub added_by: String,
    pub created_at: BsonDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub user_id: u64,
    pub username: String,
    pub reason: String,
    pub confidence: f64,
    pub matched_rule: String,
    pub timestamp: BsonDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CoreBlobDocument {
    pub version: String,
    pub compressed_binary: Binary,
    pub signature: Binary,
    pub sha256: String,
    pub deployed_at: BsonDateTime,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PluginRecord {
    pub name: String,
    #[serde(default)]
    pub manifest_json: String,
    pub bytecode: Binary,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub registered_command_ids: Vec<u64>,
    pub updated_at: BsonDateTime,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PluginKvEntry {
    pub plugin_id: String,
    pub key: String,
    pub value: String,
    pub updated_at: BsonDateTime,
}

#[derive(Clone)]
pub struct DatabaseEngine {
    db: Database,
}

impl DatabaseEngine {
    pub async fn connect(uri: &str, db_name: &str) -> Result<Self> {
        let client = Client::with_uri_str(uri).await?;
        let db = client.database(db_name);
        Ok(Self { db })
    }

    pub async fn get_storage_stats(&self) -> Result<(u64, u64)> {
        let stats = self.db.run_command(doc! { "dbStats": 1 }).await?;
        let total_size = match stats.get("totalSize") {
            Some(mongodb::bson::Bson::Int64(v)) => *v as u64,
            Some(mongodb::bson::Bson::Int32(v)) => *v as u64,
            Some(mongodb::bson::Bson::Double(v)) => *v as u64,
            _ => 5_000_000,
        };
        let max_m0_capacity: u64 = 512 * 1024 * 1024;
        Ok((total_size, max_m0_capacity))
    }

    pub async fn fetch_core_blob(&self) -> Result<CoreBlobDocument> {
        let coll: Collection<CoreBlobDocument> = self.db.collection("system_core_blob");
        coll.find_one(doc! {})
            .sort(doc! { "deployed_at": -1 })
            .await?
            .ok_or_else(|| {
                AegisError::DatabaseError(mongodb::error::Error::custom("No core blob in database"))
            })
    }

    // =========================================================================
    // IN-MEMORY dHash MIRROR DATA PROVIDER (Zero remote cursor scans!)
    // =========================================================================
    pub async fn fetch_all_dhashes(&self) -> Result<Vec<u64>> {
        let coll: Collection<Document> = self.db.collection("image_signatures");
        let mut cursor = coll.find(doc! {}).await?;
        let mut dhashes = Vec::new();

        while cursor.advance().await? {
            let doc = cursor.deserialize_current()?;
            if let Ok(dhash_i64) = doc.get_i64("dhash") {
                let dhash = dhash_i64 as u64;
                if dhash != 0 {
                    dhashes.push(dhash);
                }
            }
        }
        Ok(dhashes)
    }

    pub async fn record_banned_image(&self, sha256: &str, dhash: u64, user_id: u64) -> Result<()> {
        let coll: Collection<Document> = self.db.collection("image_signatures");
        coll.insert_one(doc! {
            "sha256": sha256,
            "dhash": dhash as i64,
            "label": "Auto-Flagged NSFW Media",
            "banned_from_user": user_id as i64,
            "recorded_at": BsonDateTime::now()
        })
        .await?;
        Ok(())
    }

    pub async fn blacklist_image_explicit(
        &self,
        sha256: &str,
        dhash: u64,
        label: &str,
        added_by: &str,
    ) -> Result<()> {
        let coll: Collection<Document> = self.db.collection("image_signatures");
        coll.insert_one(doc! {
            "sha256": sha256,
            "dhash": dhash as i64,
            "label": label,
            "added_by": added_by,
            "banned_from_user": 0i64,
            "recorded_at": BsonDateTime::now()
        })
        .await?;
        Ok(())
    }

    pub async fn is_image_blacklisted(&self, sha256: &str) -> Result<bool> {
        let coll: Collection<Document> = self.db.collection("image_signatures");
        let count = coll.count_documents(doc! { "sha256": sha256 }).await?;
        Ok(count > 0)
    }

    pub async fn revoke_blacklisted_image(&self, sha256: &str) -> Result<()> {
        let coll: Collection<Document> = self.db.collection("image_signatures");
        coll.delete_one(doc! { "sha256": sha256 }).await?;
        Ok(())
    }

    pub async fn fetch_all_image_signatures(&self) -> Result<Vec<Document>> {
        let coll: Collection<Document> = self.db.collection("image_signatures");
        let mut cursor = coll
            .find(doc! {})
            .sort(doc! { "recorded_at": -1 })
            .limit(50)
            .await?;
        let mut docs = Vec::new();
        while cursor.advance().await? {
            docs.push(cursor.deserialize_current()?);
        }
        Ok(docs)
    }

    // Whitelists CRUD
    pub async fn add_whitelisted_user(
        &self,
        identifier: &str,
        added_by: &str,
        reason: &str,
    ) -> Result<()> {
        let coll: Collection<WhitelistedUser> = self.db.collection("whitelisted_users");
        coll.delete_many(doc! { "identifier": identifier.to_lowercase() })
            .await?;
        coll.insert_one(WhitelistedUser {
            identifier: identifier.to_lowercase(),
            added_by: added_by.to_string(),
            reason: reason.to_string(),
            created_at: BsonDateTime::now(),
        })
        .await?;
        Ok(())
    }

    pub async fn remove_whitelisted_user(&self, identifier: &str) -> Result<()> {
        let coll: Collection<Document> = self.db.collection("whitelisted_users");
        coll.delete_many(doc! { "identifier": identifier.to_lowercase() })
            .await?;
        Ok(())
    }

    pub async fn fetch_whitelisted_users(&self) -> Result<Vec<WhitelistedUser>> {
        let coll: Collection<WhitelistedUser> = self.db.collection("whitelisted_users");
        let mut cursor = coll.find(doc! {}).await?;
        let mut users = Vec::new();
        while cursor.advance().await? {
            users.push(cursor.deserialize_current()?);
        }
        Ok(users)
    }

    /// Atomically records a whitelisted image and evicts any existing blacklist signatures
    pub async fn add_whitelisted_image(
        &self,
        sha256: &str,
        dhash: u64,
        label: &str,
        added_by: &str,
    ) -> Result<()> {
        let sig_coll: Collection<Document> = self.db.collection("image_signatures");

        // Evict exact SHA-256 and matching dHash from blacklist
        let mut filter = vec![doc! { "sha256": sha256 }];
        if dhash != 0 {
            filter.push(doc! { "dhash": dhash as i64 });
        }
        sig_coll.delete_many(doc! { "$or": filter }).await?;

        let wl_coll: Collection<WhitelistedImage> = self.db.collection("whitelisted_images");
        wl_coll.delete_many(doc! { "sha256": sha256 }).await?;
        wl_coll
            .insert_one(WhitelistedImage {
                sha256: sha256.to_string(),
                dhash,
                label: label.to_string(),
                added_by: added_by.to_string(),
                created_at: BsonDateTime::now(),
            })
            .await?;
        Ok(())
    }

    pub async fn remove_whitelisted_image(&self, sha256: &str) -> Result<()> {
        let coll: Collection<Document> = self.db.collection("whitelisted_images");
        coll.delete_many(doc! { "sha256": sha256 }).await?;
        Ok(())
    }

    pub async fn fetch_whitelisted_images(&self) -> Result<Vec<WhitelistedImage>> {
        let coll: Collection<WhitelistedImage> = self.db.collection("whitelisted_images");
        let mut cursor = coll.find(doc! {}).await?;
        let mut images = Vec::new();
        while cursor.advance().await? {
            images.push(cursor.deserialize_current()?);
        }
        Ok(images)
    }

    // Rules CRUD
    pub async fn fetch_dynamic_rules(&self) -> Result<Vec<DynamicRule>> {
        let coll: Collection<DynamicRule> = self.db.collection("dynamic_rules");
        let mut cursor = coll.find(doc! { "enabled": true }).await?;
        let mut rules = Vec::new();
        while cursor.advance().await? {
            rules.push(cursor.deserialize_current()?);
        }
        Ok(rules)
    }

    pub async fn add_dynamic_rule(&self, rule: DynamicRule) -> Result<()> {
        let coll: Collection<DynamicRule> = self.db.collection("dynamic_rules");
        coll.insert_one(rule).await?;
        Ok(())
    }

    pub async fn delete_dynamic_rule(&self, pattern: &str) -> Result<()> {
        let coll: Collection<Document> = self.db.collection("dynamic_rules");
        coll.delete_one(doc! { "pattern": pattern }).await?;
        Ok(())
    }

    // Users CRUD
    pub async fn get_admin_user_count(&self) -> Result<u64> {
        let coll: Collection<Document> = self.db.collection("admin_users");
        let count = coll.count_documents(doc! {}).await?;
        Ok(count)
    }

    pub async fn create_admin_user(&self, user: AdminUser) -> Result<()> {
        let coll: Collection<AdminUser> = self.db.collection("admin_users");
        coll.insert_one(user).await?;
        Ok(())
    }

    pub async fn fetch_user(&self, username: &str) -> Result<Option<AdminUser>> {
        let coll: Collection<AdminUser> = self.db.collection("admin_users");
        let user = coll.find_one(doc! { "username": username }).await?;
        Ok(user)
    }

    pub async fn fetch_all_users(&self) -> Result<Vec<AdminUser>> {
        let coll: Collection<AdminUser> = self.db.collection("admin_users");
        let mut cursor = coll.find(doc! {}).await?;
        let mut users = Vec::new();
        while cursor.advance().await? {
            users.push(cursor.deserialize_current()?);
        }
        Ok(users)
    }

    pub async fn record_audit(&self, entry: AuditLogEntry) -> Result<()> {
        let coll: Collection<AuditLogEntry> = self.db.collection("moderation_audit_log");
        coll.insert_one(entry).await?;
        Ok(())
    }

    pub async fn fetch_recent_audits(&self, limit: i64) -> Result<Vec<AuditLogEntry>> {
        let coll: Collection<AuditLogEntry> = self.db.collection("moderation_audit_log");
        let mut cursor = coll
            .find(doc! {})
            .sort(doc! { "timestamp": -1 })
            .limit(limit)
            .await?;
        let mut audits = Vec::new();
        while cursor.advance().await? {
            audits.push(cursor.deserialize_current()?);
        }
        Ok(audits)
    }

    pub async fn fetch_active_plugins(&self) -> Result<Vec<(String, Vec<u8>)>> {
        let coll: Collection<Document> = self.db.collection("plugins");
        let mut cursor = coll.find(doc! { "enabled": true }).await?;
        let mut plugins = Vec::new();

        while cursor.advance().await? {
            let doc = cursor.deserialize_current()?;
            if let (Ok(name), Ok(bytes)) = (doc.get_str("name"), doc.get_binary_generic("bytecode"))
            {
                plugins.push((name.to_string(), bytes.to_vec()));
            }
        }
        Ok(plugins)
    }

    // =========================================================================
    // COMMUNITY WASM PLUGINS REGISTRY
    // =========================================================================
    pub async fn save_plugin_record(&self, record: PluginRecord) -> Result<()> {
        let coll: Collection<PluginRecord> = self.db.collection("plugins");
        coll.delete_many(doc! { "name": &record.name }).await?;
        coll.insert_one(record).await?;
        Ok(())
    }

    pub async fn fetch_all_plugin_records(&self) -> Result<Vec<PluginRecord>> {
        let coll: Collection<PluginRecord> = self.db.collection("plugins");
        let mut cursor = coll.find(doc! {}).await?;
        let mut records = Vec::new();
        while cursor.advance().await? {
            records.push(cursor.deserialize_current()?);
        }
        Ok(records)
    }

    pub async fn toggle_plugin_record(&self, name: &str, enabled: bool) -> Result<()> {
        let coll: Collection<Document> = self.db.collection("plugins");
        coll.update_one(
            doc! { "name": name },
            doc! { "$set": { "enabled": enabled, "updated_at": BsonDateTime::now() } },
        )
        .await?;
        Ok(())
    }

    pub async fn delete_plugin_record(&self, name: &str) -> Result<()> {
        let coll: Collection<Document> = self.db.collection("plugins");
        coll.delete_many(doc! { "name": name }).await?;
        Ok(())
    }

    // =========================================================================
    // ISOLATED PLUGIN KEY-VALUE STORAGE
    // =========================================================================
    pub async fn plugin_kv_set(&self, plugin_id: &str, key: &str, value: &str) -> Result<()> {
        let coll: Collection<PluginKvEntry> = self.db.collection("plugin_storage");
        coll.delete_many(doc! { "plugin_id": plugin_id, "key": key })
            .await?;
        coll.insert_one(PluginKvEntry {
            plugin_id: plugin_id.to_string(),
            key: key.to_string(),
            value: value.to_string(),
            updated_at: BsonDateTime::now(),
        })
        .await?;
        Ok(())
    }

    pub async fn plugin_kv_get(&self, plugin_id: &str, key: &str) -> Result<Option<String>> {
        let coll: Collection<PluginKvEntry> = self.db.collection("plugin_storage");
        let entry = coll
            .find_one(doc! { "plugin_id": plugin_id, "key": key })
            .await?;
        Ok(entry.map(|e| e.value))
    }
}
