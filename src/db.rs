use crate::{AegisError, Result};
use mongodb::{
    bson::{doc, Binary, DateTime as BsonDateTime, Document},
    Client, Collection, Database,
};
use serde::{Deserialize, Serialize};

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

    /// Retrieve the signed core binary blob.
    pub async fn fetch_core_blob(&self) -> Result<CoreBlobDocument> {
        let coll: Collection<CoreBlobDocument> = self.db.collection("system_core_blob");
        coll.find_one(doc! {})
            .sort(doc! { "deployed_at": -1 })
            .await?
            .ok_or_else(|| {
                AegisError::DatabaseError(mongodb::error::Error::custom("No core blob in database"))
            })
    }

    /// Record a banned image hash to prevent re-processing repeat attacks.
    pub async fn record_banned_image(&self, sha256: &str, dhash: u64, user_id: u64) -> Result<()> {
        let coll: Collection<Document> = self.db.collection("image_signatures");
        coll.insert_one(doc! {
            "sha256": sha256,
            "dhash": dhash as i64,
            "banned_from_user": user_id as i64,
            "recorded_at": BsonDateTime::now()
        })
        .await?;
        Ok(())
    }

    /// Check if image hash is already blacklisted.
    pub async fn is_image_blacklisted(&self, sha256: &str) -> Result<bool> {
        let coll: Collection<Document> = self.db.collection("image_signatures");
        let count = coll.count_documents(doc! { "sha256": sha256 }).await?;
        Ok(count > 0)
    }

    /// Immutable Law-Enforcement Audit Log.
    pub async fn record_audit(&self, entry: AuditLogEntry) -> Result<()> {
        let coll: Collection<AuditLogEntry> = self.db.collection("moderation_audit_log");
        coll.insert_one(entry).await?;
        Ok(())
    }

    /// Fetch all enabled WASM plugins from MongoDB.
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
}
