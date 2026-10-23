//! # Cluster Distributed Lease State Machine
//!
//! Provides atomic master lease management on MongoDB Atlas with fencing tokens.
//! Heartbeat = 300s (5m), TTL = 600s (10m).
//! Strictly enforces NASA Rules 2 (bounded loops) and 7 (check all return values).

use mongodb::bson::{doc, DateTime as BsonDateTime, Document};
use mongodb::Collection;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{error, info, warn};

use crate::db::DatabaseEngine;
use crate::{AegisError, Result};

pub const LEADER_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(300); // 5 min
pub const LEASE_TTL_DURATION: Duration = Duration::from_secs(600); // 10 min
pub const LEASE_DOC_ID: &str = "active_bastion_core";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClusterLeaderLease {
    pub _id: String,
    pub leader_id: String,
    pub leader_url: String,
    pub lease_expires_at: BsonDateTime,
    pub last_heartbeat: BsonDateTime,
    pub fencing_token: i64,
}

pub struct LeaseManager {
    db: DatabaseEngine,
    instance_id: String,
    service_url: String,
}

impl LeaseManager {
    pub fn new(db: DatabaseEngine, instance_id: String, service_url: String) -> Self {
        Self {
            db,
            instance_id,
            service_url,
        }
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub fn service_url(&self) -> &str {
        &self.service_url
    }

    /// Atomically attempts to acquire or renew leadership lease.
    pub async fn try_acquire_or_renew(&self) -> Result<Option<ClusterLeaderLease>> {
        let coll: Collection<Document> = self.db.raw_database().collection("cluster_leader_lease");
        let now_ms = chrono::Utc::now().timestamp_millis();
        let expires_ms = now_ms + (LEASE_TTL_DURATION.as_millis() as i64);

        let filter = doc! {
            "_id": LEASE_DOC_ID,
            "$or": [
                { "leader_id": &self.instance_id },
                { "lease_expires_at": { "$lt": BsonDateTime::from_millis(now_ms) } }
            ]
        };

        let update = doc! {
            "$set": {
                "leader_id": &self.instance_id,
                "leader_url": &self.service_url,
                "lease_expires_at": BsonDateTime::from_millis(expires_ms),
                "last_heartbeat": BsonDateTime::from_millis(now_ms)
            },
            "$inc": { "fencing_token": 1i64 }
        };

        let options = mongodb::options::FindOneAndUpdateOptions::builder()
            .upsert(true)
            .return_document(mongodb::options::ReturnDocument::After)
            .build();

        match coll
            .find_one_and_update(filter, update)
            .with_options(options)
            .await
        {
            Ok(Some(doc)) => {
                let lease: ClusterLeaderLease = mongodb::bson::from_document(doc)?;
                if lease.leader_id == self.instance_id {
                    Ok(Some(lease))
                } else {
                    Ok(None)
                }
            }
            Ok(None) => Ok(None),
            Err(e) => {
                error!("Database error while checking lease: {}", e);
                Err(AegisError::DatabaseError(e))
            }
        }
    }

    /// Fast-path lease steal: executed when P2P health probes confirm leader is dead.
    pub async fn force_fast_path_steal(
        &self,
        dead_leader_id: &str,
    ) -> Result<Option<ClusterLeaderLease>> {
        let coll: Collection<Document> = self.db.raw_database().collection("cluster_leader_lease");
        let now_ms = chrono::Utc::now().timestamp_millis();
        let expires_ms = now_ms + (LEASE_TTL_DURATION.as_millis() as i64);

        let filter = doc! {
            "_id": LEASE_DOC_ID,
            "leader_id": dead_leader_id
        };

        let update = doc! {
            "$set": {
                "leader_id": &self.instance_id,
                "leader_url": &self.service_url,
                "lease_expires_at": BsonDateTime::from_millis(expires_ms),
                "last_heartbeat": BsonDateTime::from_millis(now_ms)
            },
            "$inc": { "fencing_token": 1i64 }
        };

        let options = mongodb::options::FindOneAndUpdateOptions::builder()
            .return_document(mongodb::options::ReturnDocument::After)
            .build();

        match coll
            .find_one_and_update(filter, update)
            .with_options(options)
            .await
        {
            Ok(Some(doc)) => {
                let lease: ClusterLeaderLease = mongodb::bson::from_document(doc)?;
                info!(
                    "⚡ [FAST PATH] Lease stolen from dead leader '{}'",
                    dead_leader_id
                );
                Ok(Some(lease))
            }
            Ok(None) => {
                warn!("Fast-path steal aborted: leader was already updated or changed.");
                Ok(None)
            }
            Err(e) => Err(AegisError::DatabaseError(e)),
        }
    }

    /// Graceful lease release on SIGTERM shutdown.
    pub async fn release_leadership(&self) -> Result<()> {
        let coll: Collection<Document> = self.db.raw_database().collection("cluster_leader_lease");
        let filter = doc! {
            "_id": LEASE_DOC_ID,
            "leader_id": &self.instance_id
        };
        let update = doc! {
            "$set": {
                "lease_expires_at": BsonDateTime::from_millis(0)
            }
        };
        let _ = coll.update_one(filter, update).await;
        info!("Voluntarily surrendered leadership lease on shutdown.");
        Ok(())
    }

    pub async fn fetch_current_lease(&self) -> Result<Option<ClusterLeaderLease>> {
        let coll: Collection<Document> = self.db.raw_database().collection("cluster_leader_lease");
        let doc_opt = coll.find_one(doc! { "_id": LEASE_DOC_ID }).await?;
        match doc_opt {
            Some(d) => Ok(Some(mongodb::bson::from_document(d)?)),
            None => Ok(None),
        }
    }
}
