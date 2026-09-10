use tracing::{info, warn};

use crate::db::DatabaseEngine;
use crate::media::MediaPayload;
use crate::queue::{BoundedScanQueue, ScanTask};
use crate::whitelist::WhitelistRegistry;
use crate::Result;

pub enum MediaVerdict {
    Safe,
    BlacklistedNSFW,
    QueuedForInference(tokio::sync::oneshot::Receiver<Result<crate::queue::ClassifierResponse>>),
}

/// Evaluates media payload through Whitelist -> Blacklist -> AI Inference Queue
pub async fn triage_media(
    payload: &MediaPayload,
    user_id: u64,
    guild_id: u64,
    media_url: String,
    whitelist: &WhitelistRegistry,
    db: &DatabaseEngine,
    scan_queue: &BoundedScanQueue,
) -> Result<MediaVerdict> {
    // 1. Whitelist Check (Fast-path 0ms bypass)
    if whitelist.is_image_safe(&payload.sha256).await {
        info!(
            "🟢 [WHITELIST] Media {} is verified safe. Bypassing scan.",
            payload.sha256
        );
        return Ok(MediaVerdict::Safe);
    }

    // 2. Blacklist Check (SHA-256 and Perceptual dHash)
    if db.is_image_blacklisted(&payload.sha256).await?
        || db.is_dhash_blacklisted(payload.dhash).await?
    {
        warn!(
            "🚨 [BLACKLIST] Media matches blacklisted signature: {}",
            payload.sha256
        );
        return Ok(MediaVerdict::BlacklistedNSFW);
    }

    // 3. Queue to ViT Classifier
    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = ScanTask {
        user_id,
        guild_id,
        image_url: media_url,
        image_bytes: payload.bytes.clone(),
        response_tx: tx,
    };

    scan_queue.submit(task).await?;
    Ok(MediaVerdict::QueuedForInference(rx))
}
