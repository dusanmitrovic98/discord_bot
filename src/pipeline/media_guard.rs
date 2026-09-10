use tracing::{info, warn};

use crate::bot::BotContainer;
use crate::media::MediaPayload;
use crate::queue::ScanTask;
use crate::Result;

pub enum MediaVerdict {
    Safe,
    BlacklistedNSFW,
    QueuedForInference(tokio::sync::oneshot::Receiver<Result<crate::queue::ClassifierResponse>>),
}

/// Evaluates media payload through In-Memory Whitelist -> In-Memory dHash/SHA -> AI Queue (5 arguments, NASA Rule 4)
pub async fn triage_media(
    c: &BotContainer,
    payload: &MediaPayload,
    user_id: u64,
    guild_id: u64,
    media_url: String,
) -> Result<MediaVerdict> {
    // 1. In-Memory Whitelist Check (Fast-path 0ms bypass)
    if c.whitelist.is_image_safe(&payload.sha256).await {
        info!(
            "🟢 [WHITELIST] Media {} is verified safe. Bypassing scan.",
            payload.sha256
        );
        return Ok(MediaVerdict::Safe);
    }

    // 2. SHA-256 Exact Blacklist
    if c.db.is_image_blacklisted(&payload.sha256).await? {
        warn!(
            "🚨 [SHA BLACKLIST] Media matches blacklisted hash: {}",
            payload.sha256
        );
        return Ok(MediaVerdict::BlacklistedNSFW);
    }

    // 3. In-Memory dHash Perceptual Check in CPU Registers (<2μs)
    if payload.dhash != 0 {
        let guard = c.blacklisted_dhashes.read().await;
        for &banned_dhash in guard.iter() {
            if (banned_dhash ^ payload.dhash).count_ones() <= 6 {
                warn!(
                    "🚨 [dHash BLACKLIST] Media matches perceptual logo signature (distance <= 6)!"
                );
                return Ok(MediaVerdict::BlacklistedNSFW);
            }
        }
    }

    // 4. Queue to ViT Classifier
    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = ScanTask {
        user_id,
        guild_id,
        image_url: media_url,
        image_bytes: payload.bytes.clone(),
        response_tx: tx,
    };

    c.scan_queue.submit(task).await?;
    Ok(MediaVerdict::QueuedForInference(rx))
}
