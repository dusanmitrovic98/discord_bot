use serenity::builder::GetMessages;
use serenity::model::id::ChannelId;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

use crate::config::GuildConfig;

/// Pure evaluation predicate: Testable in isolation without network mocks (NASA Rule 4)
pub fn is_target_welcome_message(
    author_is_bot: bool,
    author_id: u64,
    msg_timestamp_unix: i64,
    now_unix: i64,
    target_bot_id: u64,
    max_age_secs: i64,
) -> bool {
    let is_recent = (now_unix - msg_timestamp_unix).abs() < max_age_secs;
    let is_target_author = author_id == target_bot_id || author_is_bot;
    is_recent && is_target_author
}

/// Executes a single discrete inspection pass over the welcome channel
async fn sweep_once(
    http: &serenity::http::Http,
    channel_id: ChannelId,
    config: &GuildConfig,
    now_unix: i64,
    attempt: usize,
) -> bool {
    let messages = match channel_id.messages(http, GetMessages::new().limit(3)).await {
        Ok(msgs) => msgs,
        Err(e) => {
            error!("❌ [SWEEPER] Failed reading #welcome history: {}", e);
            return false;
        }
    };

    for msg in messages {
        let msg_ts = msg.timestamp.unix_timestamp();
        if !is_target_welcome_message(
            msg.author.bot,
            msg.author.id.get(),
            msg_ts,
            now_unix,
            config.sapphire_bot_id,
            60,
        ) {
            continue;
        }

        warn!(
            "🚨 [PURGE] Found welcome card from {} (ID: {}). Deleting on attempt {}...",
            msg.author.name, msg.id, attempt
        );
        match channel_id.delete_message(http, msg.id).await {
            Ok(()) => {
                info!(
                    "✅ [SWEEPER SUCCESS] Deleted welcome card on attempt {}!",
                    attempt
                );
                return true;
            }
            Err(e) => {
                error!(
                    "❌ [SWEEPER ERROR] Failed deleting message in #welcome: {}",
                    e
                );
            }
        }
    }

    false
}

/// Active Welcome Channel Sweeper: Linear retry loop without deep nesting (NASA Rule 1)
pub async fn purge_welcome_channel_on_nsfw_join(
    http: Arc<serenity::http::Http>,
    config: Arc<GuildConfig>,
) {
    let channel_id = ChannelId::new(config.welcome_channel_id);
    info!("🧹 [SWEEPER] Starting active sweep on #welcome for flagged join...");

    for attempt in 1..=4 {
        tokio::time::sleep(Duration::from_millis(800)).await;
        let now_unix = serenity::model::Timestamp::now().unix_timestamp();

        if sweep_once(&http, channel_id, &config, now_unix, attempt).await {
            return; // Target eliminated; exit immediately
        }
    }

    warn!("⚠️ [SWEEPER TIMEOUT] Active sweep finished 4 attempts.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_target_welcome_message_predicate() {
        let target_bot_id = 678344927997853742;
        let now = 1000;

        // Exact match: Sapphire bot, fresh message (5 seconds old)
        assert!(is_target_welcome_message(
            true,
            target_bot_id,
            995,
            now,
            target_bot_id,
            60
        ));

        // Generic bot, fresh message
        assert!(is_target_welcome_message(
            true,
            12345,
            995,
            now,
            target_bot_id,
            60
        ));

        // Expired message (70 seconds old) -> false
        assert!(!is_target_welcome_message(
            true,
            target_bot_id,
            920,
            now,
            target_bot_id,
            60
        ));

        // Human user (not bot, not sapphire) -> false
        assert!(!is_target_welcome_message(
            false,
            99999,
            995,
            now,
            target_bot_id,
            60
        ));
    }
}
