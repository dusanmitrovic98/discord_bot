use serenity::builder::GetMessages;
use serenity::model::id::ChannelId;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

use crate::config::GuildConfig;

/// Active Welcome Channel Sweeper: Retries every 800ms across 4 attempts to delete Sapphire welcome messages
pub async fn purge_welcome_channel_on_nsfw_join(
    http: Arc<serenity::http::Http>,
    config: Arc<GuildConfig>,
) {
    let channel = ChannelId::new(config.welcome_channel_id);
    info!("🧹 [SWEEPER] Launching active sweep on #welcome for flagged join...");

    for attempt in 1..=4 {
        tokio::time::sleep(Duration::from_millis(800)).await;

        match channel.messages(&http, GetMessages::new().limit(3)).await {
            Ok(messages) => {
                for msg in messages {
                    let now = serenity::model::Timestamp::now().unix_timestamp();
                    let msg_time = msg.timestamp.unix_timestamp();

                    if (now - msg_time).abs() < 60
                        && (msg.author.bot || msg.author.id.get() == config.sapphire_bot_id)
                    {
                        warn!(
                            "🚨 [PURGE] Found recent welcome message from {} (ID: {}). Deleting on attempt {}...",
                            msg.author.name, msg.id, attempt
                        );
                        match channel.delete_message(&http, msg.id).await {
                            Ok(()) => {
                                info!(
                                    "✅ [SWEEPER SUCCESS] Deleted welcome card on attempt {}!",
                                    attempt
                                );
                                return;
                            }
                            Err(e) => {
                                error!("❌ CRITICAL DISCORD ERROR: Failed deleting message in #welcome: {}. Check 'Manage Messages' permission!", e);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!("❌ FAILED FETCHING #welcome messages: {}. Check 'Read Message History' permission!", e);
            }
        }
    }
}
