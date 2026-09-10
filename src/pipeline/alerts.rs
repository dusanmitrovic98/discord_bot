use serenity::builder::{CreateAttachment, CreateEmbed, CreateMessage};
use serenity::model::id::ChannelId;
use serenity::prelude::*;
use tracing::error;

use crate::config::GuildConfig;

/// Tier 1 Alert: Dispatches clean, text-only embed to Moderator Channel (no graphic content)
pub async fn send_mod_alert(
    ctx: &Context,
    config: &GuildConfig,
    title: &str,
    description: &str,
    offender_id: u64,
) {
    let channel = ChannelId::new(config.mod_channel_id);
    let embed = CreateEmbed::new()
        .title(format!("⚠️ {}", title))
        .description(description)
        .field(
            "Target User",
            format!("<@{}> (`{}`)", offender_id, offender_id),
            true,
        )
        .color(0xef4444);

    let msg = CreateMessage::new()
        .content(format!(
            "<@{}> ⚠️ **MODERATION NOTICE**",
            config.owner_user_id
        ))
        .embed(embed);

    if let Err(e) = channel.send_message(&ctx.http, msg).await {
        error!(
            "Failed sending mod alert to channel {}: {}",
            config.mod_channel_id, e
        );
    }
}

/// Tier 2 Alert: Dispatches full evidence embed with image attached to Logs Channel
pub async fn send_logs_evidence(
    ctx: &Context,
    config: &GuildConfig,
    title: &str,
    description: &str,
    offender_id: u64,
    image_bytes: Vec<u8>,
) {
    let channel = ChannelId::new(config.logs_channel_id);
    let attachment = CreateAttachment::bytes(image_bytes, "evidence.png");

    let embed = CreateEmbed::new()
        .title(format!("🔍 [EVIDENCE LOG] {}", title))
        .description(description)
        .field(
            "Offender",
            format!("<@{}> (`{}`)", offender_id, offender_id),
            true,
        )
        .image("attachment://evidence.png")
        .color(0xff7700);

    let msg = CreateMessage::new()
        .content(format!("<@{}> 📋 **EVIDENCE AUDIT**", config.owner_user_id))
        .embed(embed)
        .add_file(attachment);

    if let Err(e) = channel.send_message(&ctx.http, msg).await {
        error!(
            "Failed sending evidence log to channel {}: {}",
            config.logs_channel_id, e
        );
    }
}
