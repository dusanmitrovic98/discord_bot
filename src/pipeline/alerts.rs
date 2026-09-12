//! # Sebastian The Butler - Alert & Notification Dispatcher
//!
//! Handles dual-tier moderation channel alerts, direct messages to users for review/whitelisting,
//! and tangible diagnostic proof embeds dispatched directly to the Sovereign Owner's DMs.

use serenity::builder::{CreateAttachment, CreateEmbed, CreateMessage};
use serenity::http::Http;
use serenity::model::id::{ChannelId, UserId};
use serenity::prelude::*;
use tracing::{error, info, warn};

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

/// Dispatches a courteous, discrete direct message to a user.
/// Mentions that their asset is being reviewed, highlights that it may be a false positive,
/// and invites them to contact Dule (@bk2o198) with any questions.
/// Gracefully handles closed DMs without panicking (NASA Rule 5).
pub async fn send_user_notification(
    http: &Http,
    user_id: u64,
    title: &str,
    body: &str,
) -> bool {
    let user = UserId::new(user_id);
    let Ok(dm_channel) = user.create_dm_channel(http).await else {
        info!("ℹ️ User <@{}> has direct messages disabled.", user_id);
        return false;
    };

    let embed = CreateEmbed::new()
        .title(title)
        .description(format!(
            "{}\n\n*Note: This may be an automated false positive. Our team will review it shortly. If you have questions, please feel free to reach out to **Dule (@bk2o198)**.*",
            body
        ))
        .color(0xd25a3f)
        .footer(serenity::builder::CreateEmbedFooter::new("The Chill Zone // Safety Concierge"));

    let msg = CreateMessage::new().embed(embed);

    match dm_channel.send_message(http, msg).await {
        Ok(_) => {
            info!("📨 Notification successfully delivered to <@{}> DM.", user_id);
            true
        }
        Err(e) => {
            warn!("⚠️ Could not deliver DM to <@{}>: {}", user_id, e);
            false
        }
    }
}

/// Dispatches tangible diagnostic proof of test execution directly to the Sovereign Owner's DMs.
pub async fn send_owner_diagnostic(
    http: &Http,
    config: &GuildConfig,
    title: &str,
    details: &str,
) {
    let owner = UserId::new(config.owner_user_id);
    let Ok(dm_channel) = owner.create_dm_channel(http).await else {
        error!("Fatal: Could not open DM channel with Sovereign Owner ({}).", config.owner_user_id);
        return;
    };

    let embed = CreateEmbed::new()
        .title(format!("🧪 [DIAGNOSTIC PROOF] {}", title))
        .description(details)
        .color(0x10b981)
        .timestamp(serenity::model::Timestamp::now())
        .footer(serenity::builder::CreateEmbedFooter::new("Sebastian The Butler // Kernel Telemetry"));

    let msg = CreateMessage::new().embed(embed);

    if let Err(e) = dm_channel.send_message(http, msg).await {
        error!("Failed sending diagnostic proof to Owner DM: {}", e);
    }
}
