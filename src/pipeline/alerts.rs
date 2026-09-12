//! # Sebastian The Butler - Alerts & Notifications
//!
//! Plain, clean notifications for moderators, evidence channels, and member DMs.

use serenity::builder::{CreateAttachment, CreateEmbed, CreateMessage};
use serenity::http::Http;
use serenity::model::id::{ChannelId, UserId};
use serenity::prelude::*;
use tracing::{error, info, warn};

use crate::config::GuildConfig;

pub async fn send_mod_alert(
    ctx: &Context,
    config: &GuildConfig,
    title: &str,
    description: &str,
    offender_id: u64,
) {
    let channel = ChannelId::new(config.mod_channel_id);
    let embed = CreateEmbed::new()
        .title(title)
        .description(description)
        .field(
            "User",
            format!("<@{}> (`{}`)", offender_id, offender_id),
            true,
        )
        .color(0xef4444);

    let msg = CreateMessage::new()
        .content(format!("<@{}> Moderation Notice", config.owner_user_id))
        .embed(embed);

    if let Err(e) = channel.send_message(&ctx.http, msg).await {
        error!("Failed sending mod alert: {}", e);
    }
}

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
        .title(title)
        .description(description)
        .field(
            "User",
            format!("<@{}> (`{}`)", offender_id, offender_id),
            true,
        )
        .image("attachment://evidence.png")
        .color(0xff7700);

    let msg = CreateMessage::new()
        .content(format!("<@{}> Evidence Log", config.owner_user_id))
        .embed(embed)
        .add_file(attachment);

    if let Err(e) = channel.send_message(&ctx.http, msg).await {
        error!("Failed sending evidence log: {}", e);
    }
}

pub async fn send_user_notification(http: &Http, user_id: u64, title: &str, body: &str) -> bool {
    let user = UserId::new(user_id);
    let Ok(dm_channel) = user.create_dm_channel(http).await else {
        return false;
    };

    let embed = CreateEmbed::new()
        .title(title)
        .description(format!(
            "{}\n\n*This may be an automated false positive. Staff will review it shortly. If you have questions, please reach out to **Dule (@bk2o198)**.*",
            body
        ))
        .color(0xd25a3f)
        .footer(serenity::builder::CreateEmbedFooter::new("Sebastian The Butler"));

    let msg = CreateMessage::new().embed(embed);

    match dm_channel.send_message(http, msg).await {
        Ok(_) => {
            info!("Delivered notification DM to user {}", user_id);
            true
        }
        Err(e) => {
            warn!("Could not send DM to user {}: {}", user_id, e);
            false
        }
    }
}

pub async fn send_owner_diagnostic(http: &Http, config: &GuildConfig, title: &str, details: &str) {
    let owner = UserId::new(config.owner_user_id);
    let Ok(dm_channel) = owner.create_dm_channel(http).await else {
        return;
    };

    let embed = CreateEmbed::new()
        .title(title)
        .description(details)
        .color(0x10b981)
        .timestamp(serenity::model::Timestamp::now())
        .footer(serenity::builder::CreateEmbedFooter::new(
            "Sebastian The Butler",
        ));

    let msg = CreateMessage::new().embed(embed);

    if let Err(e) = dm_channel.send_message(http, msg).await {
        error!("Failed sending proof to Owner DM: {}", e);
    }
}
