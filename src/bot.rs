use serenity::async_trait;
use serenity::builder::{
    CreateCommand, CreateCommandOption, CreateInteractionResponse, CreateInteractionResponseMessage,
};
use serenity::model::application::{CommandDataOptionValue, CommandOptionType, Interaction};
use serenity::model::channel::Message;
use serenity::model::gateway::Ready;
use serenity::model::guild::{Guild, Member};
use serenity::model::id::{GuildId, UserId};
use serenity::prelude::*;
use std::sync::Arc;
use tracing::{info, warn};

use crate::config::GuildConfig;
use crate::db::{AuditLogEntry, DatabaseEngine};
use crate::gatekeeper::{TextGatekeeper, ThreatVerdict};
use crate::media::{MediaInspector, MediaPayload};
use crate::pipeline::alerts::{send_logs_evidence, send_mod_alert};
use crate::pipeline::media_guard::{triage_media, MediaVerdict};
use crate::pipeline::name_guard::evaluate_member_names;
use crate::pipeline::sweeper::purge_welcome_channel_on_nsfw_join;
use crate::plugin_engine::DynamicPluginEngine;
use crate::queue::BoundedScanQueue;
use crate::whitelist::WhitelistRegistry;

pub struct BotContainer {
    pub config: Arc<GuildConfig>,
    pub gatekeeper: Arc<TextGatekeeper>,
    pub db: Arc<DatabaseEngine>,
    pub whitelist: Arc<WhitelistRegistry>,
    pub media_inspector: Arc<MediaInspector>,
    pub scan_queue: Arc<BoundedScanQueue>,
    pub plugin_engine: Arc<DynamicPluginEngine>,
}

pub struct Handler;

#[async_trait]
impl EventHandler for Handler {
    async fn ready(&self, ctx: Context, _ready: Ready) {
        let container = get_container(&ctx).await;
        info!(
            "Sebastian The Butler is Online. Operating for Guild: {}",
            container.config.authorized_guild_id
        );

        let guild_id = GuildId::new(container.config.authorized_guild_id);
        let commands = vec![
            CreateCommand::new("test-name")
                .description("Evaluate any username against Gatekeeper")
                .add_option(
                    CreateCommandOption::new(CommandOptionType::String, "text", "Input string")
                        .required(true),
                ),
            CreateCommand::new("test-pfp")
                .description("Analyze an avatar through ViT classifier")
                .add_option(
                    CreateCommandOption::new(CommandOptionType::User, "user", "Target user")
                        .required(false),
                )
                .add_option(
                    CreateCommandOption::new(CommandOptionType::Attachment, "image", "Image file")
                        .required(false),
                ),
            CreateCommand::new("whitelist-user")
                .description("Exempt a user from Tier 2 soft rules")
                .add_option(
                    CreateCommandOption::new(CommandOptionType::User, "user", "Target user")
                        .required(true),
                )
                .add_option(
                    CreateCommandOption::new(CommandOptionType::String, "reason", "Reason")
                        .required(false),
                ),
            CreateCommand::new("whitelist-pfp")
                .description("Mark a user's avatar as verified safe")
                .add_option(
                    CreateCommandOption::new(CommandOptionType::User, "user", "Target user")
                        .required(true),
                ),
            CreateCommand::new("db-stats").description("Audit MongoDB cloud storage usage"),
        ];

        let _ = guild_id.set_commands(&ctx.http, commands).await;
    }

    async fn guild_create(&self, ctx: Context, guild: Guild, _is_new: Option<bool>) {
        let container = get_container(&ctx).await;
        if !container.config.is_authorized_guild(guild.id.get()) {
            warn!(
                "🚨 Evicting from unauthorized guild: {} ({})",
                guild.name, guild.id
            );
            let _ = guild.leave(&ctx.http).await;
        }
    }

    async fn guild_member_addition(&self, ctx: Context, member: Member) {
        let c = get_container(&ctx).await;
        if !c.config.is_authorized_guild(member.guild_id.get()) {
            return;
        }

        let user_id = member.user.id.get();
        let eval = evaluate_member_names(
            &c.gatekeeper,
            &c.whitelist,
            user_id,
            &member.user.name,
            member.user.global_name.as_deref().unwrap_or(""),
            member.nick.as_deref().unwrap_or(""),
        )
        .await;

        if eval.verdict == ThreatVerdict::InstantBan {
            tokio::spawn(purge_welcome_channel_on_nsfw_join(
                ctx.http.clone(),
                c.config.clone(),
            ));
            execute_ban(
                &ctx.http,
                member.guild_id,
                user_id,
                &format!("Predatory Name Match: {}", eval.offending_name),
                1.0,
                &c.db,
                &c.config,
            )
            .await;
            send_mod_alert(
                &ctx,
                &c.config,
                "Predatory User Banned on Join",
                &format!("Banned <@{}> for name `{}`", user_id, eval.offending_name),
                user_id,
            )
            .await;
            return;
        }

        // Avatar inspection on join
        if let Some(avatar_url) = member.user.avatar_url() {
            if let Ok(payload) = c.media_inspector.inspect_url(&avatar_url).await {
                handle_join_avatar(
                    &ctx,
                    &c,
                    user_id,
                    member.guild_id.get(),
                    &avatar_url,
                    payload,
                )
                .await;
            }
        }
    }

    async fn message(&self, ctx: Context, msg: Message) {
        if msg.author.id == ctx.cache.current_user().id {
            return;
        }
        let c = get_container(&ctx).await;
        if msg.guild_id != Some(GuildId::new(c.config.authorized_guild_id)) {
            return;
        }

        let author_id = msg.author.id.get();
        let eval = evaluate_member_names(
            &c.gatekeeper,
            &c.whitelist,
            author_id,
            &msg.author.name,
            msg.author.global_name.as_deref().unwrap_or(""),
            msg.member
                .as_ref()
                .and_then(|m| m.nick.as_deref())
                .unwrap_or(""),
        )
        .await;

        match eval.verdict {
            ThreatVerdict::InstantBan => {
                let _ = msg.delete(&ctx.http).await;
                if let Some(gid) = msg.guild_id {
                    execute_ban(
                        &ctx.http,
                        gid,
                        author_id,
                        &format!("Predatory Name: {}", eval.offending_name),
                        1.0,
                        &c.db,
                        &c.config,
                    )
                    .await;
                    send_mod_alert(
                        &ctx,
                        &c.config,
                        "Predatory User Banned",
                        &format!("Banned <@{}>", author_id),
                        author_id,
                    )
                    .await;
                }
                return;
            }
            ThreatVerdict::DeleteOnly => {
                let _ = msg.delete(&ctx.http).await;
                send_mod_alert(
                    &ctx,
                    &c.config,
                    "Message Purged (Soft Rule)",
                    &format!(
                        "Purged message from <@{}> for name `{}`",
                        author_id, eval.offending_name
                    ),
                    author_id,
                )
                .await;
                return;
            }
            ThreatVerdict::Safe => {}
        }

        // Author PFP Check
        if let Some(avatar_url) = msg.author.avatar_url() {
            if let Ok(payload) = c.media_inspector.inspect_url(&avatar_url).await {
                if !c.whitelist.is_image_safe(&payload.sha256).await
                    && c.db
                        .is_image_blacklisted(&payload.sha256)
                        .await
                        .unwrap_or(false)
                {
                    let _ = msg.delete(&ctx.http).await;
                    send_mod_alert(
                        &ctx,
                        &c.config,
                        "Message Blocked (NSFW Avatar)",
                        &format!("Blocked <@{}> (holds adult avatar)", author_id),
                        author_id,
                    )
                    .await;
                    send_logs_evidence(
                        &ctx,
                        &c.config,
                        "Blocked NSFW Avatar",
                        &format!("User <@{}> avatar is blacklisted", author_id),
                        author_id,
                        payload.bytes,
                    )
                    .await;
                    return;
                }
            }
        }

        // Message Attachments & Embeds
        inspect_message_media(&ctx, &c, &msg).await;
    }

    async fn interaction_create(&self, ctx: Context, interaction: Interaction) {
        if let Interaction::Command(command) = interaction {
            let c = get_container(&ctx).await;
            handle_slash_command(&ctx, &c, command).await;
        }
    }
}

pub struct BotContainerKey;
impl TypeMapKey for BotContainerKey {
    type Value = Arc<BotContainer>;
}

async fn get_container(ctx: &Context) -> Arc<BotContainer> {
    ctx.data
        .read()
        .await
        .get::<BotContainerKey>()
        .unwrap()
        .clone()
}

async fn handle_join_avatar(
    ctx: &Context,
    c: &BotContainer,
    user_id: u64,
    guild_id: u64,
    url: &str,
    payload: MediaPayload,
) {
    match triage_media(
        &payload,
        user_id,
        guild_id,
        url.to_string(),
        &c.whitelist,
        &c.db,
        &c.scan_queue,
    )
    .await
    {
        Ok(MediaVerdict::BlacklistedNSFW) => {
            tokio::spawn(purge_welcome_channel_on_nsfw_join(
                ctx.http.clone(),
                c.config.clone(),
            ));
            send_mod_alert(
                ctx,
                &c.config,
                "Known Adult Avatar on Join",
                &format!("User <@{}> holds blacklisted avatar", user_id),
                user_id,
            )
            .await;
            send_logs_evidence(
                ctx,
                &c.config,
                "Known Adult Avatar",
                &format!("User <@{}> avatar blacklisted", user_id),
                user_id,
                payload.bytes,
            )
            .await;
        }
        Ok(MediaVerdict::QueuedForInference(rx)) => {
            let ctx_c = ctx.clone();
            let cfg = c.config.clone();
            let db = c.db.clone();
            tokio::spawn(async move {
                if let Ok(Ok(resp)) = rx.await {
                    if resp.confidence.nsfw >= cfg.nsfw_auto_delete_threshold {
                        tokio::spawn(purge_welcome_channel_on_nsfw_join(
                            ctx_c.http.clone(),
                            cfg.clone(),
                        ));
                        let _ = db
                            .record_banned_image(&payload.sha256, payload.dhash, user_id)
                            .await;
                        send_mod_alert(
                            &ctx_c,
                            &cfg,
                            "Adult Avatar Detected",
                            &format!(
                                "User <@{}> avatar flagged ({:.1}%)",
                                user_id, resp.confidence.nsfw
                            ),
                            user_id,
                        )
                        .await;
                        send_logs_evidence(
                            &ctx_c,
                            &cfg,
                            "Adult Avatar Evidence",
                            &format!("User <@{}> avatar flagged", user_id),
                            user_id,
                            payload.bytes,
                        )
                        .await;
                    }
                }
            });
        }
        _ => {}
    }
}

async fn inspect_message_media(ctx: &Context, c: &BotContainer, msg: &Message) {
    let mut urls = Vec::new();
    for att in &msg.attachments {
        if att
            .content_type
            .as_deref()
            .is_some_and(|ct| ct.starts_with("image/"))
        {
            urls.push(att.url.clone());
        }
    }
    for embed in &msg.embeds {
        if let Some(img) = &embed.image {
            urls.push(img.url.clone());
        }
        if let Some(thumb) = &embed.thumbnail {
            urls.push(thumb.url.clone());
        }
    }

    for url in urls {
        if let Ok(payload) = c.media_inspector.inspect_url(&url).await {
            let msg_id = msg.id;
            let ch_id = msg.channel_id;
            let author_id = msg.author.id.get();

            match triage_media(
                &payload,
                author_id,
                c.config.authorized_guild_id,
                url.clone(),
                &c.whitelist,
                &c.db,
                &c.scan_queue,
            )
            .await
            {
                Ok(MediaVerdict::BlacklistedNSFW) => {
                    let _ = ch_id.delete_message(&ctx.http, msg_id).await;
                    send_mod_alert(
                        ctx,
                        &c.config,
                        "NSFW Media Deleted (Cache)",
                        &format!("Purged media from <@{}> in <#{}>", author_id, ch_id.get()),
                        author_id,
                    )
                    .await;
                    send_logs_evidence(
                        ctx,
                        &c.config,
                        "NSFW Media Deleted",
                        &format!("Purged from <@{}>", author_id),
                        author_id,
                        payload.bytes,
                    )
                    .await;
                    return;
                }
                Ok(MediaVerdict::QueuedForInference(rx)) => {
                    let ctx_c = ctx.clone();
                    let cfg = c.config.clone();
                    let db = c.db.clone();
                    tokio::spawn(async move {
                        if let Ok(Ok(resp)) = rx.await {
                            if resp.confidence.nsfw >= cfg.nsfw_auto_delete_threshold {
                                let _ = db
                                    .record_banned_image(&payload.sha256, payload.dhash, author_id)
                                    .await;
                                let _ = ch_id.delete_message(&ctx_c.http, msg_id).await;
                                send_mod_alert(
                                    &ctx_c,
                                    &cfg,
                                    "NSFW Media Deleted",
                                    &format!(
                                        "Purged from <@{}> ({:.1}%)",
                                        author_id, resp.confidence.nsfw
                                    ),
                                    author_id,
                                )
                                .await;
                                send_logs_evidence(
                                    &ctx_c,
                                    &cfg,
                                    "NSFW Media Evidence",
                                    &format!("Flagged from <@{}>", author_id),
                                    author_id,
                                    payload.bytes,
                                )
                                .await;
                            }
                        }
                    });
                }
                _ => {}
            }
        }
    }
}

async fn handle_slash_command(
    ctx: &Context,
    c: &BotContainer,
    cmd: serenity::model::application::CommandInteraction,
) {
    let caller_id = cmd.user.id.get();
    let roles: Vec<u64> = cmd
        .member
        .as_ref()
        .map_or(Vec::new(), |m| m.roles.iter().map(|r| r.get()).collect());

    if !c.config.is_staff(caller_id, &roles) {
        let _ = cmd
            .create_response(
                &ctx.http,
                CreateInteractionResponse::Message(
                    CreateInteractionResponseMessage::new()
                        .content("⛔ **Access Denied:** Staff role required.")
                        .ephemeral(true),
                ),
            )
            .await;
        return;
    }

    match cmd.data.name.as_str() {
        "test-name" => {
            let text = cmd
                .data
                .options
                .iter()
                .find(|o| o.name == "text")
                .and_then(|o| o.value.as_str())
                .unwrap_or("");
            let verdict = c.gatekeeper.evaluate_threat(text);
            let (norm, alpha, deduped) = c.gatekeeper.canonicalize(text);
            let reply = format!("🧪 **Gatekeeper Test:** `{}`\n> **Verdict:** {:?}\n> **Normalized:** `{}`\n> **Alphanumeric:** `{}`\n> **Deduped:** `{}`", text, verdict, norm, alpha, deduped);
            let _ = cmd
                .create_response(
                    &ctx.http,
                    CreateInteractionResponse::Message(
                        CreateInteractionResponseMessage::new().content(reply),
                    ),
                )
                .await;
        }
        "whitelist-user" => {
            let mut target_id = 0u64;
            let mut target_name = String::new();
            let mut reason = "Staff Override".to_string();
            for opt in &cmd.data.options {
                if opt.name == "user" {
                    if let CommandDataOptionValue::User(uid) = &opt.value {
                        target_id = uid.get();
                        if let Some(u) = cmd.data.resolved.users.get(uid) {
                            target_name = u.name.clone();
                        }
                    }
                } else if opt.name == "reason" {
                    if let CommandDataOptionValue::String(r) = &opt.value {
                        reason = r.clone();
                    }
                }
            }
            if target_id != 0 {
                let _ =
                    c.db.add_whitelisted_user(&target_name, &cmd.user.name, &reason)
                        .await;
                let _ =
                    c.db.add_whitelisted_user(&target_id.to_string(), &cmd.user.name, &reason)
                        .await;
                c.whitelist.add_user(&target_name).await;
                c.whitelist.add_user(&target_id.to_string()).await;
                let reply = format!(
                    "✅ Whitelisted <@{}> (`{}`) by **{}** (Reason: `{}`).",
                    target_id, target_name, cmd.user.name, reason
                );
                let _ = cmd
                    .create_response(
                        &ctx.http,
                        CreateInteractionResponse::Message(
                            CreateInteractionResponseMessage::new().content(reply),
                        ),
                    )
                    .await;
            }
        }
        "db-stats" => {
            let reply = match c.db.get_storage_stats().await {
                Ok((used, max)) => {
                    let u_mb = used as f64 / (1024.0 * 1024.0);
                    let m_mb = max as f64 / (1024.0 * 1024.0);
                    format!("📊 **MongoDB Atlas M0 Storage:** `{:.2} MB` / `{:.0} MB` (Remaining: `{:.2} MB`)", u_mb, m_mb, m_mb - u_mb)
                }
                Err(e) => format!("❌ Failed: {}", e),
            };
            let _ = cmd
                .create_response(
                    &ctx.http,
                    CreateInteractionResponse::Message(
                        CreateInteractionResponseMessage::new().content(reply),
                    ),
                )
                .await;
        }
        _ => {
            let _ = cmd
                .create_response(
                    &ctx.http,
                    CreateInteractionResponse::Message(
                        CreateInteractionResponseMessage::new().content("Command acknowledged."),
                    ),
                )
                .await;
        }
    }
}

pub async fn execute_ban(
    http: &serenity::http::Http,
    guild_id: GuildId,
    user_id: u64,
    reason: &str,
    confidence: f64,
    db: &DatabaseEngine,
    config: &GuildConfig,
) {
    if config.is_owner(user_id) {
        warn!(
            "🛡️ [SOVEREIGN IMMUNITY] Refusing ban against Architect ({}).",
            user_id
        );
        return;
    }
    let user = UserId::new(user_id);
    if let Ok(()) = guild_id.ban_with_reason(http, user, 7, reason).await {
        info!(
            "Banned user {} from Guild {}. Reason: {}",
            user_id, guild_id, reason
        );
        let _ = db
            .record_audit(AuditLogEntry {
                user_id,
                username: format!("<@{}>", user_id),
                reason: reason.to_string(),
                confidence,
                matched_rule: reason.to_string(),
                timestamp: mongodb::bson::DateTime::now(),
            })
            .await;
    }
}
