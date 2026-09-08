use serenity::async_trait;
use serenity::builder::{CreateAttachment, CreateEmbed, CreateMessage};
use serenity::model::channel::Message;
use serenity::model::gateway::Ready;
use serenity::model::guild::{Guild, Member};
use serenity::model::id::{ChannelId, GuildId, UserId};
use serenity::prelude::*;
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::crypto::CryptoEngine;
use crate::db::{AuditLogEntry, DatabaseEngine};
use crate::gatekeeper::TextGatekeeper;
use crate::plugin_engine::DynamicPluginEngine;
use crate::queue::{BoundedScanQueue, ScanTask};
use crate::Result;

// =========================================================================
// AUTHORIZED BOUNDARY CONSTANTS
// =========================================================================
const AUTHORIZED_GUILD_ID: u64 = 1385636051330142369; // Strictly "The Chill Zone"
const MOD_CHANNEL_ID: u64 = 1424824152417767628; // Clean text alerts (Moderators)
const LOGS_CHANNEL_ID: u64 = 1492554211118809319; // Verbose evidence logs with images (Architect)
const OWNER_USER_ID: u64 = 1015600709724557434;

// Classification Threshold on 0.0 - 100.0 scale
const NSFW_AUTO_DELETE_THRESHOLD: f64 = 70.0;

pub struct BotContainer {
    pub gatekeeper: Arc<TextGatekeeper>,
    pub db: Arc<DatabaseEngine>,
    pub scan_queue: Arc<BoundedScanQueue>,
    pub plugin_engine: Arc<DynamicPluginEngine>,
    pub http_client: reqwest::Client,
}

pub struct Handler;

#[async_trait]
impl EventHandler for Handler {
    async fn ready(&self, _: Context, ready: Ready) {
        info!(
            "Sebastian The Butler is Online & Vigilant! Operating exclusively for Guild: {}",
            AUTHORIZED_GUILD_ID
        );
    }

    /// Auto-Eviction: Leaves any unauthorized server immediately
    async fn guild_create(&self, ctx: Context, guild: Guild, _is_new: Option<bool>) {
        if guild.id.get() != AUTHORIZED_GUILD_ID {
            warn!(
                "🚨 [UNAUTHORIZED SERVER] Bot was added to '{}' (ID: {}). Auto-evicting immediately.",
                guild.name, guild.id
            );
            let _ = guild.leave(&ctx.http).await;
        }
    }

    /// On Member Join: Strictly enforced on AUTHORIZED_GUILD_ID
    async fn guild_member_addition(&self, ctx: Context, member: Member) {
        // Enforce Server Whitelist
        if member.guild_id.get() != AUTHORIZED_GUILD_ID {
            return;
        }

        let container = {
            let data = ctx.data.read().await;
            data.get::<BotContainerKey>()
                .expect("Container initialized")
                .clone()
        };

        let username = &member.user.name;
        let display_name = member.display_name().to_string();
        let user_id = member.user.id.get();
        let guild_id = member.guild_id;

        info!("👤 [JOIN EVENT] Inspecting: {} (ID: {})", username, user_id);

        // 1. Predatory Username Gatekeeper (ONLY trigger that issues a ban)
        if container.gatekeeper.is_flagged(username)
            || container.gatekeeper.is_flagged(&display_name)
        {
            warn!(
                "🚨 [GATEKEEPER] PREDATORY USERNAME DETECTED: {} ({}). Eradicating account.",
                username, user_id
            );
            execute_ban(
                &ctx.http,
                guild_id,
                user_id,
                "Zero-Tolerance Predatory Username Match",
                1.0,
                &container.db,
            )
            .await;
            send_mod_alert(
                &ctx,
                "Predatory Username Banned",
                &format!(
                    "User <@{}> was banned for predatory username `{}`",
                    user_id, username
                ),
                user_id,
            )
            .await;
            return;
        }

        // 2. Avatar Scan on Join
        if let Some(avatar_url) = member.user.avatar_url() {
            info!(
                "🖼️ [JOIN AVATAR] Scanning PFP for user {}: {}",
                user_id, avatar_url
            );
            if let Ok(bytes) = download_image(&container.http_client, &avatar_url).await {
                let sha256 = CryptoEngine::sha256(&bytes);

                // Check MongoDB Hash Cache
                if let Ok(true) = container.db.is_image_blacklisted(&sha256).await {
                    warn!(
                        "🚨 [HASH CACHE] User {} joined with blacklisted NSFW avatar!",
                        user_id
                    );
                    send_mod_alert(
                        &ctx,
                        "Known Adult/NSFW Avatar Detected",
                        &format!(
                            "User <@{}> joined with an avatar matching a known blacklisted hash.",
                            user_id
                        ),
                        user_id,
                    )
                    .await;
                    send_logs_evidence(
                        &ctx,
                        "Known Adult/NSFW Avatar Detected",
                        &format!(
                            "User <@{}> joined with a known blacklisted avatar.",
                            user_id
                        ),
                        user_id,
                        bytes,
                    )
                    .await;
                    return;
                }

                // Dispatch to classifier queue
                let (tx, rx) = tokio::sync::oneshot::channel();
                let task = ScanTask {
                    user_id,
                    guild_id: guild_id.get(),
                    image_url: avatar_url,
                    image_bytes: bytes.clone(),
                    response_tx: tx,
                };

                if let Ok(()) = container.scan_queue.submit(task).await {
                    let ctx_clone = ctx.clone();
                    let db = container.db.clone();
                    let bytes_clone = bytes.clone();
                    tokio::spawn(async move {
                        if let Ok(Ok(resp)) = rx.await {
                            if resp.confidence.nsfw >= NSFW_AUTO_DELETE_THRESHOLD {
                                warn!(
                                    "🚨 [JOIN AVATAR NSFW] Flagged! Conf: {:.1}%",
                                    resp.confidence.nsfw
                                );
                                let _ = db.record_banned_image(&sha256, 0, user_id).await;
                                send_mod_alert(
                                    &ctx_clone,
                                    "Adult/NSFW Join Avatar Detected",
                                    &format!("User <@{}> joined with an adult PFP (Confidence: {:.1}%). No ban issued.", user_id, resp.confidence.nsfw),
                                    user_id,
                                ).await;
                                send_logs_evidence(
                                    &ctx_clone,
                                    "Adult/NSFW Join Avatar Detected",
                                    &format!("User <@{}> joined with an adult PFP (Confidence: {:.1}%). Verify evidence below.", user_id, resp.confidence.nsfw),
                                    user_id,
                                    bytes_clone,
                                ).await;
                            } else {
                                info!(
                                    "✅ [JOIN AVATAR SAFE] User {} avatar is SAFE (Conf: {:.1}%)",
                                    user_id, resp.confidence.safe
                                );
                            }
                        }
                    });
                }
            }
        }
    }

    /// On Message: Strictly enforced on AUTHORIZED_GUILD_ID
    async fn message(&self, ctx: Context, msg: Message) {
        // 1. Prevent bot from responding to its own messages
        if msg.author.id == ctx.cache.current_user().id {
            return;
        }

        // 2. Strict Boundary Enforcement: Ignore DMs and unauthorized servers
        if msg.guild_id != Some(GuildId::new(AUTHORIZED_GUILD_ID)) {
            return;
        }

        let container = {
            let data = ctx.data.read().await;
            data.get::<BotContainerKey>()
                .expect("Container initialized")
                .clone()
        };

        let author_id = msg.author.id.get();
        let channel_id = msg.channel_id;

        // =========================================================================
        // LAB DIAGNOSTIC: $test-name <text> (Safe testing: no bans)
        // =========================================================================
        if let Some(target_text) = msg.content.strip_prefix("$test-name ") {
            let is_flagged = container.gatekeeper.is_flagged(target_text);
            let (norm, alpha, deduped) = container.gatekeeper.canonicalize(target_text);
            let response = format!(
                "🧪 **Gatekeeper Lab Test**\n\
                > **Input Text:** `{}`\n\
                > **Verdict:** {}\n\
                > **Normalized Form:** `{}`\n\
                > **Alphanumeric Projection:** `{}`\n\
                > **Deduplicated Projection:** `{}`",
                target_text,
                if is_flagged {
                    "🚨 **FLAGGED (Would Trigger Instant Ban)**"
                } else {
                    "✅ **SAFE (Clean Pass)**"
                },
                norm,
                alpha,
                deduped
            );
            let _ = msg.channel_id.say(&ctx.http, response).await;
            return;
        }

        // =========================================================================
        // LAB DIAGNOSTIC: $test-pfp [@user or attachment] (Safe classifier test)
        // =========================================================================
        if msg.content.starts_with("$test-pfp") {
            let target_avatar = if let Some(user) = msg.mentions.first() {
                user.avatar_url()
            } else if let Some(att) = msg.attachments.first() {
                Some(att.url.clone())
            } else {
                msg.author.avatar_url()
            };

            if let Some(url) = target_avatar {
                let _ = msg
                    .channel_id
                    .say(
                        &ctx.http,
                        format!("🔍 Fetching and analyzing avatar: {}", url),
                    )
                    .await;

                if let Ok(bytes) = download_image(&container.http_client, &url).await {
                    let sha256 = CryptoEngine::sha256(&bytes);
                    let is_cached = container
                        .db
                        .is_image_blacklisted(&sha256)
                        .await
                        .unwrap_or(false);

                    let (tx, rx) = tokio::sync::oneshot::channel();
                    let task = ScanTask {
                        user_id: author_id,
                        guild_id: msg.guild_id.map(|g| g.get()).unwrap_or(0),
                        image_url: url.clone(),
                        image_bytes: bytes,
                        response_tx: tx,
                    };

                    if let Ok(()) = container.scan_queue.submit(task).await {
                        if let Ok(Ok(resp)) = rx.await {
                            let result_text = format!(
                                "🧪 **Avatar ViT Classifier Test**\n\
                                > **Target URL:** {}\n\
                                > **SHA-256:** `{}` (Known Banned Cache: `{}`)\n\
                                > **Verdict:** {}\n\
                                > **Confidence:** Safe: `{:.1}%` | NSFW: `{:.1}%`\n\
                                > **Inference Latency:** `{}`",
                                url,
                                sha256,
                                is_cached,
                                if resp.confidence.nsfw >= NSFW_AUTO_DELETE_THRESHOLD {
                                    "🚨 **NSFW (Violates Threshold)**"
                                } else {
                                    "✅ **SAFE**"
                                },
                                resp.confidence.safe,
                                resp.confidence.nsfw,
                                resp.processing_time
                            );
                            let _ = msg.channel_id.say(&ctx.http, result_text).await;
                            return;
                        }
                    }
                }
            } else {
                let _ = msg
                    .channel_id
                    .say(&ctx.http, "❌ Target user has no custom avatar set.")
                    .await;
                return;
            }
        }

        info!(
            "📥 [MSG] #{} | Author: {} (Bot: {}) | Attachments: {} | Embeds: {}",
            channel_id.get(),
            msg.author.name,
            msg.author.bot,
            msg.attachments.len(),
            msg.embeds.len()
        );

        // 1. Dynamic Nickname AND Username Gatekeeper (Strict Ban)
        let username = &msg.author.name;
        let nickname = msg
            .member
            .as_ref()
            .and_then(|m| m.nick.as_deref())
            .unwrap_or("");

        let is_predatory =
            container.gatekeeper.is_flagged(username) || container.gatekeeper.is_flagged(nickname);

        if is_predatory {
            let offending_name = if container.gatekeeper.is_flagged(nickname) {
                nickname
            } else {
                username
            };

            warn!(
                "🚨 [GATEKEEPER] Banning sender {} for predatory name/nick: '{}'.",
                author_id, offending_name
            );
            let _ = msg.delete(&ctx.http).await;
            if let Some(guild_id) = msg.guild_id {
                execute_ban(
                    &ctx.http,
                    guild_id,
                    author_id,
                    &format!("Predatory Name Match: {}", offending_name),
                    1.0,
                    &container.db,
                )
                .await;
                send_mod_alert(
                    &ctx,
                    "Predatory User Banned on Message",
                    &format!(
                        "Banned <@{}> for predatory name/nick `{}`",
                        author_id, offending_name
                    ),
                    author_id,
                )
                .await;
            }
            return;
        }

        // =========================================================================
        // 2. AUTHOR PFP SENTRY: Silence anyone speaking with an adult avatar
        // =========================================================================
        if let Some(avatar_url) = msg.author.avatar_url() {
            if let Ok(bytes) = download_image(&container.http_client, &avatar_url).await {
                let sha256 = CryptoEngine::sha256(&bytes);

                // Fast Cache Check: If their avatar is already blacklisted in Atlas
                if let Ok(true) = container.db.is_image_blacklisted(&sha256).await {
                    warn!(
                        "🚨 [MUTED] Deleting message from {} due to blacklisted adult avatar.",
                        author_id
                    );
                    let _ = msg.delete(&ctx.http).await;
                    send_mod_alert(
                        &ctx,
                        "Message Blocked: User Has NSFW Avatar",
                        &format!(
                            "User <@{}> attempted to send a message in <#{}>, but holds a blacklisted adult avatar. Message was deleted.",
                            author_id, channel_id.get()
                        ),
                        author_id,
                    ).await;
                    send_logs_evidence(
                        &ctx,
                        "Message Blocked: User Has NSFW Avatar",
                        &format!(
                            "Blocked message from <@{}> in <#{}>. User holds a blacklisted avatar.",
                            author_id,
                            channel_id.get()
                        ),
                        author_id,
                        bytes,
                    )
                    .await;
                    return; // Message deleted; halt execution
                }
            }
        }

        // 3. Collect image URLs from attachments AND third-party bot embeds
        let mut image_urls = Vec::new();

        for attachment in &msg.attachments {
            if let Some(ct) = &attachment.content_type {
                if ct.starts_with("image/") {
                    image_urls.push((attachment.url.clone(), "attachment"));
                }
            }
        }

        for embed in &msg.embeds {
            if let Some(img) = &embed.image {
                image_urls.push((img.url.clone(), "embed_image"));
            }
            if let Some(thumbnail) = &embed.thumbnail {
                image_urls.push((thumbnail.url.clone(), "embed_thumbnail"));
            }
        }

        // 4. Inspect every image through the SFW classifier pipeline
        for (url, source) in image_urls {
            info!(
                "🔍 [INSPECT] Scanning {} from {}: {}",
                source, msg.author.name, url
            );

            if let Ok(bytes) = download_image(&container.http_client, &url).await {
                let sha256 = CryptoEngine::sha256(&bytes);

                // Sub-millisecond Hash Cache Check
                if let Ok(true) = container.db.is_image_blacklisted(&sha256).await {
                    warn!("🚨 [CACHE HIT] Known NSFW image found! Deleting message instantly.");
                    let _ = msg.delete(&ctx.http).await;
                    send_mod_alert(
                        &ctx,
                        "NSFW Message/Embed Deleted",
                        &format!(
                            "Deleted message containing known NSFW media posted in <#{}> by <@{}>. User not banned.",
                            channel_id.get(),
                            author_id
                        ),
                        author_id,
                    ).await;
                    send_logs_evidence(
                        &ctx,
                        "NSFW Message/Embed Deleted (Cache Hit)",
                        &format!(
                            "Deleted message containing known NSFW media in <#{}> by <@{}>.",
                            channel_id.get(),
                            author_id
                        ),
                        author_id,
                        bytes,
                    )
                    .await;
                    return;
                }

                // Dispatch to sequential queue
                let (tx, rx) = tokio::sync::oneshot::channel();
                let task = ScanTask {
                    user_id: author_id,
                    guild_id: msg.guild_id.map(|g| g.get()).unwrap_or(0),
                    image_url: url.clone(),
                    image_bytes: bytes.clone(),
                    response_tx: tx,
                };

                if let Ok(()) = container.scan_queue.submit(task).await {
                    let ctx_clone = ctx.clone();
                    let db = container.db.clone();
                    let msg_id = msg.id;
                    let bytes_clone = bytes.clone();

                    tokio::spawn(async move {
                        if let Ok(Ok(resp)) = rx.await {
                            if resp.confidence.nsfw >= NSFW_AUTO_DELETE_THRESHOLD {
                                warn!(
                                    "🚨 [VERDICT NSFW] {} flagged! (NSFW Conf: {:.1}%, Time: {}). Deleting message.",
                                    source, resp.confidence.nsfw, resp.processing_time
                                );
                                let _ = db.record_banned_image(&sha256, 0, author_id).await;
                                let _ = channel_id.delete_message(&ctx_clone.http, msg_id).await;

                                // Tier 1: Clean notification to Moderator Channel
                                send_mod_alert(
                                    &ctx_clone,
                                    "NSFW Image Deleted",
                                    &format!("Deleted adult image in <#{}> posted by <@{}> (Confidence: {:.1}%). User was not banned.", channel_id.get(), author_id, resp.confidence.nsfw),
                                    author_id,
                                ).await;

                                // Tier 2: Full evidence to Logs Channel WITH image attached
                                send_logs_evidence(
                                    &ctx_clone,
                                    "NSFW Image Deleted",
                                    &format!("Deleted adult image in <#{}> posted by <@{}> (Confidence: {:.1}%). Verify evidence below.", channel_id.get(), author_id, resp.confidence.nsfw),
                                    author_id,
                                    bytes_clone,
                                ).await;
                            } else {
                                info!(
                                    "✅ [VERDICT SAFE] {} is SAFE (Confidence: {:.1}%, Time: {})",
                                    source, resp.confidence.safe, resp.processing_time
                                );
                            }
                        }
                    });
                }
            }
        }
    }
}

pub struct BotContainerKey;
impl TypeMapKey for BotContainerKey {
    type Value = Arc<BotContainer>;
}

/// Tier 1 Alert: Dispatches clean, text-only embed to Moderator Channel (NO explicit images shown)
async fn send_mod_alert(ctx: &Context, title: &str, description: &str, offender_id: u64) {
    let channel = ChannelId::new(MOD_CHANNEL_ID);
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
        .content(format!("<@{}> ⚠️ **MODERATION NOTICE**", OWNER_USER_ID))
        .embed(embed);

    if let Err(e) = channel.send_message(&ctx.http, msg).await {
        error!(
            "Failed sending mod alert to channel {}: {}",
            MOD_CHANNEL_ID, e
        );
    }
}

/// Tier 2 Alert: Dispatches full evidence embed WITH the downloaded image attached to Logs Channel (1492554211118809319)
async fn send_logs_evidence(
    ctx: &Context,
    title: &str,
    description: &str,
    offender_id: u64,
    image_bytes: Vec<u8>,
) {
    let channel = ChannelId::new(LOGS_CHANNEL_ID);
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
        .content(format!("<@{}> 📋 **EVIDENCE AUDIT**", OWNER_USER_ID))
        .embed(embed)
        .add_file(attachment);

    if let Err(e) = channel.send_message(&ctx.http, msg).await {
        error!(
            "Failed sending evidence log to channel {}: {}",
            LOGS_CHANNEL_ID, e
        );
    }
}

async fn execute_ban(
    http: &serenity::http::Http,
    guild_id: GuildId,
    user_id: u64,
    reason: &str,
    confidence: f64,
    db: &DatabaseEngine,
) {
    let user = UserId::new(user_id);
    let result = guild_id.ban_with_reason(http, user, 7, reason).await;

    if let Err(e) = result {
        error!("Failed to ban user {}: {}", user_id, e);
    } else {
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

async fn download_image(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    let resp = client.get(url).send().await?;
    let bytes = resp.bytes().await?;
    Ok(bytes.to_vec())
}
