use serenity::async_trait;
use serenity::builder::{
    CreateAttachment, CreateCommand, CreateCommandOption, CreateEmbed, CreateInteractionResponse,
    CreateInteractionResponseMessage, CreateMessage, GetMessages,
};
use serenity::model::application::{CommandDataOptionValue, CommandOptionType, Interaction};
use serenity::model::channel::Message;
use serenity::model::gateway::Ready;
use serenity::model::guild::{Guild, Member};
use serenity::model::id::{ChannelId, GuildId, UserId};
use serenity::prelude::*;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::crypto::CryptoEngine;
use crate::db::{AuditLogEntry, DatabaseEngine};
use crate::gatekeeper::{TextGatekeeper, ThreatVerdict};
use crate::plugin_engine::DynamicPluginEngine;
use crate::queue::{BoundedScanQueue, ScanTask};
use crate::Result;

// =========================================================================
// BOUNDARY, CHANNEL & ROLE RBAC CONSTANTS
// =========================================================================
const AUTHORIZED_GUILD_ID: u64 = 1385636051330142369; // "The Chill Zone"
const WELCOME_CHANNEL_ID: u64 = 1385636052374520014; // Welcome Channel
const MOD_CHANNEL_ID: u64 = 1424824152417767628; // Clean text alerts (Moderators)
const LOGS_CHANNEL_ID: u64 = 1492554211118809319; // Evidence logs with image files (Architect)
const OWNER_USER_ID: u64 = 1015600709724557434;

// Discord Role RBAC IDs specified by Architect
const ADMIN_ROLE_ID: u64 = 1491379177180626974;
const MODERATOR_ROLE_ID: u64 = 1492192888426201351;

// Classification Threshold on 0.0 - 100.0 scale
const NSFW_AUTO_DELETE_THRESHOLD: f64 = 70.0;

pub struct BotContainer {
    pub gatekeeper: Arc<TextGatekeeper>,
    pub db: Arc<DatabaseEngine>,
    pub scan_queue: Arc<BoundedScanQueue>,
    pub plugin_engine: Arc<DynamicPluginEngine>,
    pub http_client: reqwest::Client,
    pub whitelisted_users: Arc<RwLock<HashSet<String>>>, // Lowercase usernames & user IDs
    pub whitelisted_images: Arc<RwLock<HashSet<String>>>, // Safe SHA-256 hashes
}

pub struct Handler;

#[async_trait]
impl EventHandler for Handler {
    /// Discord Gateway Ready: Registers Guild Slash Commands Instantly (<1 second)
    async fn ready(&self, ctx: Context, _ready: Ready) {
        info!(
            "Sebastian The Butler is Online & Vigilant! Registering Slash Commands for Guild: {}",
            AUTHORIZED_GUILD_ID
        );

        let guild_id = GuildId::new(AUTHORIZED_GUILD_ID);

        let commands = vec![
            CreateCommand::new("test-name")
                .description("Test any username or text string against the Gatekeeper")
                .add_option(
                    CreateCommandOption::new(
                        CommandOptionType::String,
                        "text",
                        "The username or text to evaluate",
                    )
                    .required(true),
                ),
            CreateCommand::new("test-pfp")
                .description("Analyze a user's avatar or image through the ViT classifier")
                .add_option(
                    CreateCommandOption::new(
                        CommandOptionType::User,
                        "user",
                        "Target user whose avatar to analyze",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        CommandOptionType::Attachment,
                        "image",
                        "Upload an image file to analyze",
                    )
                    .required(false),
                ),
            CreateCommand::new("whitelist-user")
                .description("Whitelist a user to bypass Tier 2 soft filters (e.g. 'link' in name)")
                .add_option(
                    CreateCommandOption::new(
                        CommandOptionType::User,
                        "user",
                        "The user to whitelist",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        CommandOptionType::String,
                        "reason",
                        "Reason for whitelisting (e.g. Steam game dev)",
                    )
                    .required(false),
                ),
            CreateCommand::new("whitelist-pfp")
                .description("Whitelist a user's current avatar as verified safe in MongoDB")
                .add_option(
                    CreateCommandOption::new(
                        CommandOptionType::User,
                        "user",
                        "Target user whose avatar to mark safe",
                    )
                    .required(true),
                ),
            CreateCommand::new("db-stats")
                .description("Query MongoDB Atlas cloud storage usage metrics"),
        ];

        if let Err(e) = guild_id.set_commands(&ctx.http, commands).await {
            error!("Failed setting guild slash commands: {}", e);
        } else {
            info!("✅ Guild Slash Commands successfully registered on 'The Chill Zone'!");
        }
    }

    /// Slash Command Router with Discord RBAC (Admin/Mod/Owner Verification)
    async fn interaction_create(&self, ctx: Context, interaction: Interaction) {
        if let Interaction::Command(command) = interaction {
            let container = {
                let data = ctx.data.read().await;
                data.get::<BotContainerKey>()
                    .expect("Container initialized")
                    .clone()
            };

            let caller_id = command.user.id.get();
            let is_authorized = caller_id == OWNER_USER_ID
                || command.member.as_ref().map_or(false, |m| {
                    m.roles
                        .iter()
                        .any(|r| r.get() == ADMIN_ROLE_ID || r.get() == MODERATOR_ROLE_ID)
                });

            // RBAC Guard
            if !is_authorized {
                let response = CreateInteractionResponse::Message(
                    CreateInteractionResponseMessage::new()
                        .content("⛔ **Access Denied:** You require the **Moderator** or **Admin** role to use this command.")
                        .ephemeral(true)
                );
                let _ = command.create_response(&ctx.http, response).await;
                return;
            }

            // Route Commands
            match command.data.name.as_str() {
                "test-name" => {
                    let text = command
                        .data
                        .options
                        .iter()
                        .find(|opt| opt.name == "text")
                        .and_then(|opt| opt.value.as_str())
                        .unwrap_or("");

                    let verdict = container.gatekeeper.evaluate_threat(text);
                    let (norm, alpha, deduped) = container.gatekeeper.canonicalize(text);

                    let verdict_str = match verdict {
                        ThreatVerdict::InstantBan => {
                            "🚨 **FLAGGED (Instant Ban - Predator / Hardcoded)**"
                        }
                        ThreatVerdict::DeleteOnly => {
                            "⚠️ **SOFT FLAGGED (Delete Message Only - No Ban)**"
                        }
                        ThreatVerdict::Safe => "✅ **SAFE (Clean Pass)**",
                    };

                    let reply = format!(
                        "🧪 **Gatekeeper Lab Test**\n\
                        > **Input Text:** `{}`\n\
                        > **Verdict:** {}\n\
                        > **Normalized Form:** `{}`\n\
                        > **Alphanumeric Projection:** `{}`\n\
                        > **Deduplicated Projection:** `{}`",
                        text, verdict_str, norm, alpha, deduped
                    );

                    let response = CreateInteractionResponse::Message(
                        CreateInteractionResponseMessage::new().content(reply),
                    );
                    let _ = command.create_response(&ctx.http, response).await;
                }

                "test-pfp" => {
                    let _ = command.defer(&ctx.http).await;

                    let mut target_avatar = None;

                    // Check if attachment option was passed
                    for opt in &command.data.options {
                        if opt.name == "image" {
                            if let CommandDataOptionValue::Attachment(att_id) = &opt.value {
                                if let Some(att) = command.data.resolved.attachments.get(att_id) {
                                    target_avatar = Some(att.url.clone());
                                }
                            }
                        } else if opt.name == "user" {
                            if let CommandDataOptionValue::User(user_id) = &opt.value {
                                if let Some(user) = command.data.resolved.users.get(user_id) {
                                    target_avatar = user.avatar_url();
                                }
                            }
                        }
                    }

                    if target_avatar.is_none() {
                        target_avatar = command.user.avatar_url();
                    }

                    if let Some(url) = target_avatar {
                        if let Ok(bytes) = download_image(&container.http_client, &url).await {
                            let sha256 = CryptoEngine::sha256(&bytes);
                            let is_whitelisted =
                                container.whitelisted_images.read().await.contains(&sha256);
                            let is_blacklisted = container
                                .db
                                .is_image_blacklisted(&sha256)
                                .await
                                .unwrap_or(false);

                            let (tx, rx) = tokio::sync::oneshot::channel();
                            let task = ScanTask {
                                user_id: caller_id,
                                guild_id: AUTHORIZED_GUILD_ID,
                                image_url: url.clone(),
                                image_bytes: bytes,
                                response_tx: tx,
                            };

                            if let Ok(()) = container.scan_queue.submit(task).await {
                                if let Ok(Ok(resp)) = rx.await {
                                    let verdict_str = if is_whitelisted {
                                        "🟢 **VERIFIED SAFE (Whitelisted Hash)**"
                                    } else if resp.confidence.nsfw >= NSFW_AUTO_DELETE_THRESHOLD
                                        || is_blacklisted
                                    {
                                        "🚨 **NSFW (Violates Threshold / Blacklisted)**"
                                    } else {
                                        "✅ **SAFE**"
                                    };

                                    let result_text = format!(
                                        "🧪 **Avatar ViT Classifier Test**\n\
                                        > **Target URL:** {}\n\
                                        > **SHA-256:** `{}`\n\
                                        > **Cache Status:** Whitelisted: `{}` | Blacklisted: `{}`\n\
                                        > **Verdict:** {}\n\
                                        > **Confidence:** Safe: `{:.1}%` | NSFW: `{:.1}%`\n\
                                        > **Inference Latency:** `{}`",
                                        url,
                                        sha256,
                                        is_whitelisted,
                                        is_blacklisted,
                                        verdict_str,
                                        resp.confidence.safe,
                                        resp.confidence.nsfw,
                                        resp.processing_time
                                    );

                                    let _ = command
                                        .edit_response(
                                            &ctx.http,
                                            serenity::builder::EditInteractionResponse::new()
                                                .content(result_text),
                                        )
                                        .await;
                                    return;
                                }
                            }
                        }
                    }
                    let _ = command
                        .edit_response(
                            &ctx.http,
                            serenity::builder::EditInteractionResponse::new()
                                .content("❌ Failed fetching target avatar/image."),
                        )
                        .await;
                }

                "whitelist-user" => {
                    let mut target_id = 0u64;
                    let mut target_name = String::new();
                    let mut reason = "Moderator Whitelist Override".to_string();

                    for opt in &command.data.options {
                        if opt.name == "user" {
                            if let CommandDataOptionValue::User(uid) = &opt.value {
                                target_id = uid.get();
                                if let Some(user) = command.data.resolved.users.get(uid) {
                                    target_name = user.name.clone();
                                }
                            }
                        } else if opt.name == "reason" {
                            if let CommandDataOptionValue::String(r) = &opt.value {
                                reason = r.clone();
                            }
                        }
                    }

                    if target_id != 0 {
                        let _ = container
                            .db
                            .add_whitelisted_user(&target_name, &command.user.name, &reason)
                            .await;
                        let _ = container
                            .db
                            .add_whitelisted_user(
                                &target_id.to_string(),
                                &command.user.name,
                                &reason,
                            )
                            .await;

                        // Sync in-memory RAM cache
                        {
                            let mut guard = container.whitelisted_users.write().await;
                            guard.insert(target_name.to_lowercase());
                            guard.insert(target_id.to_string());
                        }

                        let reply = format!("✅ **User Whitelisted:** <@{}> (`{}`) is now whitelisted by **{}**.\n> **Reason:** `{}`\n*Tier 2 soft filters (such as 'link' in display name) are now bypassed for this user.*", target_id, target_name, command.user.name, reason);
                        let response = CreateInteractionResponse::Message(
                            CreateInteractionResponseMessage::new().content(reply),
                        );
                        let _ = command.create_response(&ctx.http, response).await;
                    }
                }

                "whitelist-pfp" => {
                    let mut target_id = 0u64;
                    let mut target_name = String::new();
                    let mut avatar_url_opt = None;

                    for opt in &command.data.options {
                        if opt.name == "user" {
                            if let CommandDataOptionValue::User(uid) = &opt.value {
                                target_id = uid.get();
                                if let Some(user) = command.data.resolved.users.get(uid) {
                                    target_name = user.name.clone();
                                    avatar_url_opt = user.avatar_url();
                                }
                            }
                        }
                    }

                    if let Some(url) = avatar_url_opt {
                        if let Ok(bytes) = download_image(&container.http_client, &url).await {
                            let sha256 = CryptoEngine::sha256(&bytes);
                            let label = format!("PFP Whitelist: @{}", target_name);
                            let _ = container
                                .db
                                .add_whitelisted_image(&sha256, &label, &command.user.name)
                                .await;

                            // Sync in-memory RAM cache
                            container
                                .whitelisted_images
                                .write()
                                .await
                                .insert(sha256.clone());

                            let reply = format!("✅ **Avatar Whitelisted:** Avatar for <@{}> is now marked **Verified Safe**.\n> **SHA-256:** `{}`\n*This image will permanently skip AI classification and message deletions.*", target_id, sha256);
                            let response = CreateInteractionResponse::Message(
                                CreateInteractionResponseMessage::new().content(reply),
                            );
                            let _ = command.create_response(&ctx.http, response).await;
                            return;
                        }
                    }
                    let response = CreateInteractionResponse::Message(
                        CreateInteractionResponseMessage::new()
                            .content("❌ Target user has no custom avatar set to whitelist."),
                    );
                    let _ = command.create_response(&ctx.http, response).await;
                }

                "db-stats" => {
                    let reply = match container.db.get_storage_stats().await {
                        Ok((used_bytes, max_bytes)) => {
                            let used_mb = used_bytes as f64 / (1024.0 * 1024.0);
                            let max_mb = max_bytes as f64 / (1024.0 * 1024.0);
                            let free_mb = max_mb - used_mb;
                            let free_pct = ((free_mb / max_mb) * 100.0) as i32;

                            format!(
                                "📊 **MongoDB Atlas M0 Cloud Storage Audit**\n\
                                > **Used Storage:** `{:.2} MB` / `{:.0} MB` ({:.1}% used)\n\
                                > **Remaining Space:** `{:.2} MB` (`{}% free`)\n\
                                > **Health Status:** 🟢 Optimal Operating Range\n\
                                ```[ {}{} ] {}% Free```",
                                used_mb,
                                max_mb,
                                100.0 - (free_pct as f64),
                                free_mb,
                                free_pct,
                                "█".repeat((free_pct / 5) as usize),
                                "░".repeat((20 - (free_pct / 5)).max(0) as usize),
                                free_pct
                            )
                        }
                        Err(e) => format!("❌ Failed querying MongoDB Atlas dbStats: {}", e),
                    };

                    let response = CreateInteractionResponse::Message(
                        CreateInteractionResponseMessage::new().content(reply),
                    );
                    let _ = command.create_response(&ctx.http, response).await;
                }

                _ => {}
            }
        }
    }

    /// Auto-Eviction: Leaves any unauthorized server immediately
    async fn guild_create(&self, ctx: Context, guild: Guild, _is_new: Option<bool>) {
        if guild.id.get() != AUTHORIZED_GUILD_ID {
            warn!(
                "🚨 [UNAUTHORIZED SERVER] Bot was added to '{}' (ID: {}). Auto-evicting.",
                guild.name, guild.id
            );
            let _ = guild.leave(&ctx.http).await;
        }
    }

    /// On Member Join
    async fn guild_member_addition(&self, ctx: Context, member: Member) {
        if member.guild_id.get() != AUTHORIZED_GUILD_ID {
            return;
        }

        let container = {
            let data = ctx.data.read().await;
            data.get::<BotContainerKey>()
                .expect("Container initialized")
                .clone()
        };

        let user_id = member.user.id.get();
        let guild_id = member.guild_id;

        // 3-Vector Name Inspection on Join
        let username = &member.user.name;
        let global_name = member.user.global_name.as_deref().unwrap_or("");
        let nickname = member.nick.as_deref().unwrap_or("");

        info!(
            "👤 [JOIN EVENT] Inspecting: user='{}' global='{}' nick='{}' (ID: {})",
            username, global_name, nickname, user_id
        );

        let v_user = container.gatekeeper.evaluate_threat(username);
        let v_glob = container.gatekeeper.evaluate_threat(global_name);
        let v_nick = container.gatekeeper.evaluate_threat(nickname);

        let highest_verdict = [v_user, v_glob, v_nick]
            .into_iter()
            .max_by_key(|v| match v {
                ThreatVerdict::InstantBan => 2,
                ThreatVerdict::DeleteOnly => 1,
                ThreatVerdict::Safe => 0,
            })
            .unwrap_or(ThreatVerdict::Safe);

        match highest_verdict {
            ThreatVerdict::InstantBan => {
                let offending_name = if v_nick == ThreatVerdict::InstantBan {
                    nickname
                } else if v_glob == ThreatVerdict::InstantBan {
                    global_name
                } else {
                    username
                };
                warn!("🚨 [GATEKEEPER] PREDATORY USERNAME DETECTED ON JOIN: '{}' (ID: {}). Eradicating account.", offending_name, user_id);

                tokio::spawn(purge_welcome_channel_on_nsfw_join(ctx.http.clone()));

                execute_ban(
                    &ctx.http,
                    guild_id,
                    user_id,
                    &format!("Zero-Tolerance Predatory Name Match: {}", offending_name),
                    1.0,
                    &container.db,
                )
                .await;
                send_mod_alert(
                    &ctx,
                    "Predatory User Banned on Join",
                    &format!(
                        "User <@{}> was banned on join for predatory name `{}`",
                        user_id, offending_name
                    ),
                    user_id,
                )
                .await;
                return;
            }
            ThreatVerdict::DeleteOnly => {
                let is_whitelisted = container
                    .whitelisted_users
                    .read()
                    .await
                    .contains(&username.to_lowercase())
                    || container
                        .whitelisted_users
                        .read()
                        .await
                        .contains(&user_id.to_string());

                if is_whitelisted {
                    info!(
                        "✅ Whitelisted user {} joined; soft name rule bypassed.",
                        username
                    );
                } else {
                    let offending_name = if v_nick == ThreatVerdict::DeleteOnly {
                        nickname
                    } else if v_glob == ThreatVerdict::DeleteOnly {
                        global_name
                    } else {
                        username
                    };
                    warn!("⚠️ [SOFT NAME POLICY] User {} joined with soft-flagged name '{}'. User NOT banned.", user_id, offending_name);
                    send_mod_alert(&ctx, "Soft Name Policy Notice", &format!("User <@{}> joined with name/handle `{}` matching a soft dynamic rule (e.g. 'link'). No ban issued.", user_id, offending_name), user_id).await;
                }
            }
            ThreatVerdict::Safe => {}
        }

        // Avatar Scan on Join
        if let Some(avatar_url) = member.user.avatar_url() {
            if let Ok(bytes) = download_image(&container.http_client, &avatar_url).await {
                let sha256 = CryptoEngine::sha256(&bytes);

                // Check Whitelist Cache (Bypasses all checks)
                if container.whitelisted_images.read().await.contains(&sha256) {
                    info!(
                        "🟢 [WHITELIST MATCH] User {} avatar is verified safe in whitelist!",
                        user_id
                    );
                    return;
                }

                // Sub-millisecond Blacklist Hash Cache Check
                if let Ok(true) = container.db.is_image_blacklisted(&sha256).await {
                    warn!(
                        "🚨 [HASH CACHE] User {} joined with blacklisted NSFW avatar!",
                        user_id
                    );
                    tokio::spawn(purge_welcome_channel_on_nsfw_join(ctx.http.clone()));

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
                                tokio::spawn(purge_welcome_channel_on_nsfw_join(
                                    ctx_clone.http.clone(),
                                ));
                                let _ = db.record_banned_image(&sha256, 0, user_id).await;
                                send_mod_alert(&ctx_clone, "Adult/NSFW Join Avatar Detected", &format!("User <@{}> joined with an adult PFP (Confidence: {:.1}%). No ban issued.", user_id, resp.confidence.nsfw), user_id).await;
                                send_logs_evidence(&ctx_clone, "Adult/NSFW Join Avatar Detected", &format!("User <@{}> joined with an adult PFP (Confidence: {:.1}%). Verify evidence below.", user_id, resp.confidence.nsfw), user_id, bytes_clone).await;
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

    /// On Message
    async fn message(&self, ctx: Context, msg: Message) {
        if msg.author.id == ctx.cache.current_user().id {
            return;
        }

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

        info!(
            "📥 [MSG] #{} | Author: {} (Bot: {}) | Attachments: {} | Embeds: {}",
            channel_id.get(),
            msg.author.name,
            msg.author.bot,
            msg.attachments.len(),
            msg.embeds.len()
        );

        // 1. THREE-VECTOR NAME GATEKEEPER (With Whitelist Bypass for Soft Rules)
        let username = &msg.author.name;
        let global_name = msg.author.global_name.as_deref().unwrap_or("");
        let nickname = msg
            .member
            .as_ref()
            .and_then(|m| m.nick.as_deref())
            .unwrap_or("");

        let is_user_whitelisted = container
            .whitelisted_users
            .read()
            .await
            .contains(&username.to_lowercase())
            || container
                .whitelisted_users
                .read()
                .await
                .contains(&author_id.to_string());

        let v_user = container.gatekeeper.evaluate_threat(username);
        let v_glob = container.gatekeeper.evaluate_threat(global_name);
        let v_nick = container.gatekeeper.evaluate_threat(nickname);

        let highest_verdict = [v_user, v_glob, v_nick]
            .into_iter()
            .max_by_key(|v| match v {
                ThreatVerdict::InstantBan => 2,
                ThreatVerdict::DeleteOnly => 1,
                ThreatVerdict::Safe => 0,
            })
            .unwrap_or(ThreatVerdict::Safe);

        match highest_verdict {
            ThreatVerdict::InstantBan => {
                let offending_name = if v_nick == ThreatVerdict::InstantBan {
                    nickname
                } else if v_glob == ThreatVerdict::InstantBan {
                    global_name
                } else {
                    username
                };
                warn!(
                    "🚨 [GATEKEEPER] Banning sender {} for predatory name: '{}'.",
                    author_id, offending_name
                );
                let _ = msg.delete(&ctx.http).await;
                if let Some(guild_id) = msg.guild_id {
                    execute_ban(
                        &ctx.http,
                        guild_id,
                        author_id,
                        &format!("Predatory Name Match (Hardcoded): {}", offending_name),
                        1.0,
                        &container.db,
                    )
                    .await;
                    send_mod_alert(
                        &ctx,
                        "Predatory User Banned on Message",
                        &format!(
                            "Banned <@{}> for predatory name `{}`",
                            author_id, offending_name
                        ),
                        author_id,
                    )
                    .await;
                }
                return;
            }
            ThreatVerdict::DeleteOnly => {
                if is_user_whitelisted {
                    info!(
                        "🟢 [WHITELIST BYPASS] Author {} is whitelisted; soft rule bypassed.",
                        username
                    );
                } else {
                    let offending_name = if v_nick == ThreatVerdict::DeleteOnly {
                        nickname
                    } else if v_glob == ThreatVerdict::DeleteOnly {
                        global_name
                    } else {
                        username
                    };
                    warn!("⚠️ [SOFT NAME POLICY] Deleting message from {} due to soft rule: '{}'. User NOT banned.", author_id, offending_name);
                    let _ = msg.delete(&ctx.http).await;
                    send_mod_alert(&ctx, "Message Deleted (Soft Name Policy)", &format!("Deleted message from <@{}> because their display name or handle (`{}`) contains a restricted keyword (e.g. 'link'). User was not banned.", author_id, offending_name), author_id).await;
                    return;
                }
            }
            ThreatVerdict::Safe => {}
        }

        // 2. AUTHOR PFP SENTRY
        if let Some(avatar_url) = msg.author.avatar_url() {
            if let Ok(bytes) = download_image(&container.http_client, &avatar_url).await {
                let sha256 = CryptoEngine::sha256(&bytes);

                // If avatar is whitelisted, skip check
                if !container.whitelisted_images.read().await.contains(&sha256) {
                    if let Ok(true) = container.db.is_image_blacklisted(&sha256).await {
                        warn!(
                            "🚨 [MUTED] Deleting message from {} due to blacklisted adult avatar.",
                            author_id
                        );
                        let _ = msg.delete(&ctx.http).await;
                        send_mod_alert(&ctx, "Message Blocked: User Has NSFW Avatar", &format!("User <@{}> attempted to send a message in <#{}>, but holds a blacklisted adult avatar. Message was deleted.", author_id, channel_id.get()), author_id).await;
                        send_logs_evidence(&ctx, "Message Blocked: User Has NSFW Avatar", &format!("Blocked message from <@{}> in <#{}>. User holds a blacklisted avatar.", author_id, channel_id.get()), author_id, bytes).await;
                        return;
                    }
                }
            }
        }

        // 3. Media Scanner (Attachments & Embeds)
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

        for (url, source) in image_urls {
            if let Ok(bytes) = download_image(&container.http_client, &url).await {
                let sha256 = CryptoEngine::sha256(&bytes);

                // Whitelist Check (Instant Safe Pass)
                if container.whitelisted_images.read().await.contains(&sha256) {
                    info!("🟢 [IMAGE WHITELIST] Image {} is verified safe in whitelist! Skipping scan.", sha256);
                    continue;
                }

                // Blacklist Check
                if let Ok(true) = container.db.is_image_blacklisted(&sha256).await {
                    warn!("🚨 [CACHE HIT] Known NSFW image found! Deleting message instantly.");
                    let _ = msg.delete(&ctx.http).await;
                    send_mod_alert(
                        &ctx,
                        "NSFW Message/Embed Deleted",
                        &format!(
                            "Deleted message containing known NSFW media in <#{}> by <@{}>.",
                            channel_id.get(),
                            author_id
                        ),
                        author_id,
                    )
                    .await;
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

                // AI Classifier Queue
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
                                warn!("🚨 [VERDICT NSFW] {} flagged! (NSFW Conf: {:.1}%, Time: {}). Deleting message.", source, resp.confidence.nsfw, resp.processing_time);
                                let _ = db.record_banned_image(&sha256, 0, author_id).await;
                                let _ = channel_id.delete_message(&ctx_clone.http, msg_id).await;
                                send_mod_alert(&ctx_clone, "NSFW Image Deleted", &format!("Deleted adult image in <#{}> posted by <@{}> (Confidence: {:.1}%). User was not banned.", channel_id.get(), author_id, resp.confidence.nsfw), author_id).await;
                                send_logs_evidence(&ctx_clone, "NSFW Image Deleted", &format!("Deleted adult image in <#{}> posted by <@{}> (Confidence: {:.1}%). Verify evidence below.", channel_id.get(), author_id, resp.confidence.nsfw), author_id, bytes_clone).await;
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

/// Active Welcome Channel Sweeper
async fn purge_welcome_channel_on_nsfw_join(http: Arc<serenity::http::Http>) {
    let channel = ChannelId::new(WELCOME_CHANNEL_ID);
    for attempt in 1..=4 {
        tokio::time::sleep(Duration::from_millis(800)).await;
        if let Ok(messages) = channel.messages(&http, GetMessages::new().limit(3)).await {
            for msg in messages {
                let now = serenity::model::Timestamp::now().unix_timestamp();
                let msg_time = msg.timestamp.unix_timestamp();
                if (now - msg_time).abs() < 60
                    && (msg.author.bot || msg.author.id.get() == 678344927997853742)
                {
                    warn!("🚨 [PURGE] Found recent welcome message from {} (ID: {}). Deleting on attempt {}...", msg.author.name, msg.id, attempt);
                    if let Ok(()) = channel.delete_message(&http, msg.id).await {
                        info!("✅ [SWEEPER SUCCESS] Deleted welcome card from #welcome on attempt {}!", attempt);
                        return;
                    }
                }
            }
        }
    }
}

/// Tier 1 Alert
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
    let _ = channel.send_message(&ctx.http, msg).await;
}

/// Tier 2 Alert
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
    let _ = channel.send_message(&ctx.http, msg).await;
}

async fn execute_ban(
    http: &serenity::http::Http,
    guild_id: GuildId,
    user_id: u64,
    reason: &str,
    confidence: f64,
    db: &DatabaseEngine,
) {
    if user_id == OWNER_USER_ID {
        warn!(
            "🛡️ [SOVEREIGN IMMUNITY] Refusing to ban the Architect ({}).",
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

async fn download_image(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    let resp = client.get(url).send().await?;
    let bytes = resp.bytes().await?;
    Ok(bytes.to_vec())
}
