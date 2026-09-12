//! # Sebastian The Butler - Discord Bot Gateway Core

use serenity::async_trait;
use serenity::builder::{
    CreateCommand, CreateCommandOption, CreateInteractionResponse,
    CreateInteractionResponseMessage, CreateMessage, EditInteractionResponse,
};
use serenity::model::application::{
    CommandDataOptionValue, CommandInteraction, CommandOptionType, Interaction,
};
use serenity::model::channel::{Message, Reaction};
use serenity::model::gateway::Ready;
use serenity::model::guild::{Guild, Member};
use serenity::model::id::{ChannelId, GuildId, UserId};
use serenity::model::user::User;
use serenity::model::voice::VoiceState;
use serenity::prelude::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::config::GuildConfig;
use crate::db::{AuditLogEntry, DatabaseEngine};
use crate::gatekeeper::{TextGatekeeper, ThreatVerdict};
use crate::media::{MediaInspector, MediaPayload};
use crate::pipeline::alerts::{
    send_logs_evidence, send_mod_alert, send_owner_diagnostic, send_user_notification,
};
use crate::pipeline::media_guard::{triage_media, MediaVerdict};
use crate::pipeline::name_guard::evaluate_member_names;
use crate::pipeline::sweeper::purge_welcome_channel_on_nsfw_join;
use crate::plugin_engine::DynamicPluginEngine;
use crate::queue::{BoundedScanQueue, ResilientClassifierClient, ScanTask};
use crate::whitelist::WhitelistRegistry;
use crate::Result;

pub struct BotContainer {
    pub config: Arc<GuildConfig>,
    pub gatekeeper: Arc<TextGatekeeper>,
    pub db: Arc<DatabaseEngine>,
    pub whitelist: Arc<WhitelistRegistry>,
    pub media_inspector: Arc<MediaInspector>,
    pub scan_queue: Arc<BoundedScanQueue>,
    pub plugin_engine: Arc<DynamicPluginEngine>,
    pub blacklisted_dhashes: Arc<RwLock<Vec<u64>>>,
}

impl BotContainer {
    pub async fn bootstrap(
        db: Arc<DatabaseEngine>,
        config: Arc<GuildConfig>,
        classifier_url: String,
    ) -> Result<Arc<Self>> {
        let gatekeeper = Arc::new(TextGatekeeper::new());
        if let Ok(rules) = db.fetch_dynamic_rules().await {
            let patterns: Vec<String> = rules.into_iter().map(|r| r.pattern).collect();
            let _ = gatekeeper.reload_dynamic_patterns(&patterns);
        }

        let whitelist = Arc::new(WhitelistRegistry::new());
        let _ = whitelist.sync_from_db(&db).await;

        let dhashes = db.fetch_all_dhashes().await.unwrap_or_default();
        let blacklisted_dhashes = Arc::new(RwLock::new(dhashes));

        let http_client = reqwest::Client::new();
        let media_inspector = Arc::new(MediaInspector::new(
            http_client.clone(),
            config.max_download_size_bytes,
        ));
        let classifier_client = Arc::new(ResilientClassifierClient::new(classifier_url));
        let scan_queue = Arc::new(BoundedScanQueue::new(500, classifier_client));

        let plugin_engine = Arc::new(DynamicPluginEngine::new().with_db(db.clone()));
        if let Ok(records) = db.fetch_all_plugin_records().await {
            for p in records.into_iter().filter(|r| r.enabled) {
                let _ = plugin_engine.hot_swap_plugin(&p.name, &p.bytecode.bytes);
            }
        }

        Ok(Arc::new(Self {
            config,
            gatekeeper,
            db,
            whitelist,
            media_inspector,
            scan_queue,
            plugin_engine,
            blacklisted_dhashes,
        }))
    }
}

pub struct BotContainerKey;
impl TypeMapKey for BotContainerKey {
    type Value = Arc<BotContainer>;
}

pub struct Handler;

#[async_trait]
impl EventHandler for Handler {
    async fn ready(&self, ctx: Context, _ready: Ready) {
        let c = get_container(&ctx).await;
        info!(
            "Sebastian The Butler Online. Registering commands for Guild: {}",
            c.config.authorized_guild_id
        );

        let guild_id = GuildId::new(c.config.authorized_guild_id);
        let mut commands = vec![
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
                .description("Exempt a user from soft rules")
                .add_option(
                    CreateCommandOption::new(CommandOptionType::User, "user", "Target user")
                        .required(true),
                )
                .add_option(
                    CreateCommandOption::new(CommandOptionType::String, "reason", "Reason")
                        .required(false),
                ),
            CreateCommand::new("whitelist-pfp")
                .description("Mark a user's avatar as safe")
                .add_option(
                    CreateCommandOption::new(CommandOptionType::User, "user", "Target user")
                        .required(true),
                ),
            CreateCommand::new("whitelist-image")
                .description("Whitelist an image by URL, upload, or SHA-256")
                .add_option(
                    CreateCommandOption::new(
                        CommandOptionType::String,
                        "input",
                        "Image URL or SHA-256 Hash",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        CommandOptionType::Attachment,
                        "file",
                        "Upload image directly",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(CommandOptionType::String, "label", "Label")
                        .required(false),
                ),
            CreateCommand::new("notify-user")
                .description("Send a notice to a member's DM")
                .add_option(
                    CreateCommandOption::new(CommandOptionType::User, "user", "Target user")
                        .required(true),
                )
                .add_option(
                    CreateCommandOption::new(CommandOptionType::String, "message", "Message")
                        .required(true),
                ),
            CreateCommand::new("db-stats").description("Check MongoDB storage usage"),
        ];

        for manifest in c.plugin_engine.get_all_manifests() {
            for def in manifest.slash_commands {
                info!("Registering plugin slash command: /{}", def.name);
                commands.push(CreateCommand::new(&def.name).description(&def.description));
            }
        }

        match guild_id.set_commands(&ctx.http, commands).await {
            Ok(cmds) => info!("Registered {} slash commands.", cmds.len()),
            Err(e) => error!("Failed registering slash commands: {}", e),
        }

        // Post boot notification directly to #terminal (1492187958206533834)
        let terminal_channel = ChannelId::new(c.config.terminal_channel_id);
        if let Err(e) = terminal_channel
            .send_message(
                &ctx.http,
                CreateMessage::new().content("Sebastian The Butler is online."),
            )
            .await
        {
            warn!("Could not send boot notice to #terminal channel: {}", e);
        }
    }

    async fn guild_create(&self, ctx: Context, guild: Guild, _is_new: Option<bool>) {
        let container = get_container(&ctx).await;
        if !container.config.is_authorized_guild(guild.id.get()) {
            warn!("Leaving unauthorized guild: {} ({})", guild.name, guild.id);
            let _ = guild.leave(&ctx.http).await;
        }
    }

    async fn guild_member_addition(&self, ctx: Context, member: Member) {
        let c = get_container(&ctx).await;
        if !c.config.is_authorized_guild(member.guild_id.get()) {
            return;
        }

        let user_id = member.user.id.get();

        dispatch_plugin_event(
            &c,
            "member_join",
            serde_json::json!({
                "guild_id": member.guild_id.get(),
                "user_id": user_id,
                "username": &member.user.name
            }),
        );

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
                &format!("Name violation: {}", eval.offending_name),
                1.0,
                &c.db,
                &c.config,
            )
            .await;
            send_mod_alert(
                &ctx,
                &c.config,
                "User Banned on Join",
                &format!("Banned <@{}> for name `{}`", user_id, eval.offending_name),
                user_id,
            )
            .await;
            return;
        }

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

    async fn guild_member_removal(
        &self,
        ctx: Context,
        guild_id: GuildId,
        user: User,
        _member_data: Option<Member>,
    ) {
        let c = get_container(&ctx).await;
        dispatch_plugin_event(
            &c,
            "member_leave",
            serde_json::json!({
                "guild_id": guild_id.get(),
                "user_id": user.id.get(),
                "username": &user.name
            }),
        );
    }

    async fn voice_state_update(&self, ctx: Context, old: Option<VoiceState>, new: VoiceState) {
        let c = get_container(&ctx).await;
        dispatch_plugin_event(
            &c,
            "voice_state_update",
            serde_json::json!({
                "user_id": new.user_id.get(),
                "guild_id": new.guild_id.map(|g| g.get()),
                "channel_id": new.channel_id.map(|c| c.get()),
                "old_channel_id": old.and_then(|o| o.channel_id.map(|c| c.get())),
                "self_mute": new.self_mute,
                "self_deaf": new.self_deaf
            }),
        );
    }

    async fn reaction_add(&self, ctx: Context, reaction: Reaction) {
        let c = get_container(&ctx).await;
        dispatch_plugin_event(
            &c,
            "reaction_add",
            serde_json::json!({
                "user_id": reaction.user_id.map(|u| u.get()),
                "channel_id": reaction.channel_id.get(),
                "message_id": reaction.message_id.get(),
                "emoji": reaction.emoji.as_data()
            }),
        );
    }

    async fn reaction_remove(&self, ctx: Context, reaction: Reaction) {
        let c = get_container(&ctx).await;
        dispatch_plugin_event(
            &c,
            "reaction_remove",
            serde_json::json!({
                "user_id": reaction.user_id.map(|u| u.get()),
                "channel_id": reaction.channel_id.get(),
                "message_id": reaction.message_id.get(),
                "emoji": reaction.emoji.as_data()
            }),
        );
    }

    async fn message(&self, ctx: Context, msg: Message) {
        if msg.author.id == ctx.cache.current_user().id {
            return;
        }
        let c = get_container(&ctx).await;
        if msg.guild_id != Some(GuildId::new(c.config.authorized_guild_id)) {
            return;
        }

        dispatch_plugin_event(
            &c,
            "message_create",
            serde_json::json!({
                "id": msg.id.get(),
                "channel_id": msg.channel_id.get(),
                "author_id": msg.author.id.get(),
                "author_name": &msg.author.name,
                "content": &msg.content,
                "is_bot": msg.author.bot
            }),
        );

        if guard_author_names(&ctx, &c, &msg).await {
            return;
        }
        if guard_author_pfp(&ctx, &c, &msg).await {
            return;
        }
        inspect_message_media(&ctx, &c, &msg).await;
    }

    async fn interaction_create(&self, ctx: Context, interaction: Interaction) {
        if let Interaction::Command(command) = interaction {
            let c = get_container(&ctx).await;
            handle_slash_command(&ctx, &c, command).await;
        }
    }
}

// Subroutines (<40 lines each, NASA Rule 1 & 4)

fn dispatch_plugin_event(c: &BotContainer, event_name: &str, data: serde_json::Value) {
    if c.plugin_engine.has_subscribers_for(event_name) {
        c.plugin_engine
            .dispatch_event(event_name, &data.to_string());
    }
}

async fn get_container(ctx: &Context) -> Arc<BotContainer> {
    ctx.data
        .read()
        .await
        .get::<BotContainerKey>()
        .unwrap()
        .clone()
}

async fn guard_author_names(ctx: &Context, c: &BotContainer, msg: &Message) -> bool {
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
                    &format!("Name violation: {}", eval.offending_name),
                    1.0,
                    &c.db,
                    &c.config,
                )
                .await;
                send_mod_alert(
                    ctx,
                    &c.config,
                    "User Banned",
                    &format!("Banned <@{}>", author_id),
                    author_id,
                )
                .await;
            }
            true
        }
        ThreatVerdict::DeleteOnly => {
            let _ = msg.delete(&ctx.http).await;
            send_mod_alert(
                ctx,
                &c.config,
                "Message Removed",
                &format!(
                    "Removed message from <@{}> for `{}`",
                    author_id, eval.offending_name
                ),
                author_id,
            )
            .await;
            true
        }
        ThreatVerdict::Safe => false,
    }
}

async fn guard_author_pfp(ctx: &Context, c: &BotContainer, msg: &Message) -> bool {
    if let Some(avatar_url) = msg.author.avatar_url() {
        if let Ok(payload) = c.media_inspector.inspect_url(&avatar_url).await {
            if !c
                .whitelist
                .is_image_safe(&payload.sha256, payload.dhash)
                .await
                && c.db
                    .is_image_blacklisted(&payload.sha256)
                    .await
                    .unwrap_or(false)
            {
                let _ = msg.delete(&ctx.http).await;
                let author_id = msg.author.id.get();

                tokio::spawn({
                    let http = ctx.http.clone();
                    async move {
                        send_user_notification(
                            &http,
                            author_id,
                            "Notice Regarding Your Profile Picture",
                            "Your message was held because your profile picture is currently being reviewed by server safety filters.",
                        ).await;
                    }
                });

                send_mod_alert(
                    ctx,
                    &c.config,
                    "Message Blocked (Avatar)",
                    &format!("Blocked <@{}> (avatar flagged)", author_id),
                    author_id,
                )
                .await;
                send_logs_evidence(
                    ctx,
                    &c.config,
                    "Blocked Avatar",
                    &format!("User <@{}> avatar flagged", author_id),
                    author_id,
                    payload.bytes,
                )
                .await;
                return true;
            }
        }
    }
    false
}

async fn handle_join_avatar(
    ctx: &Context,
    c: &BotContainer,
    user_id: u64,
    guild_id: u64,
    url: &str,
    payload: MediaPayload,
) {
    match triage_media(c, &payload, user_id, guild_id, url.to_string()).await {
        Ok(MediaVerdict::BlacklistedNSFW) => {
            tokio::spawn(purge_welcome_channel_on_nsfw_join(
                ctx.http.clone(),
                c.config.clone(),
            ));
            send_mod_alert(
                ctx,
                &c.config,
                "Flagged Avatar on Join",
                &format!("User <@{}> holds flagged avatar", user_id),
                user_id,
            )
            .await;
            send_logs_evidence(
                ctx,
                &c.config,
                "Flagged Avatar",
                &format!("User <@{}> avatar flagged", user_id),
                user_id,
                payload.bytes,
            )
            .await;
        }
        Ok(MediaVerdict::QueuedForInference(rx)) => {
            let ctx_c = ctx.clone();
            let cfg = c.config.clone();
            let db = c.db.clone();
            let dhash_cache = c.blacklisted_dhashes.clone();
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
                        if payload.dhash != 0 {
                            dhash_cache.write().await.push(payload.dhash);
                        }
                        send_mod_alert(
                            &ctx_c,
                            &cfg,
                            "Flagged Avatar Detected",
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
                            "Flagged Avatar Evidence",
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
                c,
                &payload,
                author_id,
                c.config.authorized_guild_id,
                url.clone(),
            )
            .await
            {
                Ok(MediaVerdict::BlacklistedNSFW) => {
                    let _ = ch_id.delete_message(&ctx.http, msg_id).await;
                    send_mod_alert(
                        ctx,
                        &c.config,
                        "Media Removed (Cache)",
                        &format!("Removed media from <@{}> in <#{}>", author_id, ch_id.get()),
                        author_id,
                    )
                    .await;
                    send_logs_evidence(
                        ctx,
                        &c.config,
                        "Media Removed",
                        &format!("Removed from <@{}>", author_id),
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
                    let dhash_cache = c.blacklisted_dhashes.clone();
                    tokio::spawn(async move {
                        if let Ok(Ok(resp)) = rx.await {
                            if resp.confidence.nsfw >= cfg.nsfw_auto_delete_threshold {
                                let _ = db
                                    .record_banned_image(&payload.sha256, payload.dhash, author_id)
                                    .await;
                                if payload.dhash != 0 {
                                    dhash_cache.write().await.push(payload.dhash);
                                }
                                let _ = ch_id.delete_message(&ctx_c.http, msg_id).await;
                                send_mod_alert(
                                    &ctx_c,
                                    &cfg,
                                    "Media Removed",
                                    &format!(
                                        "Removed from <@{}> ({:.1}%)",
                                        author_id, resp.confidence.nsfw
                                    ),
                                    author_id,
                                )
                                .await;
                                send_logs_evidence(
                                    &ctx_c,
                                    &cfg,
                                    "Media Evidence",
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

async fn handle_slash_command(ctx: &Context, c: &BotContainer, cmd: CommandInteraction) {
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
                        .content("Staff role required.")
                        .ephemeral(true),
                ),
            )
            .await;
        return;
    }

    match cmd.data.name.as_str() {
        "test-name" => cmd_test_name(ctx, c, &cmd).await,
        "test-pfp" => cmd_test_pfp(ctx, c, &cmd).await,
        "whitelist-user" => cmd_whitelist_user(ctx, c, &cmd).await,
        "whitelist-pfp" => cmd_whitelist_pfp(ctx, c, &cmd).await,
        "whitelist-image" => cmd_whitelist_image(ctx, c, &cmd).await,
        "notify-user" => cmd_notify_user(ctx, c, &cmd).await,
        "db-stats" => cmd_db_stats(ctx, c, &cmd).await,
        plugin_cmd => {
            let mut handled = false;
            for manifest in c.plugin_engine.get_all_manifests() {
                if manifest.slash_commands.iter().any(|s| s.name == plugin_cmd) {
                    handled = true;
                    info!(
                        "Executing /{} from plugin '{}' for user {}",
                        plugin_cmd, manifest.name, caller_id
                    );
                    let opts_json = serde_json::to_string(&cmd.data.options).unwrap_or_default();
                    match c.plugin_engine.execute_slash_command(
                        &manifest.name,
                        plugin_cmd,
                        &opts_json,
                    ) {
                        Ok(reply) => {
                            info!("/{} output: '{}'", plugin_cmd, reply);
                            let _ = cmd
                                .create_response(
                                    &ctx.http,
                                    CreateInteractionResponse::Message(
                                        CreateInteractionResponseMessage::new().content(reply),
                                    ),
                                )
                                .await;
                        }
                        Err(e) => {
                            tracing::error!("Plugin error on /{}: {}", plugin_cmd, e);
                            let _ = cmd
                                .create_response(
                                    &ctx.http,
                                    CreateInteractionResponse::Message(
                                        CreateInteractionResponseMessage::new()
                                            .content(format!("Plugin error: {}", e))
                                            .ephemeral(true),
                                    ),
                                )
                                .await;
                        }
                    }
                    break;
                }
            }
            if !handled {
                let _ = cmd
                    .create_response(
                        &ctx.http,
                        CreateInteractionResponse::Message(
                            CreateInteractionResponseMessage::new()
                                .content("Command acknowledged."),
                        ),
                    )
                    .await;
            }
        }
    }
}

async fn cmd_test_name(ctx: &Context, c: &BotContainer, cmd: &CommandInteraction) {
    let text = cmd
        .data
        .options
        .iter()
        .find(|o| o.name == "text")
        .and_then(|o| o.value.as_str())
        .unwrap_or("");
    let verdict = c.gatekeeper.evaluate_threat(text);
    let (norm, alpha, deduped) = c.gatekeeper.canonicalize(text);
    let reply = format!("**Gatekeeper Test:** `{}`\n> **Verdict:** {:?}\n> **Normalized:** `{}`\n> **Alphanumeric:** `{}`\n> **Deduped:** `{}`", text, verdict, norm, alpha, deduped);
    let _ = cmd
        .create_response(
            &ctx.http,
            CreateInteractionResponse::Message(
                CreateInteractionResponseMessage::new().content(reply),
            ),
        )
        .await;
}

async fn cmd_test_pfp(ctx: &Context, c: &BotContainer, cmd: &CommandInteraction) {
    let _ = cmd.defer(&ctx.http).await;

    let mut target_url = None;
    let mut target_user_id = cmd.user.id.get();
    for opt in &cmd.data.options {
        if opt.name == "image" {
            if let CommandDataOptionValue::Attachment(att_id) = &opt.value {
                target_url = cmd
                    .data
                    .resolved
                    .attachments
                    .get(att_id)
                    .map(|a| a.url.clone());
            }
        } else if opt.name == "user" {
            if let CommandDataOptionValue::User(uid) = &opt.value {
                target_user_id = uid.get();
                target_url = cmd
                    .data
                    .resolved
                    .users
                    .get(uid)
                    .and_then(|u| u.avatar_url());
            }
        }
    }

    if target_url.is_none() {
        target_url = cmd.user.avatar_url();
    }

    let Some(url) = target_url else {
        let _ = cmd
            .edit_response(
                &ctx.http,
                EditInteractionResponse::new().content("No avatar or image found to analyze."),
            )
            .await;
        return;
    };

    let Ok(payload) = c.media_inspector.inspect_url(&url).await else {
        let _ = cmd
            .edit_response(
                &ctx.http,
                EditInteractionResponse::new().content("Failed downloading image."),
            )
            .await;
        return;
    };

    let is_whitelisted = c
        .whitelist
        .is_image_safe(&payload.sha256, payload.dhash)
        .await;
    let is_blacklisted =
        c.db.is_image_blacklisted(&payload.sha256)
            .await
            .unwrap_or(false);

    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = ScanTask {
        user_id: cmd.user.id.get(),
        guild_id: c.config.authorized_guild_id,
        image_url: url.clone(),
        image_bytes: payload.bytes,
        response_tx: tx,
    };

    if c.scan_queue.submit(task).await.is_ok() {
        if let Ok(Ok(resp)) = rx.await {
            let verdict_str = if is_whitelisted {
                "Safe (Whitelisted)"
            } else if resp.confidence.nsfw >= c.config.nsfw_auto_delete_threshold || is_blacklisted
            {
                "Flagged"
            } else {
                "Safe"
            };

            let reply = format!(
                "**Image Test**\n\
                > **URL:** {}\n\
                > **SHA-256:** `{}`\n\
                > **dHash:** `{:016x}`\n\
                > **Status:** Whitelisted: `{}` | Blacklisted: `{}`\n\
                > **Verdict:** {}\n\
                > **Confidence:** Safe: `{:.1}%` | Flagged: `{:.1}%`\n\
                > **Latency:** `{}`",
                url,
                payload.sha256,
                payload.dhash,
                is_whitelisted,
                is_blacklisted,
                verdict_str,
                resp.confidence.safe,
                resp.confidence.nsfw,
                resp.processing_time
            );

            send_owner_diagnostic(
                &ctx.http,
                &c.config,
                "Test PFP Result",
                &format!(
                    "Caller: <@{}>\nTarget: <@{}>\nSHA-256: `{}`\ndHash: `{:016x}`\nVerdict: {}\nConfidence: Safe: `{:.1}%` | Flagged: `{:.1}%`",
                    cmd.user.id.get(), target_user_id, payload.sha256, payload.dhash, verdict_str, resp.confidence.safe, resp.confidence.nsfw
                ),
            ).await;

            let _ = cmd
                .edit_response(&ctx.http, EditInteractionResponse::new().content(reply))
                .await;
            return;
        }
    }

    let _ = cmd
        .edit_response(
            &ctx.http,
            EditInteractionResponse::new().content("Classification queue timeout."),
        )
        .await;
}

async fn cmd_whitelist_user(ctx: &Context, c: &BotContainer, cmd: &CommandInteraction) {
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

    if target_id == 0 {
        let _ = cmd
            .create_response(
                &ctx.http,
                CreateInteractionResponse::Message(
                    CreateInteractionResponseMessage::new()
                        .content("Invalid user specified.")
                        .ephemeral(true),
                ),
            )
            .await;
        return;
    }

    let _ =
        c.db.add_whitelisted_user(&target_name, &cmd.user.name, &reason)
            .await;
    let _ =
        c.db.add_whitelisted_user(&target_id.to_string(), &cmd.user.name, &reason)
            .await;
    c.whitelist.add_user(&target_name).await;
    c.whitelist.add_user(&target_id.to_string()).await;

    send_owner_diagnostic(
        &ctx.http,
        &c.config,
        "User Whitelisted",
        &format!(
            "Target: <@{}> (`{}`)\nStaff: {}\nReason: `{}`",
            target_id, target_name, cmd.user.name, reason
        ),
    )
    .await;

    let reply = format!(
        "Whitelisted <@{}> (`{}`) by **{}** (Reason: `{}`).",
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

async fn cmd_whitelist_pfp(ctx: &Context, c: &BotContainer, cmd: &CommandInteraction) {
    let mut target_id = 0u64;
    let mut target_name = String::new();
    let mut avatar_url = None;

    for opt in &cmd.data.options {
        if opt.name == "user" {
            if let CommandDataOptionValue::User(uid) = &opt.value {
                target_id = uid.get();
                if let Some(u) = cmd.data.resolved.users.get(uid) {
                    target_name = u.name.clone();
                    avatar_url = u.avatar_url();
                }
            }
        }
    }

    let Some(url) = avatar_url else {
        let _ = cmd
            .create_response(
                &ctx.http,
                CreateInteractionResponse::Message(
                    CreateInteractionResponseMessage::new()
                        .content("Target user has no avatar set to whitelist.")
                        .ephemeral(true),
                ),
            )
            .await;
        return;
    };

    if let Ok(payload) = c.media_inspector.inspect_url(&url).await {
        let label = format!("PFP: @{}", target_name);
        let _ =
            c.db.add_whitelisted_image(&payload.sha256, payload.dhash, &label, &cmd.user.name)
                .await;
        c.whitelist.add_image(&payload.sha256, payload.dhash).await;

        if payload.dhash != 0 {
            let mut guard = c.blacklisted_dhashes.write().await;
            guard.retain(|&banned| (banned ^ payload.dhash).count_ones() > 6);
        }

        let notified = send_user_notification(
            &ctx.http,
            target_id,
            "Profile Picture Verified Safe",
            "Your profile picture has been reviewed by server staff and marked safe. Your permissions are fully restored!",
        ).await;

        send_owner_diagnostic(
            &ctx.http,
            &c.config,
            "PFP Whitelisted",
            &format!(
                "Target: <@{}> (`{}`)\nStaff: {}\nSHA-256: `{}`\ndHash: `{:016x}`\nMember DM: {}",
                target_id,
                target_name,
                cmd.user.name,
                payload.sha256,
                payload.dhash,
                if notified { "Delivered" } else { "Closed DMs" }
            ),
        )
        .await;

        let reply = format!(
            "**Avatar Whitelisted:** <@{}>\n> **SHA-256:** `{}`\n> **dHash:** `{:016x}`\nThis image is marked safe. (Notified: {})",
            target_id, payload.sha256, payload.dhash, if notified { "Yes" } else { "DMs Disabled" }
        );
        let _ = cmd
            .create_response(
                &ctx.http,
                CreateInteractionResponse::Message(
                    CreateInteractionResponseMessage::new().content(reply),
                ),
            )
            .await;
        return;
    }

    let _ = cmd
        .create_response(
            &ctx.http,
            CreateInteractionResponse::Message(
                CreateInteractionResponseMessage::new()
                    .content("Failed downloading user avatar.")
                    .ephemeral(true),
            ),
        )
        .await;
}

async fn cmd_whitelist_image(ctx: &Context, c: &BotContainer, cmd: &CommandInteraction) {
    let _ = cmd.defer(&ctx.http).await;

    let mut raw_input = String::new();
    let mut attachment_url = None;
    let mut label = "Discord Whitelist".to_string();

    for opt in &cmd.data.options {
        if opt.name == "input" {
            if let CommandDataOptionValue::String(s) = &opt.value {
                raw_input = s.trim().to_string();
            }
        } else if opt.name == "file" {
            if let CommandDataOptionValue::Attachment(att_id) = &opt.value {
                attachment_url = cmd
                    .data
                    .resolved
                    .attachments
                    .get(att_id)
                    .map(|a| a.url.clone());
            }
        } else if opt.name == "label" {
            if let CommandDataOptionValue::String(l) = &opt.value {
                label = l.clone();
            }
        }
    }

    if raw_input.len() == 64 && raw_input.chars().all(|c| c.is_ascii_hexdigit()) {
        let sha_clean = raw_input.to_lowercase();
        let _ =
            c.db.add_whitelisted_image(&sha_clean, 0, &label, &cmd.user.name)
                .await;
        let _ = c.db.revoke_blacklisted_image(&sha_clean).await;
        c.whitelist.add_image(&sha_clean, 0).await;

        send_owner_diagnostic(
            &ctx.http,
            &c.config,
            "Direct SHA-256 Whitelisted",
            &format!(
                "SHA-256: `{}`\nStaff: {}\nLabel: `{}`",
                sha_clean, cmd.user.name, label
            ),
        )
        .await;

        let reply = format!(
            "**Image Whitelisted:**\n> **SHA-256:** `{}`\n> **Label:** `{}`\nThis image is marked safe.",
            sha_clean, label
        );
        let _ = cmd
            .edit_response(&ctx.http, EditInteractionResponse::new().content(reply))
            .await;
        return;
    }

    let target_url = attachment_url.or_else(|| {
        if raw_input.starts_with("http://") || raw_input.starts_with("https://") {
            Some(raw_input)
        } else {
            None
        }
    });

    let Some(url) = target_url else {
        let _ = cmd
            .edit_response(
                &ctx.http,
                EditInteractionResponse::new().content(
                    "Provide a valid image URL, attachment, or 64-character SHA-256 hash.",
                ),
            )
            .await;
        return;
    };

    let Ok(payload) = c.media_inspector.inspect_url(&url).await else {
        let _ = cmd
            .edit_response(
                &ctx.http,
                EditInteractionResponse::new().content("Failed downloading image from source."),
            )
            .await;
        return;
    };

    let _ =
        c.db.add_whitelisted_image(&payload.sha256, payload.dhash, &label, &cmd.user.name)
            .await;
    let _ = c.db.revoke_blacklisted_image(&payload.sha256).await;
    c.whitelist.add_image(&payload.sha256, payload.dhash).await;

    if payload.dhash != 0 {
        let mut guard = c.blacklisted_dhashes.write().await;
        guard.retain(|&banned| (banned ^ payload.dhash).count_ones() > 6);
    }

    send_owner_diagnostic(
        &ctx.http,
        &c.config,
        "Image Whitelisted",
        &format!(
            "Staff: {}\nSHA-256: `{}`\ndHash: `{:016x}`\nLabel: `{}`",
            cmd.user.name, payload.sha256, payload.dhash, label
        ),
    )
    .await;

    let reply = format!(
        "**Image Whitelisted:**\n> **SHA-256:** `{}`\n> **dHash:** `{:016x}`\n> **Label:** `{}`\nThis image is marked safe.",
        payload.sha256, payload.dhash, label
    );
    let _ = cmd
        .edit_response(&ctx.http, EditInteractionResponse::new().content(reply))
        .await;
}

async fn cmd_notify_user(ctx: &Context, c: &BotContainer, cmd: &CommandInteraction) {
    let mut target_id = 0u64;
    let mut message_text = String::new();

    for opt in &cmd.data.options {
        if opt.name == "user" {
            if let CommandDataOptionValue::User(uid) = &opt.value {
                target_id = uid.get();
            }
        } else if opt.name == "message" {
            if let CommandDataOptionValue::String(m) = &opt.value {
                message_text = m.clone();
            }
        }
    }

    if target_id == 0 || message_text.is_empty() {
        let _ = cmd
            .create_response(
                &ctx.http,
                CreateInteractionResponse::Message(
                    CreateInteractionResponseMessage::new()
                        .content("Missing user or message parameter.")
                        .ephemeral(true),
                ),
            )
            .await;
        return;
    }

    let delivered = send_user_notification(
        &ctx.http,
        target_id,
        "Notice from Server Staff",
        &message_text,
    )
    .await;

    send_owner_diagnostic(
        &ctx.http,
        &c.config,
        "User Notified",
        &format!(
            "Staff: {}\nTarget: <@{}>\nStatus: {}\nMessage: {}",
            cmd.user.name,
            target_id,
            if delivered { "Delivered" } else { "Closed DMs" },
            message_text
        ),
    )
    .await;

    let reply = if delivered {
        format!("Notification delivered to <@{}>.", target_id)
    } else {
        format!(
            "Could not send DM to <@{}> (User has DMs closed).",
            target_id
        )
    };

    let _ = cmd
        .create_response(
            &ctx.http,
            CreateInteractionResponse::Message(
                CreateInteractionResponseMessage::new()
                    .content(reply)
                    .ephemeral(true),
            ),
        )
        .await;
}

async fn cmd_db_stats(ctx: &Context, c: &BotContainer, cmd: &CommandInteraction) {
    let reply = match c.db.get_storage_stats().await {
        Ok((used, max)) => {
            let u_mb = used as f64 / (1024.0 * 1024.0);
            let m_mb = max as f64 / (1024.0 * 1024.0);
            format!(
                "MongoDB Storage: `{:.2} MB` / `{:.0} MB` (Remaining: `{:.2} MB`)",
                u_mb,
                m_mb,
                m_mb - u_mb
            )
        }
        Err(e) => format!("Failed: {}", e),
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
        warn!("Refusing ban against Owner ({}).", user_id);
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
