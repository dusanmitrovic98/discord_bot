//! # Sebastian The Butler - Discord Bot Gateway Core

use serenity::async_trait;
use serenity::builder::{
    CreateCommand, CreateCommandOption, CreateEmbed, CreateInteractionResponse,
    CreateInteractionResponseMessage, CreateMessage, EditInteractionResponse, EditMember,
};
use serenity::model::application::{
    CommandDataOptionValue, CommandInteraction, CommandOptionType, Interaction,
};
use serenity::model::channel::{Message, Reaction};
use serenity::model::event::GuildMemberUpdateEvent;
use serenity::model::gateway::Ready;
use serenity::model::guild::{Guild, Member};
use serenity::model::id::{ChannelId, GuildId, UserId};
use serenity::model::user::User;
use serenity::model::voice::VoiceState;
use serenity::prelude::*;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::config::GuildConfig;
use crate::constants::geo::{lookup_country_by_code, AgeBracket};
use crate::db::{AuditLogEntry, DatabaseEngine, GatedRoom, UserProfile};
use crate::gatekeeper::{TextGatekeeper, ThreatVerdict};
use crate::media::{MediaInspector, MediaPayload};
use crate::pipeline::alerts::{
    send_logs_evidence, send_mod_alert, send_owner_diagnostic, send_user_notification,
};
use crate::pipeline::apartments::triage_forum_message;
use crate::pipeline::leveling::{broadcast_level_up, XpWriteBackBuffer};
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
    pub xp_buffer: Arc<XpWriteBackBuffer>,
}

impl BotContainer {
    pub async fn bootstrap(
        db: Arc<DatabaseEngine>,
        config: Arc<GuildConfig>,
        classifier_url: String,
    ) -> Result<Arc<Self>> {
        let gatekeeper = Arc::new(TextGatekeeper::new());
        if let Ok(rules) = db.fetch_dynamic_rules().await {
            let mut ban_patterns = Vec::new();
            let mut delete_patterns = Vec::new();
            for r in rules {
                if r.action.to_lowercase() == "ban" {
                    ban_patterns.push(r.pattern);
                } else {
                    delete_patterns.push(r.pattern);
                }
            }
            let _ = gatekeeper.reload_dynamic_rules(&ban_patterns, &delete_patterns);
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

        let xp_buffer = Arc::new(XpWriteBackBuffer::new());

        Ok(Arc::new(Self {
            config,
            gatekeeper,
            db,
            whitelist,
            media_inspector,
            scan_queue,
            plugin_engine,
            blacklisted_dhashes,
            xp_buffer,
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
        crate::cluster::p2p::IS_GATEWAY_HEALTHY.store(true, Ordering::Relaxed);

        let c = get_container(&ctx).await;
        info!(
            "Sebastian The Butler Online. Registering commands for Guild: {}",
            c.config.authorized_guild_id
        );

        let guild_id = GuildId::new(c.config.authorized_guild_id);
        let mut commands = vec![
            CreateCommand::new("profile")
                .description("View Chill Zone virtual passport")
                .add_option(
                    CreateCommandOption::new(CommandOptionType::User, "user", "Target member")
                        .required(false),
                ),
            CreateCommand::new("profile-edit")
                .description("Configure country, age group, or bio")
                .add_option(
                    CreateCommandOption::new(CommandOptionType::String, "country", "ISO-2 Country code (e.g. RS, US, DE)")
                        .required(false),
                )
                .add_option(
                    CreateCommandOption::new(CommandOptionType::String, "age", "Age group (18-19, 20-24, 25-29, 30-34, 35-39, 40-44, 45-49, 50+)")
                        .required(false),
                )
                .add_option(
                    CreateCommandOption::new(CommandOptionType::String, "bio", "Custom markdown bio (up to 2000 chars)")
                        .required(false),
                ),
            CreateCommand::new("room-owner-set")
                .description("Staff: manage room owner or lock status")
                .add_option(
                    CreateCommandOption::new(CommandOptionType::Channel, "thread", "Forum thread channel")
                        .required(true),
                )
                .add_option(
                    CreateCommandOption::new(CommandOptionType::String, "action", "Action: assign, clear, lock, unlock")
                        .required(true),
                )
                .add_option(
                    CreateCommandOption::new(CommandOptionType::User, "user", "New owner (if assigning)")
                        .required(false),
                ),
            CreateCommand::new("room-claim")
                .description("Claim ownership of this forum thread"),
            CreateCommand::new("room-gate")
                .description("Set allowed age brackets for this apartment (comma separated)")
                .add_option(
                    CreateCommandOption::new(CommandOptionType::String, "brackets", "e.g. 20-24, 25-29")
                        .required(true),
                ),
            CreateCommand::new("xp-set")
                .description("Owner: manually adjust user level for parity")
                .add_option(
                    CreateCommandOption::new(CommandOptionType::User, "user", "Target member")
                        .required(true),
                )
                .add_option(
                    CreateCommandOption::new(CommandOptionType::Integer, "level", "Target level (0-100)")
                        .required(true),
                ),
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
            CreateCommand::new("test-dms")
                .description("Owner only: Send all sample notification templates to your DM"),
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
                    CreateCommandOption::new(CommandOptionType::String, "input", "Image URL or SHA-256 Hash")
                        .required(false),
                )
                .add_option(
                    CreateCommandOption::new(CommandOptionType::Attachment, "file", "Upload image directly")
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

        dispatch_plugin_event(&c, "member_join", serde_json::json!({
            "guild_id": member.guild_id.get(),
            "user_id": user_id,
            "username": &member.user.name
        }));

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
            // ADVISORY INVARIANT: Alert moderators with evidence; do not execute automated ban
            send_mod_alert(
                &ctx,
                &c.config,
                "🚨 Flagged Name Violation on Join",
                &format!("User <@{}> joined with illicit name `{}`. Human review required.", user_id, eval.offending_name),
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

    async fn guild_member_update(
        &self,
        ctx: Context,
        _old_if_available: Option<Member>,
        new: Option<Member>,
        event: GuildMemberUpdateEvent,
    ) {
        let c = get_container(&ctx).await;
        if !c.config.is_authorized_guild(event.guild_id.get()) {
            return;
        }

        let user_id = event.user.id.get();
        let nickname = event.nick.as_deref().unwrap_or("");
        let global_name = event.user.global_name.as_deref().unwrap_or("");
        let username = &event.user.name;

        let eval = evaluate_member_names(
            &c.gatekeeper,
            &c.whitelist,
            user_id,
            username,
            global_name,
            nickname,
        )
        .await;

        match eval.verdict {
            ThreatVerdict::InstantBan => {
                // ADVISORY INVARIANT: Reset nickname if possible and alert moderators
                if let Some(ref member) = new {
                    if member.nick.is_some() {
                        let _ = event.guild_id.edit_member(&ctx.http, user_id, EditMember::new().nickname("")).await;
                    }
                }
                send_mod_alert(
                    &ctx,
                    &c.config,
                    "🚨 Name Violation on Update",
                    &format!("User <@{}> updated name to offensive identifier `{}`. Human review required.", user_id, eval.offending_name),
                    user_id,
                )
                .await;
            }
            ThreatVerdict::DeleteOnly => {
                if let Some(ref member) = new {
                    if member.nick.is_some() {
                        let _ = event.guild_id.edit_member(&ctx.http, user_id, EditMember::new().nickname("")).await;
                    }
                }
                send_mod_alert(
                    &ctx,
                    &c.config,
                    "Nickname Reset",
                    &format!("Reset nickname for <@{}> (contained `{}`)", user_id, eval.offending_name),
                    user_id,
                )
                .await;
            }
            ThreatVerdict::Safe => {}
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
        dispatch_plugin_event(&c, "member_leave", serde_json::json!({
            "guild_id": guild_id.get(),
            "user_id": user.id.get(),
            "username": &user.name
        }));
    }

    async fn voice_state_update(
        &self,
        ctx: Context,
        old: Option<VoiceState>,
        new: VoiceState,
    ) {
        let c = get_container(&ctx).await;
        dispatch_plugin_event(&c, "voice_state_update", serde_json::json!({
            "user_id": new.user_id.get(),
            "guild_id": new.guild_id.map(|g| g.get()),
            "channel_id": new.channel_id.map(|c| c.get()),
            "old_channel_id": old.and_then(|o| o.channel_id.map(|c| c.get())),
            "self_mute": new.self_mute,
            "self_deaf": new.self_deaf
        }));
    }

    async fn reaction_add(&self, ctx: Context, reaction: Reaction) {
        let c = get_container(&ctx).await;
        dispatch_plugin_event(&c, "reaction_add", serde_json::json!({
            "user_id": reaction.user_id.map(|u| u.get()),
            "channel_id": reaction.channel_id.get(),
            "message_id": reaction.message_id.get(),
            "emoji": reaction.emoji.as_data()
        }));
    }

    async fn reaction_remove(&self, ctx: Context, reaction: Reaction) {
        let c = get_container(&ctx).await;
        dispatch_plugin_event(&c, "reaction_remove", serde_json::json!({
            "user_id": reaction.user_id.map(|u| u.get()),
            "channel_id": reaction.channel_id.get(),
            "message_id": reaction.message_id.get(),
            "emoji": reaction.emoji.as_data()
        }));
    }

    async fn message(&self, ctx: Context, msg: Message) {
        if msg.author.id == ctx.cache.current_user().id {
            return;
        }
        let c = get_container(&ctx).await;
        if msg.guild_id != Some(GuildId::new(c.config.authorized_guild_id)) {
            return;
        }

        // 1. FORUM APARTMENTS TRIAGE
        if triage_forum_message(&ctx, &c, &msg).await {
            return;
        }

        // 2. DISPATCH PLUGIN EVENTS
        dispatch_plugin_event(&c, "message_create", serde_json::json!({
            "id": msg.id.get(),
            "channel_id": msg.channel_id.get(),
            "author_id": msg.author.id.get(),
            "author_name": &msg.author.name,
            "content": &msg.content,
            "is_bot": msg.author.bot
        }));

        // 3. SECURITY GUARDS
        if guard_author_names(&ctx, &c, &msg).await {
            return;
        }
        if guard_author_pfp(&ctx, &c, &msg).await {
            return;
        }
        inspect_message_media(&ctx, &c, &msg).await;

        // 4. NATIVE LEVELING ACCUMULATION
        if let Some((user_id, current_xp)) = c.xp_buffer.process_chat_message(&msg).await {
            let xp_64 = current_xp as u64;
            let target_level = ((xp_64 as f64 / 100.0).sqrt() as u32).min(100);
            if xp_64 >= XpWriteBackBuffer::xp_for_level(target_level) && target_level > 0 {
                broadcast_level_up(&ctx, user_id, target_level).await;
            }
        }
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
        c.plugin_engine.dispatch_event(event_name, &data.to_string());
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
            send_mod_alert(
                ctx,
                &c.config,
                "🚨 Message Removed (Name Violation)",
                &format!("Removed message from <@{}> for critical pattern `{}`. Human review advised.", author_id, eval.offending_name),
                author_id,
            )
            .await;
            true
        }
        ThreatVerdict::DeleteOnly => {
            let _ = msg.delete(&ctx.http).await;
            send_mod_alert(
                ctx,
                &c.config,
                "Message Removed",
                &format!("Removed message from <@{}> for `{}`", author_id, eval.offending_name),
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
            if !c.whitelist.is_image_safe(&payload.sha256, payload.dhash).await
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
                            &format!("User <@{}> avatar flagged ({:.1}%)", user_id, resp.confidence.nsfw),
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
                                    &format!("Removed from <@{}> ({:.1}%)", author_id, resp.confidence.nsfw),
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

    match cmd.data.name.as_str() {
        "profile" => cmd_profile(ctx, c, &cmd).await,
        "profile-edit" => cmd_profile_edit(ctx, c, &cmd).await,
        "room-claim" => cmd_room_claim(ctx, c, &cmd).await,
        "room-gate" => cmd_room_gate(ctx, c, &cmd).await,
        "room-owner-set" => {
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
            cmd_room_owner_set(ctx, c, &cmd).await;
        }
        "xp-set" => {
            if !c.config.is_owner(caller_id) {
                let _ = cmd
                    .create_response(
                        &ctx.http,
                        CreateInteractionResponse::Message(
                            CreateInteractionResponseMessage::new()
                                .content("Owner role required.")
                                .ephemeral(true),
                        ),
                    )
                    .await;
                return;
            }
            cmd_xp_set(ctx, c, &cmd).await;
        }
        "test-name" => cmd_test_name(ctx, c, &cmd).await,
        "test-pfp" => cmd_test_pfp(ctx, c, &cmd).await,
        "test-dms" => cmd_test_dms(ctx, c, &cmd).await,
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
                    info!("Executing /{} from plugin '{}' for user {}", plugin_cmd, manifest.name, caller_id);
                    let opts_json = serde_json::to_string(&cmd.data.options).unwrap_or_default();
                    match c.plugin_engine.execute_slash_command(
                        &manifest.name,
                        plugin_cmd,
                        &opts_json,
                    ) {
                        Ok(reply) => {
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
                                .content("Command acknowledged.")
                                .ephemeral(true),
                        ),
                    )
                    .await;
            }
        }
    }
}

// =============================================================================
// COMMAND HANDLERS
// =============================================================================

async fn cmd_profile(ctx: &Context, c: &BotContainer, cmd: &CommandInteraction) {
    let mut target_user_id = cmd.user.id.get();
    let mut target_name = cmd.user.name.clone();

    for opt in &cmd.data.options {
        if opt.name == "user" {
            if let CommandDataOptionValue::User(uid) = &opt.value {
                target_user_id = uid.get();
                if let Some(u) = cmd.data.resolved.users.get(uid) {
                    target_name = u.name.clone();
                }
            }
        }
    }

    let profile = c.db.fetch_user_profile(target_user_id).await.unwrap_or(None);

    let (country, continent, age_group, bio, level, xp, points) = match profile {
        Some(p) => (
            p.country_name.unwrap_or_else(|| "Unspecified".into()),
            p.continent.unwrap_or_else(|| "Unspecified".into()),
            p.age_bracket.unwrap_or_else(|| "Unspecified".into()),
            p.custom_bio,
            p.level,
            p.xp,
            p.points,
        ),
        None => (
            "Unspecified".into(),
            "Unspecified".into(),
            "Unspecified".into(),
            "This member has not customized their Chill Zone profile yet.".into(),
            0,
            0,
            0,
        ),
    };

    let embed = CreateEmbed::new()
        .title(format!("Chill Zone Passport // {}", target_name))
        .field("Continent", continent, true)
        .field("Country", country, true)
        .field("Age Group", age_group, true)
        .field("Server Rank", format!("Level {} ({} XP)", level, xp), true)
        .field("Cosmetic Points", points.to_string(), true)
        .description(if bio.is_empty() { "No bio set." } else { &bio })
        .color(0xe05638)
        .footer(serenity::builder::CreateEmbedFooter::new(
            "Use /profile-edit to customize your identity",
        ));

    let _ = cmd
        .create_response(
            &ctx.http,
            CreateInteractionResponse::Message(
                CreateInteractionResponseMessage::new().embed(embed),
            ),
        )
        .await;
}

async fn cmd_profile_edit(ctx: &Context, c: &BotContainer, cmd: &CommandInteraction) {
    let user_id = cmd.user.id.get();
    let mut country_code_opt = None;
    let mut age_opt = None;
    let mut bio_opt = None;

    for opt in &cmd.data.options {
        if opt.name == "country" {
            if let CommandDataOptionValue::String(s) = &opt.value {
                country_code_opt = Some(s.trim().to_uppercase());
            }
        } else if opt.name == "age" {
            if let CommandDataOptionValue::String(s) = &opt.value {
                age_opt = Some(s.trim().to_string());
            }
        } else if opt.name == "bio" {
            if let CommandDataOptionValue::String(s) = &opt.value {
                bio_opt = Some(s.trim().to_string());
            }
        }
    }

    let mut profile = c.db.fetch_user_profile(user_id).await.unwrap_or(None).unwrap_or(UserProfile {
        user_id,
        continent: None,
        country_code: None,
        country_name: None,
        age_bracket: None,
        custom_bio: String::new(),
        xp: 0,
        level: 0,
        points: 0,
        updated_at: mongodb::bson::DateTime::now(),
    });

    if let Some(ref code) = country_code_opt {
        if let Some(entry) = lookup_country_by_code(code) {
            profile.country_code = Some(entry.code.to_string());
            profile.country_name = Some(entry.name.to_string());
            profile.continent = Some(entry.continent.as_str().to_string());
        } else {
            let _ = cmd
                .create_response(
                    &ctx.http,
                    CreateInteractionResponse::Message(
                        CreateInteractionResponseMessage::new()
                            .content("Invalid ISO-2 country code. Valid examples: `RS`, `US`, `DE`, `FR`, `JP`.")
                            .ephemeral(true),
                    ),
                )
                .await;
            return;
        }
    }

    if let Some(ref age_str) = age_opt {
        if let Some(bracket) = AgeBracket::from_str_strict(age_str) {
            profile.age_bracket = Some(bracket.as_str().to_string());
        } else {
            let _ = cmd
                .create_response(
                    &ctx.http,
                    CreateInteractionResponse::Message(
                        CreateInteractionResponseMessage::new()
                            .content("Invalid age group. Valid: `18-19`, `20-24`, `25-29`, `30-34`, `35-39`, `40-44`, `45-49`, `50+`.")
                            .ephemeral(true),
                    ),
                )
                .await;
            return;
        }
    }

    if let Some(bio) = bio_opt {
        if bio.len() > 2000 {
            let _ = cmd
                .create_response(
                    &ctx.http,
                    CreateInteractionResponse::Message(
                        CreateInteractionResponseMessage::new()
                            .content("Bio exceeds maximum bound of 2000 characters.")
                            .ephemeral(true),
                    ),
                )
                .await;
            return;
        }
        profile.custom_bio = bio;
    }

    profile.updated_at = mongodb::bson::DateTime::now();
    let _ = c.db.save_user_profile(profile).await;

    let _ = cmd
        .create_response(
            &ctx.http,
            CreateInteractionResponse::Message(
                CreateInteractionResponseMessage::new()
                    .content("Chill Zone profile updated successfully! View with `/profile`.")
                    .ephemeral(true),
            ),
        )
        .await;
}

async fn cmd_room_claim(ctx: &Context, c: &BotContainer, cmd: &CommandInteraction) {
    let caller_id = cmd.user.id.get();
    let channel_id = cmd.channel_id;

    let Ok(channel) = channel_id.to_channel(&ctx.http).await else {
        return;
    };
    let Some(guild_channel) = channel.guild() else {
        return;
    };

    if !matches!(
        guild_channel.kind,
        serenity::model::channel::ChannelType::PublicThread
            | serenity::model::channel::ChannelType::PrivateThread
    ) {
        let _ = cmd
            .create_response(
                &ctx.http,
                CreateInteractionResponse::Message(
                    CreateInteractionResponseMessage::new()
                        .content("This command must be invoked inside a forum apartment thread.")
                        .ephemeral(true),
                ),
            )
            .await;
        return;
    }

    let thread_id = channel_id.get();
    let mut room = c.db.fetch_gated_room(thread_id).await.unwrap_or(None).unwrap_or(GatedRoom {
        channel_id: thread_id,
        owner_id: None,
        allowed_brackets: Vec::new(),
        is_locked: false,
        created_at: mongodb::bson::DateTime::now(),
        updated_at: mongodb::bson::DateTime::now(),
    });

    if let Some(existing_owner) = room.owner_id {
        let reply = if existing_owner == caller_id {
            "You are already the designated owner of this apartment."
        } else {
            "This apartment is already owned. Ownership transfers require server staff."
        };
        let _ = cmd
            .create_response(
                &ctx.http,
                CreateInteractionResponse::Message(
                    CreateInteractionResponseMessage::new().content(reply).ephemeral(true),
                ),
            )
            .await;
        return;
    }

    if guild_channel.owner_id != Some(UserId::new(caller_id)) && !c.config.is_owner(caller_id) {
        let _ = cmd
            .create_response(
                &ctx.http,
                CreateInteractionResponse::Message(
                    CreateInteractionResponseMessage::new()
                        .content("Only the original creator of this thread can claim ownership.")
                        .ephemeral(true),
                ),
            )
            .await;
        return;
    }

    room.owner_id = Some(caller_id);
    room.updated_at = mongodb::bson::DateTime::now();
    let _ = c.db.save_gated_room(room).await;

    let _ = cmd
        .create_response(
            &ctx.http,
            CreateInteractionResponse::Message(
                CreateInteractionResponseMessage::new()
                    .content(format!("Ownership bound! <@{}> is now the owner of this apartment.", caller_id)),
            ),
        )
        .await;
}

async fn cmd_room_gate(ctx: &Context, c: &BotContainer, cmd: &CommandInteraction) {
    let caller_id = cmd.user.id.get();
    let channel_id = cmd.channel_id;
    let mut brackets_str = String::new();

    for opt in &cmd.data.options {
        if opt.name == "brackets" {
            if let CommandDataOptionValue::String(s) = &opt.value {
                brackets_str = s.clone();
            }
        }
    }

    let thread_id = channel_id.get();
    let mut room = c.db.fetch_gated_room(thread_id).await.unwrap_or(None).unwrap_or(GatedRoom {
        channel_id: thread_id,
        owner_id: None,
        allowed_brackets: Vec::new(),
        is_locked: false,
        created_at: mongodb::bson::DateTime::now(),
        updated_at: mongodb::bson::DateTime::now(),
    });

    let caller_roles: Vec<u64> = cmd
        .member
        .as_ref()
        .map_or(Vec::new(), |m| m.roles.iter().map(|r| r.get()).collect());

    if room.owner_id != Some(caller_id) && !c.config.is_staff(caller_id, &caller_roles) {
        let _ = cmd
            .create_response(
                &ctx.http,
                CreateInteractionResponse::Message(
                    CreateInteractionResponseMessage::new()
                        .content("Only the room owner or staff can configure apartment gates.")
                        .ephemeral(true),
                ),
            )
            .await;
        return;
    }

    let parsed_brackets: Vec<String> = brackets_str
        .split(',')
        .filter_map(|s| AgeBracket::from_str_strict(s).map(|b| b.as_str().to_string()))
        .collect();

    if parsed_brackets.is_empty() {
        let _ = cmd
            .create_response(
                &ctx.http,
                CreateInteractionResponse::Message(
                    CreateInteractionResponseMessage::new()
                        .content("No valid age brackets parsed. Example: `/room-gate brackets: 20-24, 25-29`.")
                        .ephemeral(true),
                ),
            )
            .await;
        return;
    }

    room.allowed_brackets = parsed_brackets.clone();
    room.updated_at = mongodb::bson::DateTime::now();
    let _ = c.db.save_gated_room(room).await;

    let _ = cmd
        .create_response(
            &ctx.http,
            CreateInteractionResponse::Message(
                CreateInteractionResponseMessage::new()
                    .content(format!("Apartment gates updated! Allowed groups: `{}`", parsed_brackets.join(", "))),
            ),
        )
        .await;
}

async fn cmd_room_owner_set(ctx: &Context, c: &BotContainer, cmd: &CommandInteraction) {
    let mut target_thread_id = 0u64;
    let mut target_user_id = None;
    let mut action = String::new();

    for opt in &cmd.data.options {
        if opt.name == "thread" {
            if let CommandDataOptionValue::Channel(cid) = &opt.value {
                target_thread_id = cid.get();
            }
        } else if opt.name == "user" {
            if let CommandDataOptionValue::User(uid) = &opt.value {
                target_user_id = Some(uid.get());
            }
        } else if opt.name == "action" {
            if let CommandDataOptionValue::String(s) = &opt.value {
                action = s.to_lowercase();
            }
        }
    }

    if target_thread_id == 0 {
        let _ = cmd
            .create_response(
                &ctx.http,
                CreateInteractionResponse::Message(
                    CreateInteractionResponseMessage::new().content("Thread parameter required.").ephemeral(true),
                ),
            )
            .await;
        return;
    }

    let mut room = c.db.fetch_gated_room(target_thread_id).await.unwrap_or(None).unwrap_or(GatedRoom {
        channel_id: target_thread_id,
        owner_id: None,
        allowed_brackets: Vec::new(),
        is_locked: false,
        created_at: mongodb::bson::DateTime::now(),
        updated_at: mongodb::bson::DateTime::now(),
    });

    match action.as_str() {
        "assign" => {
            room.owner_id = target_user_id;
            room.updated_at = mongodb::bson::DateTime::now();
            let _ = c.db.save_gated_room(room).await;
            let _ = cmd.create_response(&ctx.http, CreateInteractionResponse::Message(CreateInteractionResponseMessage::new().content(format!("Assigned owner of thread <#{}> to <@{}>.", target_thread_id, target_user_id.unwrap_or(0))))).await;
        }
        "clear" => {
            room.owner_id = None;
            room.updated_at = mongodb::bson::DateTime::now();
            let _ = c.db.save_gated_room(room).await;
            let _ = cmd.create_response(&ctx.http, CreateInteractionResponse::Message(CreateInteractionResponseMessage::new().content(format!("Thread <#{}> is now ownerless.", target_thread_id)))).await;
        }
        "lock" => {
            room.is_locked = true;
            room.updated_at = mongodb::bson::DateTime::now();
            let _ = c.db.save_gated_room(room).await;
            let _ = cmd.create_response(&ctx.http, CreateInteractionResponse::Message(CreateInteractionResponseMessage::new().content(format!("Thread <#{}> is now locked to non-staff.", target_thread_id)))).await;
        }
        "unlock" => {
            room.is_locked = false;
            room.updated_at = mongodb::bson::DateTime::now();
            let _ = c.db.save_gated_room(room).await;
            let _ = cmd.create_response(&ctx.http, CreateInteractionResponse::Message(CreateInteractionResponseMessage::new().content(format!("Thread <#{}> unlocked.", target_thread_id)))).await;
        }
        _ => {
            let _ = cmd.create_response(&ctx.http, CreateInteractionResponse::Message(CreateInteractionResponseMessage::new().content("Invalid action: use `assign`, `clear`, `lock`, or `unlock`.").ephemeral(true))).await;
        }
    }
}

async fn cmd_xp_set(ctx: &Context, c: &BotContainer, cmd: &CommandInteraction) {
    let mut target_id = 0u64;
    let mut target_level = 0u32;

    for opt in &cmd.data.options {
        if opt.name == "user" {
            if let CommandDataOptionValue::User(uid) = &opt.value {
                target_id = uid.get();
            }
        } else if opt.name == "level" {
            if let CommandDataOptionValue::Integer(lvl) = &opt.value {
                target_level = (*lvl).clamp(0, 100) as u32;
            }
        }
    }

    let calculated_xp = XpWriteBackBuffer::xp_for_level(target_level);
    let mut profile = c.db.fetch_user_profile(target_id).await.unwrap_or(None).unwrap_or(UserProfile {
        user_id: target_id,
        continent: None,
        country_code: None,
        country_name: None,
        age_bracket: None,
        custom_bio: String::new(),
        xp: calculated_xp,
        level: target_level,
        points: calculated_xp,
        updated_at: mongodb::bson::DateTime::now(),
    });

    profile.level = target_level;
    profile.xp = calculated_xp;
    profile.updated_at = mongodb::bson::DateTime::now();
    let _ = c.db.save_user_profile(profile).await;

    let _ = cmd
        .create_response(
            &ctx.http,
            CreateInteractionResponse::Message(
                CreateInteractionResponseMessage::new()
                    .content(format!("Level for <@{}> calibrated to **Level {}** ({} XP).", target_id, target_level, calculated_xp)),
            ),
        )
        .await;
}

async fn cmd_test_dms(ctx: &Context, c: &BotContainer, cmd: &CommandInteraction) {
    let caller_id = cmd.user.id.get();
    if !c.config.is_owner(caller_id) {
        let _ = cmd
            .create_response(
                &ctx.http,
                CreateInteractionResponse::Message(
                    CreateInteractionResponseMessage::new()
                        .content("Owner role required.")
                        .ephemeral(true),
                ),
            )
            .await;
        return;
    }

    let _ = cmd.defer_ephemeral(&ctx.http).await;
    let owner_id = c.config.owner_user_id;

    send_user_notification(
        &ctx.http,
        owner_id,
        "[Template 1/5] Notice Regarding Your Profile Picture",
        "Your message was held because your profile picture is currently being reviewed by server safety filters.",
    ).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    send_user_notification(
        &ctx.http,
        owner_id,
        "[Template 2/5] Profile Picture Verified Safe",
        "Your profile picture has been reviewed by server staff and marked safe. Your permissions are fully restored!",
    ).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    send_user_notification(
        &ctx.http,
        owner_id,
        "[Template 3/5] Notice from Server Staff",
        "This is an official communication from server staff regarding community safety.",
    ).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    send_user_notification(
        &ctx.http,
        owner_id,
        "[Template 4/5] Notice Regarding Your Message",
        "Your message was held because an uploaded image or asset is currently being reviewed by server safety filters.",
    ).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    send_owner_diagnostic(
        &ctx.http,
        &c.config,
        "[Template 5/5] Sample Diagnostic Proof",
        "Target: <@1015600709724557434>\nSHA-256: 407d63b271139ac80b1556eac007c167bdf60f36e02613f9893043ccf531d12d\ndHash: 8c4baba3c793c3e3\nStatus: Verified Safe\nLatency: 34ms",
    ).await;

    let _ = cmd
        .edit_response(
            &ctx.http,
            EditInteractionResponse::new().content("All 5 sample notification templates have been sent to your private messages."),
        )
        .await;
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

    let is_whitelisted = c.whitelist.is_image_safe(&payload.sha256, payload.dhash).await;
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

    let _ = c.db.add_whitelisted_user(&target_name, &cmd.user.name, &reason).await;
    let _ = c.db.add_whitelisted_user(&target_id.to_string(), &cmd.user.name, &reason).await;
    c.whitelist.add_user(&target_name).await;
    c.whitelist.add_user(&target_id.to_string()).await;

    send_owner_diagnostic(
        &ctx.http,
        &c.config,
        "User Whitelisted",
        &format!("Target: <@{}> (`{}`)\nStaff: {}\nReason: `{}`", target_id, target_name, cmd.user.name, reason),
    ).await;

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
        let _ = c.db.add_whitelisted_image(&payload.sha256, payload.dhash, &label, &cmd.user.name).await;
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
                target_id, target_name, cmd.user.name, payload.sha256, payload.dhash, if notified { "Delivered" } else { "Closed DMs" }
            ),
        ).await;

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
                attachment_url = cmd.data.resolved.attachments.get(att_id).map(|a| a.url.clone());
            }
        } else if opt.name == "label" {
            if let CommandDataOptionValue::String(l) = &opt.value {
                label = l.clone();
            }
        }
    }

    if raw_input.len() == 64 && raw_input.chars().all(|c| c.is_ascii_hexdigit()) {
        let sha_clean = raw_input.to_lowercase();
        let _ = c.db.add_whitelisted_image(&sha_clean, 0, &label, &cmd.user.name).await;
        let _ = c.db.revoke_blacklisted_image(&sha_clean).await;
        c.whitelist.add_image(&sha_clean, 0).await;

        send_owner_diagnostic(
            &ctx.http,
            &c.config,
            "Direct SHA-256 Whitelisted",
            &format!("SHA-256: `{}`\nStaff: {}\nLabel: `{}`", sha_clean, cmd.user.name, label),
        ).await;

        let reply = format!(
            "**Image Whitelisted:**\n> **SHA-256:** `{}`\n> **Label:** `{}`\nThis image is marked safe.",
            sha_clean, label
        );
        let _ = cmd.edit_response(&ctx.http, EditInteractionResponse::new().content(reply)).await;
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
                EditInteractionResponse::new().content("Provide a valid image URL, attachment, or 64-character SHA-256 hash."),
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

    let _ = c.db.add_whitelisted_image(&payload.sha256, payload.dhash, &label, &cmd.user.name).await;
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
    ).await;

    let reply = format!(
        "**Image Whitelisted:**\n> **SHA-256:** `{}`\n> **dHash:** `{:016x}`\n> **Label:** `{}`\nThis image is marked safe.",
        payload.sha256, payload.dhash, label
    );
    let _ = cmd.edit_response(&ctx.http, EditInteractionResponse::new().content(reply)).await;
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
    ).await;

    send_owner_diagnostic(
        &ctx.http,
        &c.config,
        "User Notified",
        &format!(
            "Staff: {}\nTarget: <@{}>\nStatus: {}\nMessage: {}",
            cmd.user.name, target_id, if delivered { "Delivered" } else { "Closed DMs" }, message_text
        ),
    ).await;

    let reply = if delivered {
        format!("Notification delivered to <@{}>.", target_id)
    } else {
        format!("Could not send DM to <@{}> (User has DMs closed).", target_id)
    };

    let _ = cmd
        .create_response(
            &ctx.http,
            CreateInteractionResponse::Message(
                CreateInteractionResponseMessage::new().content(reply).ephemeral(true),
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
        info!("Banned user {} from Guild {}. Reason: {}", user_id, guild_id, reason);
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
