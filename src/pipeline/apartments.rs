//! # Forum Apartments Room Governance, Age Triage & Inactive Sweeper

use serenity::builder::{CreateMessage, EditThread};
use serenity::http::Http;
use serenity::model::channel::{ChannelType, Message};
use serenity::model::id::ChannelId;
use serenity::prelude::*;
use tracing::{info, warn};

use crate::bot::BotContainer;
use crate::constants::geo::AgeBracket;
use crate::db::DatabaseEngine;

pub async fn triage_forum_message(ctx: &Context, c: &BotContainer, msg: &Message) -> bool {
    let channel_id = msg.channel_id;

    // 1. ISOLATED SYNCHRONOUS CACHE PROBE (NASA Rule 3: Guard dropped before any .await)
    #[allow(deprecated)]
    let cached_info = {
        ctx.cache.channel(channel_id).map(|ch| {
            let is_th = matches!(
                ch.kind,
                ChannelType::PublicThread | ChannelType::PrivateThread | ChannelType::NewsThread
            );
            (is_th, ch.parent_id)
        })
    };

    // 2. FALLBACK TO ASYNC HTTP IF CACHE MISS
    let (is_thread, parent_id) = match cached_info {
        Some(info) => info,
        None => {
            let Ok(channel) = channel_id.to_channel(&ctx.http).await else {
                return false;
            };
            let Some(gc) = channel.guild() else {
                return false;
            };
            let is_th = matches!(
                gc.kind,
                ChannelType::PublicThread | ChannelType::PrivateThread | ChannelType::NewsThread
            );
            (is_th, gc.parent_id)
        }
    };

    if !is_thread {
        return false;
    }

    if parent_id != Some(ChannelId::new(c.config.welcome_channel_id))
        && parent_id.map(|p| p.get()) != Some(1424824152417767628)
    {
        return false;
    }

    let thread_id = channel_id.get();
    let author_id = msg.author.id.get();

    // Touch activity timestamp in background task
    let db_touch = c.db.clone();
    tokio::spawn(async move {
        let _ = db_touch.touch_room_activity(thread_id).await;
    });

    // Staff exemption
    let caller_roles: Vec<u64> = msg
        .member
        .as_ref()
        .map_or(Vec::new(), |m| m.roles.iter().map(|r| r.get()).collect());

    if c.config.is_staff(author_id, &caller_roles) {
        return false;
    }

    let Ok(Some(room)) = c.db.fetch_gated_room(thread_id).await else {
        return false;
    };

    if room.is_locked {
        let _ = msg.delete(&ctx.http).await;
        return true;
    }

    if room.allowed_brackets.is_empty() {
        return false;
    }

    let author_profile = c.db.fetch_user_profile(author_id).await.unwrap_or(None);
    let author_bracket = author_profile
        .as_ref()
        .and_then(|p| p.age_bracket.as_deref())
        .and_then(AgeBracket::from_str_strict);

    let is_compliant = match author_bracket {
        Some(bracket) => room
            .allowed_brackets
            .iter()
            .any(|b| AgeBracket::from_str_strict(b) == Some(bracket)),
        None => false,
    };

    if !is_compliant {
        let _ = msg.delete(&ctx.http).await;
        warn!(
            "Blocked message from <@{}> in thread {} (Age non-compliant)",
            author_id, thread_id
        );

        let dm_text = format!(
            "Your message in <#{}> was removed because this room is set for age group(s): `{}`.\n\
            Set or adjust your age group using `/profile-edit`.",
            thread_id,
            room.allowed_brackets.join(", ")
        );

        tokio::spawn({
            let http = ctx.http.clone();
            async move {
                crate::pipeline::alerts::send_user_notification(
                    &http,
                    author_id,
                    "Notice Regarding Room Age Criteria",
                    &dm_text,
                )
                .await;
            }
        });

        return true;
    }

    false
}

/// Sweeps apartments inactive for > 30 days and posts a courteous warning to the owner.
pub async fn sweep_inactive_apartments(http: &Http, db: &DatabaseEngine) {
    let Ok(inactive_rooms) = db.fetch_inactive_rooms(30).await else {
        return;
    };

    for room in inactive_rooms {
        let Some(owner_id) = room.owner_id else {
            continue;
        };

        let ch = ChannelId::new(room.channel_id);

        if let Ok(ch_obj) = ch.to_channel(http).await {
            if let Some(mut guild_channel) = ch_obj.guild() {
                if guild_channel.thread_metadata.is_some_and(|m| m.archived) {
                    let _ = guild_channel
                        .edit_thread(http, EditThread::new().archived(false))
                        .await;
                }
            }
        }

        let msg = CreateMessage::new().content(format!(
            "⚠️ <@{}> **Apartment Inactivity Notice**:\n\
            This room has had no activity for over 30 days. To keep \"The Chill Zone\" clean, \
            rooms that remain inactive will eventually be archived or cleared. Post a message to keep this room active!",
            owner_id
        ));

        if ch.send_message(http, msg).await.is_ok() {
            info!(
                "Dispatched 30-day inactivity notice in apartment thread {}",
                room.channel_id
            );
            let _ = db.mark_room_inactivity_warned(room.channel_id).await;
        }
    }
}
