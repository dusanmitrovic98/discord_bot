//! # Forum Apartments Room Governance & Age-Bracket Triage
//!
//! Sub-millisecond inspection of messages posted in Discord Forum threads under #apartments.
//! Operates in advisory mode: drops non-compliant messages and notifies user (no auto-bans).

use serenity::model::channel::{ChannelType, Message};
use serenity::model::id::ChannelId;
use serenity::prelude::*;
use tracing::warn;

use crate::bot::BotContainer;
use crate::constants::geo::AgeBracket;

pub async fn triage_forum_message(ctx: &Context, c: &BotContainer, msg: &Message) -> bool {
    let channel_id = msg.channel_id;

    // Fast-path: Check if this channel is a thread inside the #apartments forum
    let Ok(channel) = channel_id.to_channel(&ctx.http).await else {
        return false;
    };
    let Some(guild_channel) = channel.guild() else {
        return false;
    };

    // Serenity 0.12 Thread Variant Invariant
    let is_thread = matches!(
        guild_channel.kind,
        ChannelType::PublicThread | ChannelType::PrivateThread | ChannelType::NewsThread
    );

    if !is_thread {
        return false;
    }

    if guild_channel.parent_id != Some(ChannelId::new(c.config.welcome_channel_id))
        && guild_channel.parent_id.map(|p| p.get()) != Some(1424824152417767628)
    {
        return false;
    }

    let thread_id = channel_id.get();
    let author_id = msg.author.id.get();

    // Owner and Staff hold omnipotent exemption
    let caller_roles: Vec<u64> = msg
        .member
        .as_ref()
        .map_or(Vec::new(), |m| m.roles.iter().map(|r| r.get()).collect());

    if c.config.is_staff(author_id, &caller_roles) {
        return false;
    }

    let Ok(Some(room)) = c.db.fetch_gated_room(thread_id).await else {
        return false; // Room is open and unconfigured
    };

    if room.is_locked {
        let _ = msg.delete(&ctx.http).await;
        return true;
    }

    if room.allowed_brackets.is_empty() {
        return false;
    }

    // Verify author's age bracket from virtual profile
    let author_profile = c.db.fetch_user_profile(author_id).await.unwrap_or(None);
    let author_bracket = author_profile
        .as_ref()
        .and_then(|p| p.age_bracket.as_deref())
        .and_then(AgeBracket::from_str_strict);

    let is_compliant = match author_bracket {
        Some(bracket) => room
            .allowed_brackets
            .iter()
            .any(|b| AgeBracket::from_str_strict(b).map_or(false, |allowed| allowed == bracket)),
        None => false, // No age bracket set
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
