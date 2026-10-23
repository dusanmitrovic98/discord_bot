//! # Native Anti-Spam Leveling & XP Engine
//!
//! Accumulates chat XP in RAM with 60-second cooldowns, minimum 5 characters,
//! and batch writes back to MongoDB Atlas. Dispatches announcements strictly to #1562094497452785664.

use serenity::builder::{CreateEmbed, CreateMessage};
use serenity::model::channel::Message;
use serenity::model::id::ChannelId;
use serenity::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub const LEVELING_CHANNEL_ID: u64 = 1562094497452785664; // Dedicated #🆙・leveling channel

#[derive(Default)]
pub struct XpWriteBackBuffer {
    pending_xp: Arc<RwLock<HashMap<u64, u32>>>,
    last_chat_ts: Arc<RwLock<HashMap<u64, i64>>>,
}

impl XpWriteBackBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Calculate required cumulative XP for Level L (NASA Rule 2 bounded math).
    pub fn xp_for_level(level: u32) -> u64 {
        let l = level as u64;
        5 * (l * l) + (50 * l) + 100
    }

    pub async fn process_chat_message(&self, msg: &Message) -> Option<(u64, u32)> {
        if msg.author.bot || msg.content.trim().len() < 5 {
            return None;
        }

        let user_id = msg.author.id.get();
        let now = chrono::Utc::now().timestamp();

        {
            let mut ts_guard = self.last_chat_ts.write().await;
            if let Some(&last_ts) = ts_guard.get(&user_id) {
                if now - last_ts < 60 {
                    return None; // 60-second anti-spam cooldown active
                }
            }
            ts_guard.insert(user_id, now);
        }

        let xp_gain = rand::random::<u32>() % 11 + 15; // 15 to 25 XP
        let mut xp_guard = self.pending_xp.write().await;
        let entry = xp_guard.entry(user_id).or_insert(0);
        *entry += xp_gain;

        Some((user_id, *entry))
    }

    pub async fn flush_to_db(&self, db: &crate::db::DatabaseEngine) {
        let mut xp_guard = self.pending_xp.write().await;
        if xp_guard.is_empty() {
            return;
        }

        let snapshot: Vec<(u64, u32)> = xp_guard.drain().collect();
        drop(xp_guard);

        for (uid, xp_gain) in snapshot {
            let _ = db.add_user_xp(uid, xp_gain as u64).await;
        }
    }
}

pub async fn broadcast_level_up(ctx: &Context, user_id: u64, new_level: u32) {
    let channel = ChannelId::new(LEVELING_CHANNEL_ID);
    let embed = CreateEmbed::new()
        .title("LEVEL UP!")
        .description(format!(
            "Congratulations <@{}>! You have reached **Level {}**! GG!",
            user_id, new_level
        ))
        .color(0xe05638)
        .footer(serenity::builder::CreateEmbedFooter::new(
            "Sebastian The Butler // Leveling Mesh",
        ));

    let msg = CreateMessage::new()
        .content(format!("<@{}>", user_id))
        .embed(embed);

    if let Err(e) = channel.send_message(&ctx.http, msg).await {
        tracing::error!("Failed dispatching level-up notice: {}", e);
    }
}
