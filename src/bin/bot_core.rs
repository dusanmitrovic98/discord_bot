//! # Sebastian The Butler - Active Bot Core Binary
//!
//! Hot-swappable child core binary running inside sealed Linux RAM (`memfd_create`).
//! Connects to the Discord Gateway, hosts the background dynamic synchronizer,
//! and runs the multimodal defense and WASM plugin engine.

use serenity::prelude::*;
use std::env;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

use aegis_bastion::bot::{BotContainer, BotContainerKey, Handler};
use aegis_bastion::config::GuildConfig;
use aegis_bastion::db::DatabaseEngine;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("Initializing Sebastian The Butler Core...");

    let token = env::var("DISCORD_TOKEN").expect("Fatal: DISCORD_TOKEN required");
    let mongo_uri =
        env::var("MONGO_URI").unwrap_or_else(|_| "mongodb://localhost:27017".to_string());
    let classifier_url = env::var("CLASSIFIER_ENDPOINT")
        .unwrap_or_else(|_| "https://sfw-classifier.onrender.com/api/classify".to_string());

    let db = DatabaseEngine::connect(&mongo_uri, "aegis_bastion")
        .await
        .expect("Fatal: MongoDB connection failed");
    let container = BotContainer::bootstrap(
        Arc::new(db),
        Arc::new(GuildConfig::default()),
        classifier_url,
    )
    .await
    .expect("Fatal: BotContainer bootstrap failed");

    // =========================================================================
    // BACKGROUND DYNAMIC SYNCHRONIZER (Throttled to 30s to spare MongoDB Atlas)
    // =========================================================================
    let sync_c = container.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;

            // 1. Sync Dynamic Regexes
            if let Ok(rules) = sync_c.db.fetch_dynamic_rules().await {
                let patterns: Vec<String> = rules.into_iter().map(|r| r.pattern).collect();
                let _ = sync_c.gatekeeper.reload_dynamic_patterns(&patterns);
            }

            // 2. Sync Whitelist (Silent in stdout)
            let _ = sync_c.whitelist.sync_from_db(&sync_c.db).await;

            // 3. Sync Blacklisted dHashes
            if let Ok(dhashes) = sync_c.db.fetch_all_dhashes().await {
                let mut guard = sync_c.blacklisted_dhashes.write().await;
                *guard = dhashes;
            }

            // 4. Sync WASM Community Plugins with Full Toggle Parity!
            if let Ok(records) = sync_c.db.fetch_all_plugin_records().await {
                for p in records {
                    if p.enabled {
                        let _ = sync_c
                            .plugin_engine
                            .hot_swap_plugin(&p.name, &p.bytecode.bytes);
                    } else {
                        // Evict disabled plugins from RAM registry immediately
                        sync_c.plugin_engine.unload_plugin(&p.name);
                    }
                }
            }
        }
    });

    let intents = GatewayIntents::GUILDS
        | GatewayIntents::GUILD_MEMBERS
        | GatewayIntents::GUILD_MESSAGES
        | GatewayIntents::GUILD_MESSAGE_REACTIONS
        | GatewayIntents::GUILD_VOICE_STATES
        | GatewayIntents::MESSAGE_CONTENT;

    let mut client = Client::builder(&token, intents)
        .event_handler(Handler)
        .await
        .expect("Fatal: Serenity client creation failed");

    {
        client
            .data
            .write()
            .await
            .insert::<BotContainerKey>(container);
    }

    info!("Bot Core online. Connecting to Discord Gateway...");
    if let Err(e) = client.start().await {
        error!("Fatal Discord gateway error: {:?}", e);
    }
}
