use serenity::prelude::*;
use std::collections::HashSet;
use std::env;
use std::sync::Arc;
use tracing::{error, info};

use aegis_bastion::bot::{BotContainer, BotContainerKey, Handler};
use aegis_bastion::db::DatabaseEngine;
use aegis_bastion::gatekeeper::TextGatekeeper;
use aegis_bastion::plugin_engine::DynamicPluginEngine;
use aegis_bastion::queue::{BoundedScanQueue, ResilientClassifierClient};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("Initializing Aegis Bastion Bot Core...");

    let discord_token = env::var("DISCORD_TOKEN").expect("Fatal: DISCORD_TOKEN required");
    let mongo_uri =
        env::var("MONGO_URI").unwrap_or_else(|_| "mongodb://localhost:27017".to_string());
    let classifier_url = env::var("CLASSIFIER_ENDPOINT")
        .unwrap_or_else(|_| "https://sfw-classifier.onrender.com/api/classify".to_string());

    let db = DatabaseEngine::connect(&mongo_uri, "aegis_bastion")
        .await
        .expect("Fatal: Failed connecting to MongoDB cluster");
    let db_arc = Arc::new(db);

    // 1. Gatekeeper & Dynamic Rules Sync
    let gatekeeper = Arc::new(TextGatekeeper::new());
    if let Ok(rules) = db_arc.fetch_dynamic_rules().await {
        let patterns: Vec<String> = rules.into_iter().map(|r| r.pattern).collect();
        info!(
            "Synchronizing {} dynamic threat rules from MongoDB...",
            patterns.len()
        );
        let _ = gatekeeper.reload_dynamic_patterns(&patterns);
    }

    // 2. Whitelists Sync
    let mut whitelisted_users_set = HashSet::new();
    if let Ok(wl_users) = db_arc.fetch_whitelisted_users().await {
        for u in wl_users {
            whitelisted_users_set.insert(u.identifier.to_lowercase());
        }
    }
    info!(
        "Synchronized {} whitelisted users/IDs into RAM.",
        whitelisted_users_set.len()
    );

    let mut whitelisted_images_set = HashSet::new();
    if let Ok(wl_images) = db_arc.fetch_whitelisted_images().await {
        for img in wl_images {
            whitelisted_images_set.insert(img.sha256);
        }
    }
    info!(
        "Synchronized {} verified safe image hashes into RAM.",
        whitelisted_images_set.len()
    );

    // 3. Plugins Sync
    let plugin_engine = Arc::new(DynamicPluginEngine::new());
    if let Ok(plugins) = db_arc.fetch_active_plugins().await {
        for (name, bytecode) in plugins {
            let _ = plugin_engine.hot_swap_plugin(&name, &bytecode);
        }
    }

    // 4. Queue & Container
    let classifier_client = Arc::new(ResilientClassifierClient::new(classifier_url));
    let scan_queue = Arc::new(BoundedScanQueue::new(500, classifier_client));

    let container = Arc::new(BotContainer {
        gatekeeper,
        db: db_arc,
        scan_queue,
        plugin_engine,
        http_client: reqwest::Client::new(),
        whitelisted_users: Arc::new(tokio::sync::RwLock::new(whitelisted_users_set)),
        whitelisted_images: Arc::new(tokio::sync::RwLock::new(whitelisted_images_set)),
    });

    let intents = GatewayIntents::GUILDS
        | GatewayIntents::GUILD_MEMBERS
        | GatewayIntents::GUILD_MESSAGES
        | GatewayIntents::MESSAGE_CONTENT;

    let mut client = Client::builder(&discord_token, intents)
        .event_handler(Handler)
        .await
        .expect("Fatal: Serenity client creation failed");

    {
        let mut data = client.data.write().await;
        data.insert::<BotContainerKey>(container);
    }

    info!("Bot Core online. Connecting to Discord Gateway...");
    if let Err(why) = client.start().await {
        error!("Fatal Discord client error: {:?}", why);
    }
}
