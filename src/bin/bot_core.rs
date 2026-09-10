use serenity::prelude::*;
use std::env;
use std::sync::Arc;
use tracing::{error, info};

use aegis_bastion::bot::{BotContainer, BotContainerKey, Handler};
use aegis_bastion::config::GuildConfig;
use aegis_bastion::db::DatabaseEngine;
use aegis_bastion::gatekeeper::TextGatekeeper;
use aegis_bastion::media::MediaInspector;
use aegis_bastion::plugin_engine::DynamicPluginEngine;
use aegis_bastion::queue::{BoundedScanQueue, ResilientClassifierClient};
use aegis_bastion::whitelist::WhitelistRegistry;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("Initializing Aegis Bastion Bot Core (Refactored Pipeline)...");

    let config = Arc::new(GuildConfig::default());
    let discord_token = env::var("DISCORD_TOKEN").expect("Fatal: DISCORD_TOKEN required");
    let mongo_uri =
        env::var("MONGO_URI").unwrap_or_else(|_| "mongodb://localhost:27017".to_string());
    let classifier_url = env::var("CLASSIFIER_ENDPOINT")
        .unwrap_or_else(|_| "https://sfw-classifier.onrender.com/api/classify".to_string());

    let db = DatabaseEngine::connect(&mongo_uri, "aegis_bastion")
        .await
        .expect("Fatal: Failed connecting to MongoDB cluster");
    let db_arc = Arc::new(db);

    // 1. Threat Rules Sync
    let gatekeeper = Arc::new(TextGatekeeper::new());
    if let Ok(rules) = db_arc.fetch_dynamic_rules().await {
        let patterns: Vec<String> = rules.into_iter().map(|r| r.pattern).collect();
        info!(
            "Synchronized {} dynamic rules from MongoDB.",
            patterns.len()
        );
        let _ = gatekeeper.reload_dynamic_patterns(&patterns);
    }

    // 2. Whitelist Registry Sync
    let whitelist = Arc::new(WhitelistRegistry::new());
    let _ = whitelist.sync_from_db(&db_arc).await;

    // 3. Media Inspector & AI Queue
    let http_client = reqwest::Client::new();
    let media_inspector = Arc::new(MediaInspector::new(
        http_client.clone(),
        config.max_download_size_bytes,
    ));
    let classifier_client = Arc::new(ResilientClassifierClient::new(classifier_url));
    let scan_queue = Arc::new(BoundedScanQueue::new(500, classifier_client));

    // 4. Plugin Engine Sync
    let plugin_engine = Arc::new(DynamicPluginEngine::new());
    if let Ok(plugins) = db_arc.fetch_active_plugins().await {
        for (name, bytecode) in plugins {
            let _ = plugin_engine.hot_swap_plugin(&name, &bytecode);
        }
    }

    let container = Arc::new(BotContainer {
        config,
        gatekeeper,
        db: db_arc,
        whitelist,
        media_inspector,
        scan_queue,
        plugin_engine,
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
        error!("Fatal Discord client runtime error: {:?}", why);
    }
}
