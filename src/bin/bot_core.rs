use serenity::prelude::*;
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
    // 1. Initialize Tracing & Telemetry
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    info!("Initializing Aegis Bastion Bot Core...");

    // 2. Load Required Environment Variables
    let discord_token =
        env::var("DISCORD_TOKEN").expect("Fatal: DISCORD_TOKEN environment variable is required");
    let mongo_uri =
        env::var("MONGO_URI").unwrap_or_else(|_| "mongodb://localhost:27017".to_string());
    let classifier_url = env::var("CLASSIFIER_ENDPOINT")
        .unwrap_or_else(|_| "https://sfw-classifier.onrender.com/api/classify".to_string());

    // 3. Connect to MongoDB Engine
    let db = DatabaseEngine::connect(&mongo_uri, "aegis_bastion")
        .await
        .expect("Fatal: Failed to connect to MongoDB cluster");
    let db_arc = Arc::new(db);

    // 4. Initialize Local Gatekeeper Heuristics
    let gatekeeper = Arc::new(TextGatekeeper::new());

    // 5. Initialize Sandboxed WASM Plugin Engine and Synchronize from DB
    let plugin_engine = Arc::new(DynamicPluginEngine::new());
    match db_arc.fetch_active_plugins().await {
        Ok(plugins) => {
            info!("Synchronizing {} plugins from MongoDB...", plugins.len());
            for (name, bytecode) in plugins {
                if let Err(e) = plugin_engine.hot_swap_plugin(&name, &bytecode) {
                    error!("Failed to load plugin '{}' into memory: {}", name, e);
                }
            }
        }
        Err(e) => {
            error!("Could not fetch plugins from database: {}", e);
        }
    }

    // 6. Initialize Resilient Classifier Client & Bounded Queue
    let classifier_client = Arc::new(ResilientClassifierClient::new(classifier_url));
    // Spawn background keep-alive pinger for Render free-tier
    classifier_client.clone().spawn_keep_alive();

    // Bounded MPSC Queue: Capacity 500, sequential processing (NASA Rule 2)
    let scan_queue = Arc::new(BoundedScanQueue::new(500, classifier_client));

    // 7. Assemble Unified Container
    let container = Arc::new(BotContainer {
        gatekeeper,
        db: db_arc,
        scan_queue,
        plugin_engine,
        http_client: reqwest::Client::new(),
    });

    // 8. Configure Gateway Intents
    let intents = GatewayIntents::GUILDS
        | GatewayIntents::GUILD_MEMBERS
        | GatewayIntents::GUILD_MESSAGES
        | GatewayIntents::MESSAGE_CONTENT;

    // 9. Build and Start Serenity Discord Client
    let mut client = Client::builder(&discord_token, intents)
        .event_handler(Handler)
        .await
        .expect("Fatal: Error constructing Serenity client");

    {
        let mut data = client.data.write().await;
        data.insert::<BotContainerKey>(container);
    }

    info!("Bot Core online. Connecting to Discord Gateway...");
    if let Err(why) = client.start().await {
        error!("Fatal Discord client runtime error: {:?}", why);
    }
}
