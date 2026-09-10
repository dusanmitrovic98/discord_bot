use serenity::prelude::*;
use std::env;
use std::sync::Arc;
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

    info!("Initializing Aegis Bastion Bot Core...");

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

    let intents = GatewayIntents::GUILDS
        | GatewayIntents::GUILD_MEMBERS
        | GatewayIntents::GUILD_MESSAGES
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
