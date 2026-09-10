use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Notify;
use tracing::{error, info, warn};

use aegis_bastion::crypto::CryptoEngine;
use aegis_bastion::db::DatabaseEngine;
use aegis_bastion::supervisor::SupervisorWatchdog;
use aegis_bastion::web::{build_web_router, AppState};

const ARCHITECT_PUBLIC_KEY: [u8; 32] = [
    0xe2, 0x9d, 0xae, 0xf6, 0x71, 0x41, 0xba, 0x1e, 0xce, 0x83, 0x56, 0x7e, 0x46, 0x03, 0x18, 0xdb,
    0x95, 0x9c, 0xa6, 0x66, 0x6d, 0xdd, 0x43, 0x5c, 0xbf, 0x0a, 0xea, 0x4e, 0x3f, 0x9c, 0x79, 0x6c,
];

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("Starting Aegis Sentry Supervisor & Web Console (PID 1)...");

    let mongo_uri = env::var("MONGO_URI").expect("MONGO_URI required");
    let db = DatabaseEngine::connect(&mongo_uri, "aegis_bastion")
        .await
        .expect("Fatal: Could not connect to MongoDB");
    let db_arc = Arc::new(db);
    let reload_notifier = Arc::new(Notify::new());

    let state = AppState {
        db: db_arc.clone(),
        reload_notifier: reload_notifier.clone(),
    };

    // Bind Axum web router
    let port: u16 = env::var("PORT")
        .unwrap_or_else(|_| "10000".to_string())
        .parse()
        .unwrap_or(10000);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let app = build_web_router(state);

    tokio::spawn(async move {
        info!("Aegis Web Console listening on http://{}", addr);
        let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    });

    let mut watchdog = SupervisorWatchdog::new();
    sync_and_swap(&db_arc, &mut watchdog).await;

    loop {
        reload_notifier.notified().await;
        info!("On-demand core swap triggered from Web Console...");
        sync_and_swap(&db_arc, &mut watchdog).await;
    }
}

async fn sync_and_swap(db: &DatabaseEngine, watchdog: &mut SupervisorWatchdog) {
    match db.fetch_core_blob().await {
        Ok(blob_doc) => {
            let compressed_bytes = blob_doc.compressed_binary.bytes;
            let signature_bytes: [u8; 64] =
                blob_doc.signature.bytes.try_into().unwrap_or([0u8; 64]);
            if let Err(e) = CryptoEngine::verify_signature(
                &ARCHITECT_PUBLIC_KEY,
                &compressed_bytes,
                &signature_bytes,
            ) {
                error!("SECURITY ALERT: Core Blob signature is invalid: {}", e);
            } else {
                info!("Ed25519 Signature Verified. Decompressing Zstd binary...");
                if let Ok(decompressed_binary) = zstd::decode_all(&compressed_bytes[..]) {
                    let _ = watchdog.hot_swap_core(decompressed_binary);
                }
            }
        }
        Err(e) => warn!(
            "Could not retrieve core blob: {}. Waiting for next trigger...",
            e
        ),
    }
}
