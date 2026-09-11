//! # Aegis Sentry Supervisor (PID 1) & Web Control Console
//!
//! Immutable supervisor process running as PID 1 on the container host.
//! Manages Linux anonymous memory execution (`memfd_create`), verifies Ed25519
//! cryptographic binary signatures from MongoDB Atlas, captures real-time application
//! logs in RAM, and exposes the HTTP web management console.

use axum::http::header;
use axum::http::Method;
use rand::RngCore;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Notify;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::{error, info, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use aegis_bastion::crypto::CryptoEngine;
use aegis_bastion::db::DatabaseEngine;
use aegis_bastion::supervisor::SupervisorWatchdog;
use aegis_bastion::telemetry::LogBuffer;
use aegis_bastion::web::{build_web_router, AppState};

/// The Sovereign Architect's Master Ed25519 Public Key.
/// Used to cryptographically verify core binary blobs before RAM execution.
const ARCHITECT_PUBLIC_KEY: [u8; 32] = [
    0xe2, 0x9d, 0xae, 0xf6, 0x71, 0x41, 0xba, 0x1e, 0xce, 0x83, 0x56, 0x7e, 0x46, 0x03, 0x18, 0xdb,
    0x95, 0x9c, 0xa6, 0x66, 0x6d, 0xdd, 0x43, 0x5c, 0xbf, 0x0a, 0xea, 0x4e, 0x3f, 0x9c, 0x79, 0x6c,
];

#[tokio::main]
async fn main() {
    // 1. Initialize the Bounded Tracing Log Ring Buffer (NASA Rule 2: Max 500 lines)
    let log_buffer = LogBuffer::new(500);

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with(tracing_subscriber::fmt::layer())
        .with(log_buffer.clone())
        .init();

    info!("Starting Aegis Sentry Supervisor & Web Console (PID 1)...");

    // 2. Resolve Database Environment Invariants (NASA Rule 5)
    let mongo_uri = env::var("MONGO_URI").expect("Fatal: MONGO_URI environment variable required");
    let db = DatabaseEngine::connect(&mongo_uri, "aegis_bastion")
        .await
        .expect("Fatal: Could not connect to MongoDB Atlas");
    let db_arc = Arc::new(db);
    let reload_notifier = Arc::new(Notify::new());

    // 3. Generate Cryptographic Secret for HMAC-SHA256 Sessions
    let mut session_secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut session_secret);

    let state = AppState {
        db: db_arc.clone(),
        reload_notifier: reload_notifier.clone(),
        session_secret,
        log_buffer: log_buffer.clone(),
    };

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::mirror_request())
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::ACCEPT,
            header::COOKIE,
        ])
        .allow_credentials(true);

    let port: u16 = env::var("PORT")
        .unwrap_or_else(|_| "10000".to_string())
        .parse()
        .unwrap_or(10000);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let app = build_web_router(state).layer(cors);

    // 5. Spawn Non-blocking Axum HTTP Engine
    tokio::spawn(async move {
        info!("Aegis Web Console listening on http://{}", addr);
        match tokio::net::TcpListener::bind(&addr).await {
            Ok(listener) => {
                if let Err(e) = axum::serve(listener, app).await {
                    error!("Fatal Axum web server error: {}", e);
                }
            }
            Err(e) => {
                error!("Failed binding TCP listener on {}: {}", addr, e);
            }
        }
    });

    // 6. Initialize RAM Execution Watchdog and Perform Boot Core Swap
    let mut watchdog = SupervisorWatchdog::new();
    sync_and_swap(&db_arc, &mut watchdog).await;

    // 7. On-Demand Hot-Swap Trigger Loop
    loop {
        reload_notifier.notified().await;
        info!("On-demand core swap triggered from Web Console or /update signal...");
        sync_and_swap(&db_arc, &mut watchdog).await;
    }
}

/// Atomically synchronizes the signed core blob from Atlas and hot-swaps in sealed RAM.
async fn sync_and_swap(db: &DatabaseEngine, watchdog: &mut SupervisorWatchdog) {
    match db.fetch_core_blob().await {
        Ok(blob_doc) => {
            let compressed_bytes = blob_doc.compressed_binary.bytes;
            let signature_bytes: [u8; 64] =
                blob_doc.signature.bytes.try_into().unwrap_or([0u8; 64]);

            // Cryptographic validation invariant (NASA Rule 5)
            if let Err(e) = CryptoEngine::verify_signature(
                &ARCHITECT_PUBLIC_KEY,
                &compressed_bytes,
                &signature_bytes,
            ) {
                error!("SECURITY ALERT: Core Blob signature is invalid: {}", e);
            } else {
                info!("Ed25519 Signature Verified. Decompressing Zstd binary in RAM...");
                match zstd::decode_all(&compressed_bytes[..]) {
                    Ok(decompressed_binary) => {
                        if let Err(err) = watchdog.hot_swap_core(decompressed_binary) {
                            error!("Watchdog failed swapping core in RAM: {}", err);
                        }
                    }
                    Err(e) => {
                        error!("Zstd decompression failed for core blob: {}", e);
                    }
                }
            }
        }
        Err(e) => warn!(
            "Could not retrieve core blob: {}. Waiting for next trigger...",
            e
        ),
    }
}
