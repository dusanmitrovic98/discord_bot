use aegis_bastion::crypto::CryptoEngine;
use aegis_bastion::db::DatabaseEngine;
use aegis_bastion::supervisor::SupervisorWatchdog;
use std::env;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tracing::{error, info, warn};

// Your Architect Public Key
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

    info!("Starting Aegis Sentry Supervisor (PID 1)...");

    let reload_notifier = Arc::new(Notify::new());

    // =========================================================================
    // HTTP SENTRY & ON-DEMAND UPDATE ENDPOINT (No 60-second polling!)
    // =========================================================================
    let port = env::var("PORT").unwrap_or_else(|_| "10000".to_string());
    let addr = format!("0.0.0.0:{}", port);
    let notifier_clone = reload_notifier.clone();

    tokio::spawn(async move {
        match TcpListener::bind(&addr).await {
            Ok(listener) => {
                info!(
                    "Sentry listening on {}. Call GET /update to swap core.",
                    addr
                );
                while let Ok((mut socket, _)) = listener.accept().await {
                    let notifier = notifier_clone.clone();
                    tokio::spawn(async move {
                        let mut buf = [0u8; 512];
                        if let Ok(n) = socket.read(&mut buf).await {
                            let request = String::from_utf8_lossy(&buf[..n]);

                            // On-Demand trigger: /update
                            if request.contains("GET /update") || request.contains("POST /update") {
                                info!("Manual update trigger received via HTTP endpoint!");
                                notifier.notify_one();
                                let response = b"HTTP/1.1 200 OK\r\nContent-Length: 26\r\nConnection: close\r\n\r\nCore swap signal accepted\n";
                                let _ = socket.write_all(response).await;
                                return;
                            }

                            // Standard Render health probe: 200 OK
                            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
                            let _ = socket.write_all(response).await;
                        }
                    });
                }
            }
            Err(e) => error!("Failed to bind Sentry on {}: {}", addr, e),
        }
    });

    // =========================================================================
    // IN-MEMORY EXECUTION & ON-DEMAND SWAP
    // =========================================================================
    let mongo_uri = env::var("MONGO_URI").expect("MONGO_URI environment variable required");
    let db = DatabaseEngine::connect(&mongo_uri, "aegis_bastion")
        .await
        .expect("Fatal: Could not connect to MongoDB from Supervisor");

    let mut watchdog = SupervisorWatchdog::new();

    // Initial boot on startup
    sync_and_swap(&db, &mut watchdog).await;

    // Await manual triggers via /update endpoint (Zero background query polling)
    loop {
        reload_notifier.notified().await;
        info!("Processing on-demand core swap from MongoDB...");
        sync_and_swap(&db, &mut watchdog).await;
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
                match zstd::decode_all(&compressed_bytes[..]) {
                    Ok(decompressed_binary) => {
                        if let Err(e) = watchdog.hot_swap_core(decompressed_binary) {
                            error!("Failed hot-swapping core binary: {}", e);
                        }
                    }
                    Err(e) => error!("Zstd decompression failed: {}", e),
                }
            }
        }
        Err(e) => warn!(
            "Could not retrieve core blob: {}. Waiting for next trigger...",
            e
        ),
    }
}
