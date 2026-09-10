use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Notify;
use tracing::{error, info, warn};

use aegis_bastion::crypto::CryptoEngine;
use aegis_bastion::db::{AdminUser, DatabaseEngine, DynamicRule};
use aegis_bastion::supervisor::SupervisorWatchdog;

const ARCHITECT_PUBLIC_KEY: [u8; 32] = [
    0xe2, 0x9d, 0xae, 0xf6, 0x71, 0x41, 0xba, 0x1e, 0xce, 0x83, 0x56, 0x7e, 0x46, 0x03, 0x18, 0xdb,
    0x95, 0x9c, 0xa6, 0x66, 0x6d, 0xdd, 0x43, 0x5c, 0xbf, 0x0a, 0xea, 0x4e, 0x3f, 0x9c, 0x79, 0x6c,
];

const DASHBOARD_HTML: &str = include_str!("../dashboard.html");

#[derive(Clone)]
struct AppState {
    db: Arc<DatabaseEngine>,
    reload_notifier: Arc<Notify>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("Starting Aegis Sentry Supervisor & Web Console (PID 1)...");

    let mongo_uri = env::var("MONGO_URI").expect("MONGO_URI environment variable required");
    let db = DatabaseEngine::connect(&mongo_uri, "aegis_bastion")
        .await
        .expect("Fatal: Could not connect to MongoDB from Supervisor");
    let db_arc = Arc::new(db);
    let reload_notifier = Arc::new(Notify::new());

    let state = AppState {
        db: db_arc.clone(),
        reload_notifier: reload_notifier.clone(),
    };

    // =========================================================================
    // AXUM ROUTER: Root is plain "OK", Dashboard hidden at /dashboard
    // =========================================================================
    let app = Router::new()
        .route("/", get(health_check)) // Plain "OK" for camouflage & pings
        .route("/health", get(health_check)) // Plain "OK"
        .route("/dashboard", get(serve_dashboard)) // Protected Flat UI Console
        .route("/update", get(handle_update_get).post(handle_update_post))
        .route("/api/auth/status", get(auth_status))
        .route("/api/auth/submit", post(auth_submit))
        .route("/api/auth/logout", post(auth_logout))
        .route(
            "/api/rules",
            get(list_rules).post(add_rule).delete(delete_rule),
        )
        .route("/api/images", get(list_images).delete(revoke_image))
        .route("/api/images/blacklist", post(blacklist_image))
        .route("/api/audits", get(list_audits))
        .route("/api/users", get(list_users).post(create_moderator))
        .with_state(state);

    let port: u16 = env::var("PORT")
        .unwrap_or_else(|_| "10000".to_string())
        .parse()
        .unwrap_or(10000);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    tokio::spawn(async move {
        info!("Aegis Web Console listening on http://{}", addr);
        let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    });

    // =========================================================================
    // IN-MEMORY EXECUTION & WATCHDOG
    // =========================================================================
    let mut watchdog = SupervisorWatchdog::new();
    sync_and_swap(&db_arc, &mut watchdog).await;

    loop {
        reload_notifier.notified().await;
        info!("On-demand core swap trigger activated from Web Console...");
        sync_and_swap(&db_arc, &mut watchdog).await;
    }
}

async fn serve_dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

async fn health_check() -> &'static str {
    "OK"
}

async fn handle_update_get(State(state): State<AppState>) -> &'static str {
    state.reload_notifier.notify_one();
    "Core swap signal accepted\n"
}

async fn handle_update_post(State(state): State<AppState>) -> &'static str {
    state.reload_notifier.notify_one();
    "Core swap signal accepted\n"
}

// =============================================================================
// AUTHENTICATION & RBAC (Argon2id + First-User Bootstrap)
// =============================================================================

#[derive(Serialize)]
struct AuthStatusResponse {
    has_admin: bool,
    authenticated: bool,
    user: Option<UserDto>,
}

#[derive(Serialize)]
struct UserDto {
    username: String,
    role: String,
}

#[derive(Deserialize)]
struct AuthPayload {
    username: String,
    password: String,
}

async fn auth_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<AuthStatusResponse> {
    let count = state.db.get_admin_user_count().await.unwrap_or(0);
    let has_admin = count > 0;

    let mut authenticated = false;
    let mut user = None;

    if let Some(cookie_hdr) = headers.get(header::COOKIE) {
        if let Ok(cookie_str) = cookie_hdr.to_str() {
            if let Some(user_val) = parse_session_cookie(cookie_str) {
                if let Ok(Some(db_user)) = state.db.fetch_user(&user_val).await {
                    authenticated = true;
                    user = Some(UserDto {
                        username: db_user.username,
                        role: db_user.role,
                    });
                }
            }
        }
    }

    Json(AuthStatusResponse {
        has_admin,
        authenticated,
        user,
    })
}

async fn auth_submit(State(state): State<AppState>, Json(payload): Json<AuthPayload>) -> Response {
    let count = state.db.get_admin_user_count().await.unwrap_or(0);

    if count == 0 {
        // Bootstrap: First user becomes Master Admin
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(payload.password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        let admin = AdminUser {
            username: payload.username.clone(),
            password_hash,
            role: "admin".to_string(),
            created_at: mongodb::bson::DateTime::now(),
        };

        let _ = state.db.create_admin_user(admin).await;
        info!("👑 Master Admin account initialized: {}", payload.username);
        return create_auth_cookie(&payload.username);
    }

    // Standard Login
    if let Ok(Some(user)) = state.db.fetch_user(&payload.username).await {
        let parsed_hash = PasswordHash::new(&user.password_hash).unwrap();
        if Argon2::default()
            .verify_password(payload.password.as_bytes(), &parsed_hash)
            .is_ok()
        {
            info!("User authenticated successfully: {}", payload.username);
            return create_auth_cookie(&payload.username);
        }
    }

    (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response()
}

async fn auth_logout() -> Response {
    let cookie = "aegis_session=; Path=/; HttpOnly; Max-Age=0";
    ([(header::SET_COOKIE, cookie)], "Logged out").into_response()
}

fn create_auth_cookie(username: &str) -> Response {
    let cookie = format!(
        "aegis_session={}; Path=/; HttpOnly; Max-Age=86400; SameSite=Lax",
        username
    );
    ([(header::SET_COOKIE, cookie)], "Authenticated").into_response()
}

fn parse_session_cookie(cookie_str: &str) -> Option<String> {
    for c in cookie_str.split(';') {
        let parts: Vec<&str> = c.trim().split('=').collect();
        if parts.len() == 2 && parts[0] == "aegis_session" {
            return Some(parts[1].to_string());
        }
    }
    None
}

// =============================================================================
// THREAT STUDIO (DYNAMIC REGEXES)
// =============================================================================

#[derive(Deserialize)]
struct AddRulePayload {
    pattern: String,
    description: String,
    action: String,
}

#[derive(Deserialize)]
struct QueryPattern {
    pattern: String,
}

async fn list_rules(State(state): State<AppState>) -> Json<Vec<DynamicRule>> {
    let rules = state.db.fetch_dynamic_rules().await.unwrap_or_default();
    Json(rules)
}

async fn add_rule(State(state): State<AppState>, Json(payload): Json<AddRulePayload>) -> Response {
    // NASA Rule 5: Test-compile regex on input before storing!
    if let Err(e) = regex::Regex::new(&payload.pattern) {
        return (
            StatusCode::BAD_REQUEST,
            format!("Invalid regex syntax: {}", e),
        )
            .into_response();
    }

    let rule = DynamicRule {
        pattern: payload.pattern,
        description: payload.description,
        action: payload.action,
        enabled: true,
        added_by: "Console".to_string(),
        created_at: mongodb::bson::DateTime::now(),
    };

    let _ = state.db.add_dynamic_rule(rule).await;
    (StatusCode::CREATED, "Rule added").into_response()
}

async fn delete_rule(State(state): State<AppState>, Query(q): Query<QueryPattern>) -> Response {
    let _ = state.db.delete_dynamic_rule(&q.pattern).await;
    StatusCode::OK.into_response()
}

// =============================================================================
// IMAGE BLACKLIST (LOGO ANNIHILATOR - SHA256 & dHash)
// =============================================================================

#[derive(Deserialize)]
struct BlacklistImagePayload {
    url: String,
    label: String,
}

#[derive(Deserialize)]
struct QuerySha {
    sha256: String,
}

async fn list_images(State(state): State<AppState>) -> Json<Vec<serde_json::Value>> {
    let raw = state
        .db
        .fetch_all_image_signatures()
        .await
        .unwrap_or_default();
    let json_docs: Vec<serde_json::Value> = raw
        .into_iter()
        .map(|d| serde_json::to_value(d).unwrap_or_default())
        .collect();
    Json(json_docs)
}

async fn blacklist_image(
    State(state): State<AppState>,
    Json(payload): Json<BlacklistImagePayload>,
) -> Response {
    let client = reqwest::Client::new();
    if let Ok(resp) = client.get(&payload.url).send().await {
        if let Ok(bytes) = resp.bytes().await {
            let sha256 = CryptoEngine::sha256(&bytes);
            let dhash = CryptoEngine::compute_dhash(&bytes).unwrap_or(0);

            let _ = state
                .db
                .blacklist_image_explicit(&sha256, dhash, &payload.label, "Console")
                .await;
            info!(
                "🖼️ Image Blacklisted via Console: '{}' (SHA: {}, dHash: {:016x})",
                payload.label, sha256, dhash
            );
            return StatusCode::CREATED.into_response();
        }
    }
    (StatusCode::BAD_REQUEST, "Failed fetching image from URL").into_response()
}

async fn revoke_image(State(state): State<AppState>, Query(q): Query<QuerySha>) -> Response {
    let _ = state.db.revoke_blacklisted_image(&q.sha256).await;
    StatusCode::OK.into_response()
}

// =============================================================================
// AUDITS & MODERATOR USER MANAGEMENT
// =============================================================================

async fn list_audits(State(state): State<AppState>) -> Json<Vec<aegis_bastion::db::AuditLogEntry>> {
    let audits = state.db.fetch_recent_audits(50).await.unwrap_or_default();
    Json(audits)
}

#[derive(Deserialize)]
struct CreateModPayload {
    username: String,
    password: String,
}

async fn list_users(State(state): State<AppState>) -> Json<Vec<UserDto>> {
    let users = state.db.fetch_all_users().await.unwrap_or_default();
    let dtos: Vec<UserDto> = users
        .into_iter()
        .map(|u| UserDto {
            username: u.username,
            role: u.role,
        })
        .collect();
    Json(dtos)
}

async fn create_moderator(
    State(state): State<AppState>,
    Json(payload): Json<CreateModPayload>,
) -> Response {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(payload.password.as_bytes(), &salt)
        .unwrap()
        .to_string();

    let mod_user = AdminUser {
        username: payload.username,
        password_hash,
        role: "moderator".to_string(),
        created_at: mongodb::bson::DateTime::now(),
    };

    let _ = state.db.create_admin_user(mod_user).await;
    StatusCode::CREATED.into_response()
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
