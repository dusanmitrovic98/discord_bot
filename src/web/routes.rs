use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    Json,
};
use base64::Engine;
use mongodb::bson::{spec::BinarySubtype, Binary};
use serde::Deserialize;
use tracing::info;

use crate::crypto::CryptoEngine;
use crate::db::{AdminUser, DynamicRule, PluginRecord};
use crate::plugin_engine::DynamicPluginEngine;
use crate::web::auth::{
    clear_auth_cookie, create_signed_session_cookie, hash_password, verify_password,
    verify_session_cookie, AuthPayload, AuthStatusResponse, UserDto,
};
use crate::web::AppState;

const DASHBOARD_HTML: &str = include_str!("../dashboard.html");

pub async fn serve_dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

pub async fn health_check() -> &'static str {
    "OK"
}

pub async fn handle_update(State(state): State<AppState>) -> &'static str {
    state.reload_notifier.notify_one();
    "Core swap signal accepted\n"
}

// =============================================================================
// AUTHENTICATION & RBAC
// =============================================================================

pub async fn auth_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<AuthStatusResponse> {
    let count = state.db.get_admin_user_count().await.unwrap_or(0);
    let has_admin = count > 0;
    let mut authenticated = false;
    let mut user = None;

    if let Some(user_val) = verify_session_cookie(&headers, &state.session_secret) {
        if let Ok(Some(db_user)) = state.db.fetch_user(&user_val).await {
            authenticated = true;
            user = Some(UserDto {
                username: db_user.username,
                role: db_user.role,
            });
        }
    }
    Json(AuthStatusResponse {
        has_admin,
        authenticated,
        user,
    })
}

pub async fn auth_submit(
    State(state): State<AppState>,
    Json(payload): Json<AuthPayload>,
) -> Response {
    let count = state.db.get_admin_user_count().await.unwrap_or(0);

    if count == 0 {
        let password_hash = hash_password(&payload.password);
        let admin = AdminUser {
            username: payload.username.clone(),
            password_hash,
            role: "admin".to_string(),
            created_at: mongodb::bson::DateTime::now(),
        };
        let _ = state.db.create_admin_user(admin).await;
        info!("👑 Master Admin initialized: {}", payload.username);
        return create_signed_session_cookie(&payload.username, &state.session_secret);
    }

    if let Ok(Some(user)) = state.db.fetch_user(&payload.username).await {
        if verify_password(&payload.password, &user.password_hash) {
            return create_signed_session_cookie(&payload.username, &state.session_secret);
        }
    }
    (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response()
}

pub async fn auth_logout() -> Response {
    clear_auth_cookie()
}

// =============================================================================
// THREAT STUDIO (DYNAMIC REGEXES)
// =============================================================================

#[derive(Deserialize)]
pub struct AddRulePayload {
    pub pattern: String,
    pub description: String,
    pub action: String,
}

#[derive(Deserialize)]
pub struct QueryPattern {
    pub pattern: String,
}

pub async fn list_rules(State(state): State<AppState>) -> Json<Vec<DynamicRule>> {
    Json(state.db.fetch_dynamic_rules().await.unwrap_or_default())
}

pub async fn add_rule(
    State(state): State<AppState>,
    Json(payload): Json<AddRulePayload>,
) -> Response {
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

pub async fn delete_rule(State(state): State<AppState>, Query(q): Query<QueryPattern>) -> Response {
    let _ = state.db.delete_dynamic_rule(&q.pattern).await;
    StatusCode::OK.into_response()
}

// =============================================================================
// WHITELIST STUDIO (USERS & IMAGES)
// =============================================================================

#[derive(Deserialize)]
pub struct AddWlUserPayload {
    pub identifier: String,
    pub reason: String,
}

#[derive(Deserialize)]
pub struct QueryIdentifier {
    pub identifier: String,
}

pub async fn list_whitelisted_users(
    State(state): State<AppState>,
) -> Json<Vec<crate::db::WhitelistedUser>> {
    Json(state.db.fetch_whitelisted_users().await.unwrap_or_default())
}

pub async fn add_whitelisted_user(
    State(state): State<AppState>,
    Json(payload): Json<AddWlUserPayload>,
) -> Response {
    let _ = state
        .db
        .add_whitelisted_user(&payload.identifier, "Console", &payload.reason)
        .await;
    StatusCode::CREATED.into_response()
}

pub async fn delete_whitelisted_user(
    State(state): State<AppState>,
    Query(q): Query<QueryIdentifier>,
) -> Response {
    let _ = state.db.remove_whitelisted_user(&q.identifier).await;
    StatusCode::OK.into_response()
}

#[derive(Deserialize)]
pub struct AddWlImagePayload {
    pub url: String,
    pub label: String,
}

#[derive(Deserialize)]
pub struct QuerySha {
    pub sha256: String,
}

pub async fn list_whitelisted_images(
    State(state): State<AppState>,
) -> Json<Vec<crate::db::WhitelistedImage>> {
    Json(
        state
            .db
            .fetch_whitelisted_images()
            .await
            .unwrap_or_default(),
    )
}

pub async fn add_whitelisted_image(
    State(state): State<AppState>,
    Json(payload): Json<AddWlImagePayload>,
) -> Response {
    let client = reqwest::Client::new();
    if let Ok(resp) = client.get(&payload.url).send().await {
        if let Ok(bytes) = resp.bytes().await {
            let sha256 = CryptoEngine::sha256(&bytes);
            let dhash = CryptoEngine::compute_dhash(&bytes).unwrap_or(0);
            let _ = state
                .db
                .add_whitelisted_image(&sha256, dhash, &payload.label, "Console")
                .await;
            return StatusCode::CREATED.into_response();
        }
    }
    (StatusCode::BAD_REQUEST, "Failed fetching image").into_response()
}

pub async fn delete_whitelisted_image(
    State(state): State<AppState>,
    Query(q): Query<QuerySha>,
) -> Response {
    let _ = state.db.remove_whitelisted_image(&q.sha256).await;
    StatusCode::OK.into_response()
}

// =============================================================================
// IMAGE BLACKLIST (LOGO ANNIHILATOR - SHA256 & dHash)
// =============================================================================

#[derive(Deserialize)]
pub struct BlacklistImagePayload {
    pub url: String,
    pub label: String,
}

pub async fn list_images(State(state): State<AppState>) -> Json<Vec<serde_json::Value>> {
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

pub async fn blacklist_image(
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
            return StatusCode::CREATED.into_response();
        }
    }
    (StatusCode::BAD_REQUEST, "Failed fetching image from URL").into_response()
}

pub async fn revoke_image(State(state): State<AppState>, Query(q): Query<QuerySha>) -> Response {
    let _ = state.db.revoke_blacklisted_image(&q.sha256).await;
    StatusCode::OK.into_response()
}

pub async fn get_live_logs(
    State(state): State<AppState>,
) -> Json<Vec<crate::telemetry::LiveLogEntry>> {
    Json(state.log_buffer.get_entries())
}

// =============================================================================
// COMMUNITY PLUGINS MANAGER & WEBHOOK MULTIPLEXER
// =============================================================================

#[derive(Deserialize)]
pub struct UploadPluginPayload {
    pub name: String,
    pub wasm_base64: String,
}

#[derive(Deserialize)]
pub struct TogglePluginPayload {
    pub name: String,
    pub enabled: bool,
}

#[derive(Deserialize)]
pub struct QueryPluginName {
    pub name: String,
}

pub async fn list_community_plugins(State(state): State<AppState>) -> Json<Vec<serde_json::Value>> {
    let records = state
        .db
        .fetch_all_plugin_records()
        .await
        .unwrap_or_default();
    let dtos = records
        .into_iter()
        .map(|p| {
            let manifest: serde_json::Value = serde_json::from_str(&p.manifest_json)
                .unwrap_or_else(|_| serde_json::json!({ "name": p.name }));
            serde_json::json!({
                "name": p.name,
                "enabled": p.enabled,
                "manifest": manifest,
                "bytecode_len": p.bytecode.bytes.len(),
                "updated_at": p.updated_at
            })
        })
        .collect();
    Json(dtos)
}

pub async fn upload_community_plugin(
    State(state): State<AppState>,
    Json(payload): Json<UploadPluginPayload>,
) -> Response {
    let wasm_bytes = match hex::decode(&payload.wasm_base64)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&payload.wasm_base64))
    {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                "Invalid Base64 or Hex WASM payload",
            )
                .into_response()
        }
    };

    let engine = DynamicPluginEngine::new();
    let manifest = match engine.hot_swap_plugin(&payload.name, &wasm_bytes) {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("WASM validation failed: {}", e),
            )
                .into_response()
        }
    };

    let manifest_json = serde_json::to_string(&manifest).unwrap_or_default();

    let record = PluginRecord {
        name: payload.name.clone(),
        manifest_json,
        bytecode: Binary {
            subtype: BinarySubtype::Generic,
            bytes: wasm_bytes,
        },
        enabled: true,
        registered_command_ids: Vec::new(),
        updated_at: mongodb::bson::DateTime::now(),
    };

    if let Err(e) = state.db.save_plugin_record(record).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("DB Error: {}", e),
        )
            .into_response();
    }

    info!(
        "Community plugin '{}' installed and verified.",
        payload.name
    );
    (StatusCode::CREATED, "Plugin installed").into_response()
}

pub async fn toggle_community_plugin(
    State(state): State<AppState>,
    Json(payload): Json<TogglePluginPayload>,
) -> Response {
    let _ = state
        .db
        .toggle_plugin_record(&payload.name, payload.enabled)
        .await;
    StatusCode::OK.into_response()
}

pub async fn delete_community_plugin(
    State(state): State<AppState>,
    Query(q): Query<QueryPluginName>,
) -> Response {
    let _ = state.db.delete_plugin_record(&q.name).await;
    StatusCode::OK.into_response()
}

/// Wildcard HTTP Webhook Multiplexer: Dispatches `/api/plugins/:plugin_id/*path` to the WASM guest
pub async fn handle_plugin_http(
    State(state): State<AppState>,
    Path((plugin_id, path)): Path<(String, String)>,
    req: axum::http::Request<axum::body::Body>,
) -> Response {
    let method = req.method().to_string();
    let bytes = match axum::body::to_bytes(req.into_body(), 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => {
            return (StatusCode::PAYLOAD_TOO_LARGE, "Payload exceeds 1MB limit").into_response()
        }
    };

    let engine = DynamicPluginEngine::new().with_db(state.db.clone());
    if let Ok(records) = state.db.fetch_all_plugin_records().await {
        if let Some(record) = records
            .into_iter()
            .find(|p| p.name == plugin_id && p.enabled)
        {
            let _ = engine.hot_swap_plugin(&record.name, &record.bytecode.bytes);
            if let Ok((status_code, body_str)) =
                engine.execute_http_request(&record.name, &method, &path, &bytes)
            {
                let code = StatusCode::from_u16(status_code).unwrap_or(StatusCode::OK);
                return (code, body_str).into_response();
            }
        }
    }

    (
        StatusCode::NOT_FOUND,
        "Plugin endpoint not found or inactive",
    )
        .into_response()
}

// =============================================================================
// AUDITS & USERS
// =============================================================================

pub async fn list_audits(State(state): State<AppState>) -> Json<Vec<crate::db::AuditLogEntry>> {
    Json(state.db.fetch_recent_audits(50).await.unwrap_or_default())
}

#[derive(Deserialize)]
pub struct CreateModPayload {
    pub username: String,
    pub password: String,
}

pub async fn list_users(State(state): State<AppState>) -> Json<Vec<UserDto>> {
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

pub async fn create_moderator(
    State(state): State<AppState>,
    Json(payload): Json<CreateModPayload>,
) -> Response {
    let password_hash = hash_password(&payload.password);
    let mod_user = AdminUser {
        username: payload.username,
        password_hash,
        role: "moderator".to_string(),
        created_at: mongodb::bson::DateTime::now(),
    };
    let _ = state.db.create_admin_user(mod_user).await;
    StatusCode::CREATED.into_response()
}
