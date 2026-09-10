use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use tracing::info;

use crate::crypto::CryptoEngine;
use crate::db::{AdminUser, DynamicRule};
use crate::web::auth::{
    clear_auth_cookie, create_auth_cookie, hash_password, parse_session_cookie, verify_password,
    AuthPayload, AuthStatusResponse, UserDto,
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

pub async fn auth_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<AuthStatusResponse> {
    let count = state.db.get_admin_user_count().await.unwrap_or(0);
    let has_admin = count > 0;
    let mut authenticated = false;
    let mut user = None;

    if let Some(user_val) = parse_session_cookie(&headers) {
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
        return create_auth_cookie(&payload.username);
    }

    if let Ok(Some(user)) = state.db.fetch_user(&payload.username).await {
        if verify_password(&payload.password, &user.password_hash) {
            return create_auth_cookie(&payload.username);
        }
    }
    (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response()
}

pub async fn auth_logout() -> Response {
    clear_auth_cookie()
}

// Rules CRUD
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
    let rules = state.db.fetch_dynamic_rules().await.unwrap_or_default();
    Json(rules)
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
    state.reload_notifier.notify_one();
    (StatusCode::CREATED, "Rule added").into_response()
}

pub async fn delete_rule(State(state): State<AppState>, Query(q): Query<QueryPattern>) -> Response {
    let _ = state.db.delete_dynamic_rule(&q.pattern).await;
    state.reload_notifier.notify_one();
    StatusCode::OK.into_response()
}

// Whitelist CRUD
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
    state.reload_notifier.notify_one();
    StatusCode::CREATED.into_response()
}

pub async fn delete_whitelisted_user(
    State(state): State<AppState>,
    Query(q): Query<QueryIdentifier>,
) -> Response {
    let _ = state.db.remove_whitelisted_user(&q.identifier).await;
    state.reload_notifier.notify_one();
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
            let _ = state
                .db
                .add_whitelisted_image(&sha256, &payload.label, "Console")
                .await;
            state.reload_notifier.notify_one();
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
    state.reload_notifier.notify_one();
    StatusCode::OK.into_response()
}

// Images Blacklist & Audits
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
    (StatusCode::BAD_REQUEST, "Failed fetching image").into_response()
}

pub async fn revoke_image(State(state): State<AppState>, Query(q): Query<QuerySha>) -> Response {
    let _ = state.db.revoke_blacklisted_image(&q.sha256).await;
    StatusCode::OK.into_response()
}

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
