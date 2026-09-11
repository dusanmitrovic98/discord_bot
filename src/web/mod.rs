pub mod auth;
pub mod routes;

use crate::telemetry::LogBuffer;
use axum::routing::{any, delete, get, post};
use axum::Router;
use std::sync::Arc;
use tokio::sync::Notify;

use crate::db::DatabaseEngine;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<DatabaseEngine>,
    pub reload_notifier: Arc<Notify>,
    pub session_secret: [u8; 32],
    pub log_buffer: LogBuffer,
}

pub fn build_web_router(state: AppState) -> Router {
    Router::new()
        // Camouflage & Health
        .route("/", get(routes::health_check))
        .route("/health", get(routes::health_check))
        .route("/dashboard", get(routes::serve_dashboard))
        .route(
            "/update",
            get(routes::handle_update).post(routes::handle_update),
        )
        // Authentication & RBAC
        .route("/api/auth/status", get(routes::auth_status))
        .route("/api/auth/submit", post(routes::auth_submit))
        .route("/api/auth/logout", post(routes::auth_logout))
        // Dynamic Threat Studio (Regexes)
        .route(
            "/api/rules",
            get(routes::list_rules)
                .post(routes::add_rule)
                .delete(routes::delete_rule),
        )
        .route(
            "/api/whitelist/users",
            get(routes::list_whitelisted_users)
                .post(routes::add_whitelisted_user)
                .delete(routes::delete_whitelisted_user),
        )
        .route(
            "/api/whitelist/images",
            get(routes::list_whitelisted_images)
                .post(routes::add_whitelisted_image)
                .delete(routes::delete_whitelisted_image),
        )
        // Image Blacklist (Logo Annihilator)
        .route(
            "/api/images",
            get(routes::list_images).delete(routes::revoke_image),
        )
        .route("/api/images/blacklist", post(routes::blacklist_image))
        // Community WASM Plugins Manager & Webhook Multiplexer
        .route("/api/plugins/list", get(routes::list_community_plugins))
        .route("/api/plugins/upload", post(routes::upload_community_plugin))
        .route("/api/plugins/toggle", post(routes::toggle_community_plugin))
        .route(
            "/api/plugins/delete",
            delete(routes::delete_community_plugin),
        )
        .route(
            "/api/plugins/:plugin_id/*path",
            any(routes::handle_plugin_http),
        )
        // Audits & Moderators
        .route("/api/audits", get(routes::list_audits))
        .route(
            "/api/users",
            get(routes::list_users).post(routes::create_moderator),
        )
        .with_state(state)
}
