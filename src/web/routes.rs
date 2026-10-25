//! # Web Console HTTP Route Handlers

use axum::{
    extract::{Path, Query, State},
    http::{
        header::{CACHE_CONTROL, CONTENT_TYPE},
        HeaderMap, StatusCode,
    },
    response::{IntoResponse, Response},
    Json,
};
use base64::Engine;
use mongodb::bson::{doc, spec::BinarySubtype, Binary, Document};
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

const FALLBACK_DASHBOARD_HTML: &str = include_str!("../dashboard.html");

pub const MASTER_STUDIO_SALT: [u8; 32] = [
    0xe2, 0x9d, 0xae, 0xf6, 0x71, 0x41, 0xba, 0x1e, 0xce, 0x83, 0x56, 0x7e, 0x46, 0x03, 0x18, 0xdb,
    0x95, 0x9c, 0xa6, 0x66, 0x6d, 0xdd, 0x43, 0x5c, 0xbf, 0x0a, 0xea, 0x4e, 0x3f, 0x9c, 0x79, 0x6c,
];

pub async fn serve_dashboard() -> Response {
    if let Ok(gist_url) = std::env::var("DASHBOARD_GIST_URL") {
        let mut clean_url = gist_url.trim().to_string();

        if let Some(raw_idx) = clean_url.find("/raw/") {
            let after_raw = &clean_url[raw_idx + 5..];
            if let Some(slash_idx) = after_raw.find('/') {
                let segment = &after_raw[..slash_idx];
                if segment.len() == 40 && segment.chars().all(|c| c.is_ascii_hexdigit()) {
                    clean_url = format!(
                        "{}/raw/{}",
                        &clean_url[..raw_idx],
                        &after_raw[slash_idx + 1..]
                    );
                }
            }
        }

        if !clean_url.is_empty() {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(3))
                .build()
                .unwrap_or_default();

            let separator = if clean_url.contains('?') { "&" } else { "?" };
            let fresh_url = format!(
                "{}{}_t={}",
                clean_url,
                separator,
                chrono::Utc::now().timestamp_millis()
            );

            if let Ok(resp) = client
                .get(&fresh_url)
                .header("Cache-Control", "no-cache")
                .header("Pragma", "no-cache")
                .send()
                .await
            {
                if resp.status().is_success() {
                    if let Ok(html) = resp.text().await {
                        return (
                            [
                                (CONTENT_TYPE, "text/html; charset=utf-8"),
                                (CACHE_CONTROL, "no-store, no-cache, must-revalidate"),
                            ],
                            html,
                        )
                            .into_response();
                    }
                }
            }
        }
    }

    (
        [
            (CONTENT_TYPE, "text/html; charset=utf-8"),
            (CACHE_CONTROL, "no-store, no-cache, must-revalidate"),
        ],
        FALLBACK_DASHBOARD_HTML,
    )
        .into_response()
}

pub async fn health_check() -> &'static str {
    "OK"
}

/// Deep Liveness Probe for P2P Cluster Mesh
pub async fn liveness_check() -> (StatusCode, &'static str) {
    let is_alive = std::path::Path::new("/tmp/gateway_liveness").exists()
        || crate::cluster::p2p::IS_GATEWAY_HEALTHY.load(std::sync::atomic::Ordering::Relaxed);

    if is_alive {
        (StatusCode::OK, "HEALTHY_LEADER\n")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "GATEWAY_DISCONNECTED\n")
    }
}

pub async fn handle_update(State(state): State<AppState>) -> &'static str {
    state.reload_notifier.notify_one();
    "Core swap signal accepted\n"
}

pub async fn get_live_logs(
    State(state): State<AppState>,
) -> Json<Vec<crate::telemetry::LiveLogEntry>> {
    Json(state.log_buffer.get_entries())
}

// =============================================================================
// TRUE DOTA 2 WYSIWYG SHOWCASE STUDIO (LIVE REAL-TIME PREVIEW)
// =============================================================================

const REAL_STUDIO_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Chill Zone // Dota 2 Showcase Studio</title>
<style>
:root { --bg: #090a0d; --card: #121418; --border: #262930; --accent: #e05638; --text: #f3f4f6; }
* { box-sizing: border-box; }
body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; flex-direction: column; align-items: center; padding: 24px; margin: 0; }
.studio-container { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 24px; width: 860px; box-shadow: 0 12px 30px rgba(0,0,0,0.7); }
.header-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
h2 { margin: 0; font-size: 1.35rem; font-weight: 800; letter-spacing: 0.5px; }
h2 span { color: var(--accent); }
p.hint { color: #9ca3af; font-size: 0.82rem; margin: 4px 0 0 0; }
#canvas-wrapper { position: relative; width: 800px; height: 400px; margin: 0 auto; box-shadow: 0 8px 24px rgba(0,0,0,0.6); border-radius: 6px; overflow: hidden; }
canvas { background: #0b0d11; display: block; cursor: grab; }
canvas:active { cursor: grabbing; }
.control-panel { display: flex; flex-direction: column; gap: 12px; margin-top: 20px; }
.btn-row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.btn-row label { font-size: 0.75rem; font-weight: bold; color: #9ca3af; text-transform: uppercase; margin-right: 4px; }
button { background: #1a1d24; color: #f3f4f6; border: 1px solid #3a3f4a; padding: 8px 14px; border-radius: 6px; font-size: 0.82rem; font-weight: 600; cursor: pointer; transition: 0.15s; }
button:hover { background: #262930; border-color: var(--accent); }
button.active { border-color: var(--accent); background: rgba(224,86,56,0.15); color: #fff; }
.btn-save { background: var(--accent); border-color: var(--accent); color: #fff; padding: 10px 24px; font-size: 0.9rem; font-weight: bold; margin-left: auto; }
.btn-save:hover { background: #ff6b4a; }
.status-pill { font-size: 0.85rem; color: #10b981; font-weight: bold; }
</style>
</head>
<body>
<div class="studio-container">
  <div class="header-row">
    <div>
      <h2><span>Dota 2</span> Showcase Studio</h2>
      <p class="hint">WYSIWYG Live Canvas. Drag elements directly. What you see is exactly what Discord sends.</p>
    </div>
    <div id="status-pill" class="status-pill"></div>
  </div>

  <div id="canvas-wrapper">
    <canvas id="cv" width="800" height="400"></canvas>
  </div>

  <div class="control-panel">
    <div class="btn-row">
      <label>Presets:</label>
      <button onclick="applyPreset('classic')">Classic</button>
      <button onclick="applyPreset('showcase')">Hero Spotlight</button>
      <button onclick="applyPreset('compact')">Compact</button>
      
      <label style="margin-left: 12px;">Grid:</label>
      <button id="grid-btn" onclick="toggleGrid()">Grid: OFF</button>
      
      <label style="margin-left: 12px;">Theme:</label>
      <button onclick="setTheme('crimson')">Crimson</button>
      <button onclick="setTheme('cyan')">Cyan</button>
      <button onclick="setTheme('emerald')">Emerald</button>
      <button onclick="setTheme('amber')">Amber</button>
      <button onclick="setTheme('amethyst')">Amethyst</button>

      <button class="btn-save" onclick="saveScene()">✓ Save to Discord</button>
    </div>
  </div>
</div>

<script>
const cv = document.getElementById('cv');
const ctx = cv.getContext('2d');
const auth = new URLSearchParams(window.location.search).get('auth') || '';

let profileData = {
  username: 'Member',
  country: 'Serbia',
  continent: 'Europe',
  age_display: '28',
  level: 6,
  xp: 606,
  points: 606,
  theme: 'crimson'
};

let scene = null;
let showGrid = false;
let selectedLayer = null;
let dragOffset = { x: 0, y: 0 };
let avatarImg = new Image();

const THEME_COLORS = {
  crimson: '#e05638',
  cyan: '#06b6d4',
  emerald: '#10b981',
  amber: '#f59e0b',
  amethyst: '#8b5cf6'
};

async function init() {
  avatarImg.crossOrigin = 'anonymous';
  avatarImg.src = 'https://cdn.discordapp.com/embed/avatars/0.png'; // Fallback

  try {
    const res = await fetch('/api/studio/scene?auth=' + encodeURIComponent(auth));
    if (res.ok) {
      const data = await res.json();
      scene = data.scene;
      if (data.profile) {
        profileData = { ...profileData, ...data.profile };
        if (data.avatar_url) avatarImg.src = data.avatar_url;
      }
    }
  } catch(e) {}

  if (!scene) {
    scene = {
      width: 800, height: 400,
      layers: [
        { layer_id: 'avatar', transform: { x: 45, y: 55, z_index: 10 } },
        { layer_id: 'username', transform: { x: 180, y: 60, z_index: 20 } },
        { layer_id: 'badges', transform: { x: 180, y: 105, z_index: 20 } },
        { layer_id: 'chip_continent', transform: { x: 45, y: 195, z_index: 30 } },
        { layer_id: 'chip_country', transform: { x: 290, y: 195, z_index: 30 } },
        { layer_id: 'chip_age', transform: { x: 535, y: 195, z_index: 30 } },
        { layer_id: 'xp_bar', transform: { x: 45, y: 305, z_index: 40 } }
      ]
    };
  }

  avatarImg.onload = () => render();
  render();
}

function getLayerBounds(l) {
  const t = l.transform;
  switch(l.layer_id) {
    case 'avatar': return { x: t.x, y: t.y, w: 110, h: 110 };
    case 'username': return { x: t.x, y: t.y, w: 260, h: 32 };
    case 'badges': return { x: t.x, y: t.y, w: 240, h: 32 };
    case 'chip_continent':
    case 'chip_country':
    case 'chip_age': return { x: t.x, y: t.y, w: 220, h: 65 };
    case 'xp_bar': return { x: t.x, y: t.y, w: 710, h: 24 };
    default: return { x: t.x, y: t.y, w: 100, h: 40 };
  }
}

function render() {
  const accent = THEME_COLORS[profileData.theme] || '#e05638';
  
  // Base Canvas Background
  ctx.fillStyle = '#0b0d11';
  ctx.fillRect(0, 0, 800, 400);

  // Card Panel
  ctx.fillStyle = '#121418';
  ctx.fillRect(12, 12, 776, 376);
  ctx.strokeStyle = '#262930';
  ctx.lineWidth = 1;
  ctx.strokeRect(12, 12, 776, 376);

  // Accent Top Bar
  ctx.fillStyle = accent;
  ctx.fillRect(12, 12, 776, 6);

  // Optional Grid
  if (showGrid) {
    ctx.strokeStyle = '#1a1d24';
    for (let x = 0; x < 800; x += 20) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, 400); ctx.stroke(); }
    for (let y = 0; y < 400; y += 20) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(800, y); ctx.stroke(); }
  }

  // Sort by z_index
  const layers = [...scene.layers].sort((a,b) => a.transform.z_index - b.transform.z_index);

  layers.forEach(l => {
    const t = l.transform;
    ctx.save();

    switch(l.layer_id) {
      case 'avatar':
        // Real Circular Avatar with Gold Frame
        ctx.save();
        ctx.beginPath();
        ctx.arc(t.x + 55, t.y + 55, 55, 0, Math.PI * 2);
        ctx.closePath();
        ctx.clip();
        try { ctx.drawImage(avatarImg, t.x, t.y, 110, 110); } catch(e) {}
        ctx.restore();
        // Frame
        ctx.beginPath();
        ctx.arc(t.x + 55, t.y + 55, 57, 0, Math.PI * 2);
        ctx.strokeStyle = '#f59e0b';
        ctx.lineWidth = 3;
        ctx.stroke();
        break;

      case 'username':
        // Real Username with drop shadow
        ctx.font = 'bold 24px monospace';
        ctx.fillStyle = '#000000';
        ctx.fillText(profileData.username, t.x + 2, t.y + 24);
        ctx.fillStyle = '#f3f4f6';
        ctx.fillText(profileData.username, t.x, t.y + 22);
        break;

      case 'badges':
        // Real LVL Badge
        const lvlStr = 'LVL ' + profileData.level;
        const ptsStr = 'PTS: ' + profileData.points;
        ctx.fillStyle = accent;
        ctx.fillRect(t.x, t.y, 80, 28);
        ctx.fillStyle = '#fff';
        ctx.font = 'bold 14px monospace';
        ctx.fillText(lvlStr, t.x + 12, t.y + 19);

        // Real PTS Badge
        ctx.fillStyle = '#10b981';
        ctx.fillRect(t.x + 94, t.y, 105, 28);
        ctx.fillStyle = '#fff';
        ctx.fillText(ptsStr, t.x + 104, t.y + 19);
        break;

      case 'chip_continent':
        drawStatChip(t.x, t.y, 'CONTINENT', profileData.continent, '#6366f1');
        break;

      case 'chip_country':
        drawStatChip(t.x, t.y, 'COUNTRY', profileData.country, '#ec4899');
        break;

      case 'chip_age':
        drawStatChip(t.x, t.y, 'AGE', profileData.age_display, accent);
        break;

      case 'xp_bar':
        // Real XP Bar
        ctx.font = '12px monospace';
        ctx.fillStyle = '#d1d5db';
        ctx.fillText(`XP: ${profileData.xp} / 695 (22.6%)`, t.x, t.y - 6);
        ctx.fillStyle = '#1a1d24';
        ctx.fillRect(t.x, t.y, 710, 24);
        ctx.fillStyle = accent;
        ctx.fillRect(t.x, t.y, 160, 24);
        ctx.strokeStyle = '#3a3f4a';
        ctx.strokeRect(t.x, t.y, 710, 24);
        break;
    }

    // Selection border when dragging
    if (selectedLayer === l) {
      const b = getLayerBounds(l);
      ctx.strokeStyle = '#ffffff';
      ctx.lineWidth = 1;
      ctx.setLineDash([4, 4]);
      ctx.strokeRect(b.x - 2, b.y - 2, b.w + 4, b.h + 4);
    }

    ctx.restore();
  });
}

function drawStatChip(x, y, label, val, barColor) {
  ctx.fillStyle = '#16191f';
  ctx.fillRect(x, y, 220, 65);
  ctx.strokeStyle = '#282c35';
  ctx.lineWidth = 1;
  ctx.strokeRect(x, y, 220, 65);
  ctx.fillStyle = barColor;
  ctx.fillRect(x, y, 4, 65);
  ctx.font = '11px monospace';
  ctx.fillStyle = '#9ca3af';
  ctx.fillText(label, x + 14, y + 20);
  ctx.font = 'bold 18px monospace';
  ctx.fillStyle = '#f3f4f6';
  ctx.fillText(val, x + 14, y + 46);
}

// Canvas Mouse Dragging Handlers
cv.onmousedown = (e) => {
  const rect = cv.getBoundingClientRect();
  const mx = e.clientX - rect.left;
  const my = e.clientY - rect.top;

  selectedLayer = null;
  for (let i = scene.layers.length - 1; i >= 0; i--) {
    const l = scene.layers[i];
    const b = getLayerBounds(l);
    if (mx >= b.x && mx <= b.x + b.w && my >= b.y && my <= b.y + b.h) {
      selectedLayer = l;
      dragOffset.x = mx - l.transform.x;
      dragOffset.y = my - l.transform.y;
      break;
    }
  }
  render();
};

window.onmousemove = (e) => {
  if (!selectedLayer) return;
  const rect = cv.getBoundingClientRect();
  let nx = e.clientX - rect.left - dragOffset.x;
  let ny = e.clientY - rect.top - dragOffset.y;

  if (showGrid) {
    nx = Math.round(nx / 10) * 10;
    ny = Math.round(ny / 10) * 10;
  }

  selectedLayer.transform.x = Math.max(12, Math.min(788 - 50, nx));
  selectedLayer.transform.y = Math.max(12, Math.min(388 - 20, ny));
  render();
};

window.onmouseup = () => {
  if (selectedLayer) { selectedLayer = null; render(); }
};

function toggleGrid() {
  showGrid = !showGrid;
  document.getElementById('grid-lbl').innerText = showGrid ? 'ON' : 'OFF';
  render();
}

function setTheme(th) {
  profileData.theme = th;
  render();
}

function applyPreset(p) {
  if (p === 'showcase') {
    // Spotlight Layout
    scene.layers.forEach(l => {
      if (l.layer_id === 'avatar') { l.transform.x = 345; l.transform.y = 35; }
      if (l.layer_id === 'username') { l.transform.x = 300; l.transform.y = 165; }
      if (l.layer_id === 'badges') { l.transform.x = 295; l.transform.y = 200; }
      if (l.layer_id === 'chip_continent') { l.transform.x = 45; l.transform.y = 245; }
      if (l.layer_id === 'chip_country') { l.transform.x = 290; l.transform.y = 245; }
      if (l.layer_id === 'chip_age') { l.transform.x = 535; l.transform.y = 245; }
      if (l.layer_id === 'xp_bar') { l.transform.x = 45; l.transform.y = 330; }
    });
  } else if (p === 'compact') {
    scene.layers.forEach(l => {
      if (l.layer_id === 'avatar') { l.transform.x = 40; l.transform.y = 45; }
      if (l.layer_id === 'username') { l.transform.x = 170; l.transform.y = 55; }
      if (l.layer_id === 'badges') { l.transform.x = 170; l.transform.y = 95; }
      if (l.layer_id === 'chip_continent') { l.transform.x = 45; l.transform.y = 175; }
      if (l.layer_id === 'chip_country') { l.transform.x = 290; l.transform.y = 175; }
      if (l.layer_id === 'chip_age') { l.transform.x = 535; l.transform.y = 175; }
      if (l.layer_id === 'xp_bar') { l.transform.x = 45; l.transform.y = 265; }
    });
  } else {
    // Classic Layout
    scene.layers.forEach(l => {
      if (l.layer_id === 'avatar') { l.transform.x = 45; l.transform.y = 55; }
      if (l.layer_id === 'username') { l.transform.x = 180; l.transform.y = 60; }
      if (l.layer_id === 'badges') { l.transform.x = 180; l.transform.y = 105; }
      if (l.layer_id === 'chip_continent') { l.transform.x = 45; l.transform.y = 195; }
      if (l.layer_id === 'chip_country') { l.transform.x = 290; l.transform.y = 195; }
      if (l.layer_id === 'chip_age') { l.transform.x = 535; l.transform.y = 195; }
      if (l.layer_id === 'xp_bar') { l.transform.x = 45; l.transform.y = 305; }
    });
  }
  render();
}

async function saveScene() {
  const pill = document.getElementById('status-pill');
  pill.innerText = 'Saving...';
  try {
    const res = await fetch('/api/studio/save?auth=' + encodeURIComponent(auth), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scene, theme: profileData.theme })
    });
    if (res.ok) {
      pill.innerText = '✓ Saved to Discord!';
      setTimeout(() => { pill.innerText = ''; }, 3000);
    } else {
      pill.innerText = '❌ Save failed';
    }
  } catch(e) {
    pill.innerText = '❌ Network error';
  }
}

init();
</script>
</body>
</html>"##;

pub async fn serve_studio(
    State(state): State<AppState>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    if let Some(auth) = q.get("auth") {
        if verify_studio_token(auth).is_some() {
            // Check dynamic template in MongoDB Atlas first (ZERO GIT PUSH OVERHEAD!)
            if let Ok(Some(doc)) = state
                .db
                .raw_database()
                .collection::<Document>("system_ui_templates")
                .find_one(doc! { "_id": "studio_html" })
                .await
            {
                if let Ok(html) = doc.get_str("html") {
                    return (
                        [(CONTENT_TYPE, "text/html; charset=utf-8")],
                        html.to_string(),
                    )
                        .into_response();
                }
            }

            return (
                [(CONTENT_TYPE, "text/html; charset=utf-8")],
                REAL_STUDIO_HTML,
            )
                .into_response();
        }
    }
    (
        StatusCode::UNAUTHORIZED,
        "Invalid or expired studio authorization token",
    )
        .into_response()
}

pub async fn get_studio_scene(
    State(state): State<AppState>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let auth = q.get("auth").cloned().unwrap_or_default();
    let user_id = match verify_studio_token(&auth) {
        Some(uid) => uid,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let scene = state
        .db
        .fetch_canvas_scene(user_id)
        .await
        .unwrap_or(None)
        .unwrap_or_else(crate::canvas::CanvasScene::default_classic);

    let profile = state.db.fetch_user_profile(user_id).await.unwrap_or(None);

    Json(serde_json::json!({
        "scene": scene,
        "profile": profile,
        "avatar_url": format!("https://cdn.discordapp.com/embed/avatars/{}.png", user_id % 5)
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct SaveScenePayload {
    pub scene: crate::canvas::CanvasScene,
    pub theme: Option<String>,
}

pub async fn save_studio_scene(
    State(state): State<AppState>,
    Query(q): Query<std::collections::HashMap<String, String>>,
    Json(payload): Json<SaveScenePayload>,
) -> Response {
    let auth = q.get("auth").cloned().unwrap_or_default();
    let user_id = match verify_studio_token(&auth) {
        Some(uid) => uid,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    if payload.scene.layers.len() > crate::canvas::MAX_LAYERS {
        return (
            StatusCode::BAD_REQUEST,
            "Exceeded maximum layer capacity bound of 12",
        )
            .into_response();
    }

    let _ = state.db.save_canvas_scene(user_id, &payload.scene).await;

    if let Some(th) = payload.theme {
        if let Ok(Some(mut p)) = state.db.fetch_user_profile(user_id).await {
            p.theme = th;
            let _ = state.db.save_user_profile(p).await;
        }
    }

    StatusCode::OK.into_response()
}

pub fn create_studio_token(user_id: u64) -> String {
    let expires = chrono::Utc::now().timestamp() + 900; // 15 min TTL
    let payload = format!("{}:{}", user_id, expires);
    let sig = CryptoEngine::sha256(format!("{}:{:?}", payload, MASTER_STUDIO_SALT).as_bytes());
    format!("{}.{}.{}", user_id, expires, sig)
}

pub fn verify_studio_token(token: &str) -> Option<u64> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let user_id: u64 = parts[0].parse().ok()?;
    let expires: i64 = parts[1].parse().ok()?;
    if chrono::Utc::now().timestamp() > expires {
        return None;
    }
    let payload = format!("{}:{}", user_id, expires);
    let expected = CryptoEngine::sha256(format!("{}:{:?}", payload, MASTER_STUDIO_SALT).as_bytes());
    if parts[2] == expected {
        Some(user_id)
    } else {
        None
    }
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
        info!("Master Admin initialized: {}", payload.username);
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
// THREAT RULES
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
// WHITELISTS
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
    let target = payload.url.trim();

    if target.len() == 64 && target.chars().all(|c| c.is_ascii_hexdigit()) {
        let sha_clean = target.to_lowercase();
        let _ = state
            .db
            .add_whitelisted_image(&sha_clean, 0, &payload.label, "Console")
            .await;
        let _ = state.db.revoke_blacklisted_image(&sha_clean).await;
        return StatusCode::CREATED.into_response();
    }

    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    if let Ok(resp) = client.get(target).send().await {
        if resp.status().is_success() {
            if let Ok(bytes) = resp.bytes().await {
                let sha256 = CryptoEngine::sha256(&bytes);
                let dhash = CryptoEngine::compute_dhash(&bytes).unwrap_or(0);
                let _ = state
                    .db
                    .add_whitelisted_image(&sha256, dhash, &payload.label, "Console")
                    .await;
                let _ = state.db.revoke_blacklisted_image(&sha256).await;
                return StatusCode::CREATED.into_response();
            }
        }
    }

    (
        StatusCode::BAD_REQUEST,
        "Failed fetching image from URL or invalid SHA-256 hash",
    )
        .into_response()
}

pub async fn delete_whitelisted_image(
    State(state): State<AppState>,
    Query(q): Query<QuerySha>,
) -> Response {
    let _ = state.db.remove_whitelisted_image(&q.sha256).await;
    StatusCode::OK.into_response()
}

// =============================================================================
// BLACKLISTED MEDIA
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
    let target = payload.url.trim();

    if target.len() == 64 && target.chars().all(|c| c.is_ascii_hexdigit()) {
        let _ = state
            .db
            .blacklist_image_explicit(target, 0, &payload.label, "Console")
            .await;
        return StatusCode::CREATED.into_response();
    }

    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    if let Ok(resp) = client.get(target).send().await {
        if resp.status().is_success() {
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
    }
    (StatusCode::BAD_REQUEST, "Failed fetching image from URL").into_response()
}

pub async fn revoke_image(State(state): State<AppState>, Query(q): Query<QuerySha>) -> Response {
    let _ = state.db.revoke_blacklisted_image(&q.sha256).await;
    StatusCode::OK.into_response()
}

// =============================================================================
// WASM PLUGINS
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

    info!("WASM Plugin '{}' installed and registered.", payload.name);
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
// AUDITS & OPERATORS
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
