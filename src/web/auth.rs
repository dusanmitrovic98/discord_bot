use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::http::{header, HeaderMap};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize)]
pub struct AuthStatusResponse {
    pub has_admin: bool,
    pub authenticated: bool,
    pub user: Option<UserDto>,
}

#[derive(Serialize)]
pub struct UserDto {
    pub username: String,
    pub role: String,
}

#[derive(Deserialize)]
pub struct AuthPayload {
    pub username: String,
    pub password: String,
}

pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    if let Ok(parsed_hash) = PasswordHash::new(hash) {
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
    } else {
        false
    }
}

/// Constant-time equality comparison to prevent timing attacks (NASA Rule 5)
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Computes RFC 2104 compliant HMAC-SHA256 signature
fn compute_hmac(key: &[u8; 32], message: &[u8]) -> String {
    let mut k_ipad = [0x36u8; 64];
    let mut k_opad = [0x5cu8; 64];

    for i in 0..32 {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    let mut inner = Sha256::new();
    inner.update(k_ipad);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(k_opad);
    outer.update(inner_hash);
    format!("{:x}", outer.finalize())
}

/// Generates a signed cryptographic session cookie: `username.expires_at.signature`
pub fn create_signed_session_cookie(username: &str, secret: &[u8; 32]) -> Response {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expires_at = now + 86400; // 24 hours
    let payload = format!("{}:{}", username, expires_at);
    let signature = compute_hmac(secret, payload.as_bytes());

    let token = format!("{}.{}.{}", username, expires_at, signature);
    let cookie = format!(
        "aegis_session={}; Path=/; HttpOnly; Max-Age=86400; SameSite=Lax",
        token
    );
    ([(header::SET_COOKIE, cookie)], "Authenticated").into_response()
}

pub fn clear_auth_cookie() -> Response {
    let cookie = "aegis_session=; Path=/; HttpOnly; Max-Age=0";
    ([(header::SET_COOKIE, cookie)], "Logged out").into_response()
}

/// Verifies HMAC signature, constant-time checks equality, and asserts expiration bounds
pub fn verify_session_cookie(headers: &HeaderMap, secret: &[u8; 32]) -> Option<String> {
    let cookie_hdr = headers.get(header::COOKIE)?.to_str().ok()?;
    let mut token_opt = None;

    for c in cookie_hdr.split(';') {
        let parts: Vec<&str> = c.trim().split('=').collect();
        if parts.len() == 2 && parts[0] == "aegis_session" {
            token_opt = Some(parts[1]);
            break;
        }
    }

    let token = token_opt?;
    let segments: Vec<&str> = token.split('.').collect();
    if segments.len() != 3 {
        return None;
    }

    let (username, exp_str, sig) = (segments[0], segments[1], segments[2]);
    let expires_at: u64 = exp_str.parse().ok()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if now > expires_at {
        return None; // Expired session
    }

    let payload = format!("{}:{}", username, expires_at);
    let expected_sig = compute_hmac(secret, payload.as_bytes());

    if constant_time_compare(sig.as_bytes(), expected_sig.as_bytes()) {
        Some(username.to_string())
    } else {
        None // Forged signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_session_cookie_tamper_proofing() {
        let secret = [42u8; 32];
        let fake_secret = [99u8; 32];
        let headers = HeaderMap::new();

        // 1. Valid Token
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let payload = format!("dusanmitrovic98:{}", now);
        let sig = compute_hmac(&secret, payload.as_bytes());
        let valid_token = format!("dusanmitrovic98.{}.{}", now, sig);

        let mut valid_headers = headers.clone();
        valid_headers.insert(
            header::COOKIE,
            format!("aegis_session={}", valid_token).parse().unwrap(),
        );
        assert_eq!(
            verify_session_cookie(&valid_headers, &secret),
            Some("dusanmitrovic98".into())
        );

        // 2. Tampered Username Attempt
        let tampered_token = format!("admin.{}.{}", now, sig);
        let mut tampered_headers = headers.clone();
        tampered_headers.insert(
            header::COOKIE,
            format!("aegis_session={}", tampered_token).parse().unwrap(),
        );
        assert_eq!(verify_session_cookie(&tampered_headers, &secret), None);

        // 3. Forged with wrong secret
        assert_eq!(verify_session_cookie(&valid_headers, &fake_secret), None);

        // 4. Expired Token
        let expired_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 100;
        let exp_payload = format!("dusanmitrovic98:{}", expired_time);
        let exp_sig = compute_hmac(&secret, exp_payload.as_bytes());
        let expired_token = format!("dusanmitrovic98.{}.{}", expired_time, exp_sig);
        let mut expired_headers = headers.clone();
        expired_headers.insert(
            header::COOKIE,
            format!("aegis_session={}", expired_token).parse().unwrap(),
        );
        assert_eq!(verify_session_cookie(&expired_headers, &secret), None);
    }
}
