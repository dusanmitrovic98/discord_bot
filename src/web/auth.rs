use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::http::{header, HeaderMap};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

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

pub fn create_auth_cookie(username: &str) -> Response {
    let cookie = format!(
        "aegis_session={}; Path=/; HttpOnly; Max-Age=86400; SameSite=Lax",
        username
    );
    ([(header::SET_COOKIE, cookie)], "Authenticated").into_response()
}

pub fn clear_auth_cookie() -> Response {
    let cookie = "aegis_session=; Path=/; HttpOnly; Max-Age=0";
    ([(header::SET_COOKIE, cookie)], "Logged out").into_response()
}

pub fn parse_session_cookie(headers: &HeaderMap) -> Option<String> {
    if let Some(cookie_hdr) = headers.get(header::COOKIE) {
        if let Ok(cookie_str) = cookie_hdr.to_str() {
            for c in cookie_str.split(';') {
                let parts: Vec<&str> = c.trim().split('=').collect();
                if parts.len() == 2 && parts[0] == "aegis_session" {
                    return Some(parts[1].to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2id_hash_and_verify() {
        let password = "super_secure_architect_password";
        let hash = hash_password(password);
        assert!(verify_password(password, &hash));
        assert!(!verify_password("wrong_password", &hash));
    }
}
