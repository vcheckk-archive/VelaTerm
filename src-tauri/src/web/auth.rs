//! Web-service authentication: password login, session-token gating, persistent pairing token, and devices.
//!
//! - Passwords are verified against a memory-hard Argon2id PHC string; the salt lives inside the PHC
//!   string and no plaintext password is ever persisted.
//! - Successful HTTP login creates a random in-memory session token returned in JSON. Clients present it
//!   through `Authorization: Bearer` or WebSocket `?token=`. Cookies were removed because domain-wide,
//!   port-agnostic sharing caused windows to overwrite one another's credentials.
//! - The shared pairing-admission token embedded in pairing links persists in the data directory
//!   (`access_store`), so restarting the app or server keeps old links valid. Only the explicit rotate
//!   action replaces the token and invalidates every link.
//! - Clients self-report device ID and name during handshake for a display registry. The registry and the
//!   blocklist persist alongside the token, so a revoked device stays revoked across restarts. Rotation
//!   replaces the shared token and requires every device to reconnect.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{access_store, Ctx};

/// Registered device self-reported during handshake and kept in memory for display only.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceEntry {
    pub device_id: String,
    pub name: String,
    pub first_seen_at: u64,
    pub last_seen_at: u64,
}

/// Current Unix time in seconds.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct AuthState {
    inner: Mutex<Inner>,
    /// Data directory for write-through persistence of token, registry, and blocklist.
    store_dir: PathBuf,
}

struct Inner {
    /// Argon2id PHC verifier string; the salt is embedded, no plaintext password is held.
    verifier_phc: String,
    /// HTTP session tokens used by plaintext and legacy authentication paths. Deliberately not
    /// persisted: password-login windows re-authenticate after a restart; only pairing survives.
    tokens: HashSet<String>,
    /// Shared admission token embedded in pairing links, persisted and replaced only by `rotate`.
    pairing_token: String,
    /// Display registry of client-reported devices, persisted with the token.
    devices: Vec<DeviceEntry>,
    /// Blocked device IDs. E2EE handshake rejects reconnection, and heartbeat disconnects active matches.
    /// Persisted so revocations survive restarts; cleared together with the registry on rotation.
    blocked: HashSet<String>,
}

/// Hash a plaintext password into an Argon2id PHC string (default parameters: memory-hard, ~tens of
/// milliseconds per verify). The PHC string is the only password-derived value ever persisted.
pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("Failed to hash password: {e}"))
}

impl AuthState {
    /// Load the persisted pairing token, device registry, and blocklist from the data directory, or
    /// create a fresh token and write the file when it is missing or corrupt (the E2EE key pattern).
    /// The Argon2id PHC verifier comes from the caller; it is never stored in the pairing-state file.
    pub fn load_or_create(verifier_phc: &str, data_dir: &Path) -> Self {
        let (pairing_token, devices, blocked) = match access_store::load(data_dir) {
            Some(p) => (
                p.pairing_token,
                p.devices,
                p.blocked_devices.into_iter().collect(),
            ),
            None => {
                let token = new_token();
                if let Err(e) = access_store::save(
                    data_dir,
                    &access_store::PersistedAccess {
                        pairing_token: token.clone(),
                        blocked_devices: Vec::new(),
                        devices: Vec::new(),
                    },
                ) {
                    // Nonfatal: the service still works for this run; only restart persistence degrades.
                    eprintln!("failed to persist remote-access state: {e}");
                }
                (token, Vec::new(), HashSet::new())
            }
        };
        Self {
            inner: Mutex::new(Inner {
                verifier_phc: verifier_phc.to_string(),
                tokens: HashSet::new(),
                pairing_token,
                devices,
                blocked,
            }),
            store_dir: data_dir.to_path_buf(),
        }
    }

    /// Write the current pairing state through to disk. Called with the lock held so concurrent
    /// mutations cannot persist out of order; failures are logged and the in-memory state stays valid.
    fn persist(&self, inner: &Inner) {
        let access = access_store::PersistedAccess {
            pairing_token: inner.pairing_token.clone(),
            blocked_devices: inner.blocked.iter().cloned().collect(),
            devices: inner.devices.clone(),
        };
        if let Err(e) = access_store::save(&self.store_dir, &access) {
            eprintln!("failed to persist remote-access state: {e}");
        }
    }

    fn verify(&self, password: &str) -> bool {
        // Clone the PHC string out of the lock: Argon2id verification is deliberately slow and must not
        // stall unrelated token checks.
        let phc = self.inner.lock().unwrap().verifier_phc.clone();
        let Ok(parsed) = PasswordHash::new(&phc) else {
            return false;
        };
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    }

    /// Verify the password against the hash shared by HTTP login and E2EE's second factor.
    pub fn verify_password(&self, password: &str) -> bool {
        self.verify(password)
    }

    /// Pairing token for this run, embedded in links and checked during handshake.
    pub fn pairing_token(&self) -> String {
        self.inner.lock().unwrap().pairing_token.clone()
    }

    /// Verify a pairing token against the current value in constant time.
    pub fn validate_pairing_token(&self, token: &str) -> bool {
        let inner = self.inner.lock().unwrap();
        constant_time_eq(token.as_bytes(), inner.pairing_token.as_bytes())
    }

    /// Rotate the pairing token and clear devices, effectively replacing links for everyone. Existing
    /// connections retain negotiated keys; the new token blocks only new and reconnecting clients. Restart
    /// the service to disconnect all clients immediately. The persisted file is overwritten, so rotation
    /// remains the explicit invalidation path for the now restart-surviving token.
    pub fn rotate_pairing_token(&self) -> String {
        let mut inner = self.inner.lock().unwrap();
        inner.pairing_token = new_token();
        inner.devices.clear();
        // Full reset: invalidate old links, require every device to pair again, and clear the blocklist.
        inner.blocked.clear();
        self.persist(&inner);
        inner.pairing_token.clone()
    }

    /// Register or update a device after handshake, using placeholders for missing self-reported fields.
    pub fn register_device(&self, device_id: Option<&str>, name: Option<&str>) {
        let id = device_id
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("(unknown)")
            .to_string();
        let nm = name
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("Browser")
            .to_string();
        let now = now_secs();
        let mut inner = self.inner.lock().unwrap();
        if let Some(d) = inner.devices.iter_mut().find(|d| d.device_id == id) {
            d.last_seen_at = now;
            d.name = nm;
        } else {
            inner.devices.push(DeviceEntry {
                device_id: id,
                name: nm,
                first_seen_at: now,
                last_seen_at: now,
            });
        }
        self.persist(&inner);
    }

    /// List devices registered during this run, distinguished by self-reported identifiers.
    pub fn list_devices(&self) -> Vec<DeviceEntry> {
        self.inner.lock().unwrap().devices.clone()
    }

    /// Block a device by ID and remove it from the display registry. [`is_blocked`] rejects its E2EE
    /// handshake even with valid credentials, while heartbeat disconnects an existing connection. Other
    /// devices are unaffected. Return whether it was registered. IDs are self-reported and spoofable.
    pub fn block_device(&self, device_id: &str) -> bool {
        let mut inner = self.inner.lock().unwrap();
        inner.blocked.insert(device_id.to_string());
        let before = inner.devices.len();
        inner.devices.retain(|d| d.device_id != device_id);
        self.persist(&inner);
        inner.devices.len() < before
    }

    /// Whether a device ID is blocked, shared by handshake rejection and heartbeat eviction.
    pub fn is_blocked(&self, device_id: &str) -> bool {
        self.inner.lock().unwrap().blocked.contains(device_id)
    }

    fn mint(&self) -> String {
        let token = Uuid::new_v4().to_string();
        self.inner.lock().unwrap().tokens.insert(token.clone());
        token
    }

    fn check(&self, token: &str) -> bool {
        self.inner.lock().unwrap().tokens.contains(token)
    }

    /// Validate a raw session token for WebSocket `?token=` authentication. Browser WebSocket APIs cannot
    /// set custom headers, so this checks the same login-issued value stored in the token set.
    pub fn token_valid(&self, token: &str) -> bool {
        self.check(token)
    }

    fn revoke(&self, token: &str) {
        self.inner.lock().unwrap().tokens.remove(token);
    }
}

/// Generate an unpredictable token by joining two simple UUID strings.
fn new_token() -> String {
    Uuid::new_v4().simple().to_string() + &Uuid::new_v4().simple().to_string()
}

/// Constant-time comparison for equal-length values to avoid hash timing side channels.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Extract a session token only from `Authorization: Bearer`. Cookies were removed on 2026-07-03; each
/// window holds and presents its own credential through sessionStorage or mobile memory, eliminating
/// cross-window overwrites and WKWebView cookie timing issues. Browser WebSockets use `?token=` because
/// their API cannot set custom headers.
pub(super) fn token_from_headers(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let t = auth.strip_prefix("Bearer ")?.trim();
    if t.is_empty() {
        return None;
    }
    Some(t.to_string())
}

/// Unified authentication gate for `/ws` and data endpoints.
pub fn is_authed(ctx: &Ctx, headers: &HeaderMap) -> bool {
    token_from_headers(headers)
        .map(|t| ctx.auth.check(&t))
        .unwrap_or(false)
}

#[derive(serde::Deserialize)]
pub struct LoginBody {
    password: String,
}

/// Verify login password, issue a token, and return it in a JSON body as `{"token":"…"}`.
///
/// The token is the sole credential. Web clients keep it in per-window sessionStorage and mobile clients
/// in memory, presenting it in WebSocket URLs or HTTP headers. No cookie is issued.
pub async fn login(State(ctx): State<Ctx>, Json(body): Json<LoginBody>) -> impl IntoResponse {
    if !ctx.auth.verify(&body.password) {
        return (StatusCode::UNAUTHORIZED, "Wrong password").into_response();
    }
    let token = ctx.auth.mint();
    Json(serde_json::json!({ "token": token })).into_response()
}

/// Check whether the current request is authenticated when the frontend enters the page.
pub async fn me(State(ctx): State<Ctx>, headers: HeaderMap) -> impl IntoResponse {
    if is_authed(&ctx, &headers) {
        StatusCode::OK
    } else {
        StatusCode::UNAUTHORIZED
    }
}

/// Log out by revoking the bearer token. Each window clears its local copy; sessionStorage also expires
/// when the window closes.
pub async fn logout(State(ctx): State<Ctx>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(t) = token_from_headers(&headers) {
        ctx.auth.revoke(&t);
    }
    "ok".into_response()
}

#[cfg(test)]
mod tests {
    use super::{hash_password, AuthState};
    use std::path::PathBuf;

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vlx-auth-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Test constructor: hash the plaintext once and build the state in a tag-specific tempdir.
    fn new_auth(password: &str, dir: &PathBuf) -> AuthState {
        AuthState::load_or_create(&hash_password(password).unwrap(), dir)
    }

    #[test]
    fn password_verify_and_token_lifecycle() {
        let dir = tempdir("pw");
        let auth = new_auth("s3cret", &dir);
        // Password verification against the Argon2id PHC verifier.
        assert!(auth.verify("s3cret"));
        assert!(!auth.verify("wrong"));
        assert!(!auth.verify(""));

        // Session-token lifecycle: issue, validate, revoke, invalidate.
        let token = auth.mint();
        assert!(auth.check(&token));
        assert!(!auth.check("not-a-token"));
        auth.revoke(&token);
        assert!(!auth.check(&token));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pairing_token_rotate_and_device_registry() {
        let dir = tempdir("rotate");
        let auth = new_auth("pw", &dir);
        // The run's pairing token is stable and verifiable.
        let tok = auth.pairing_token();
        assert!(auth.validate_pairing_token(&tok));
        assert!(!auth.validate_pairing_token("nope"));

        // Register two devices.
        auth.register_device(Some("dev-a"), Some("Mac"));
        auth.register_device(Some("dev-b"), Some("Phone"));
        assert_eq!(auth.list_devices().len(), 2);
        // Registering the same ID updates rather than duplicates it.
        auth.register_device(Some("dev-a"), Some("Mac mini"));
        assert_eq!(auth.list_devices().len(), 2);

        // Rotation invalidates the old token and clears the registry.
        let tok2 = auth.rotate_pairing_token();
        assert_ne!(tok, tok2);
        assert!(!auth.validate_pairing_token(&tok));
        assert!(auth.validate_pairing_token(&tok2));
        assert_eq!(auth.list_devices().len(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn block_device_blocks_and_rotate_clears() {
        let dir = tempdir("block");
        let auth = new_auth("pw", &dir);
        auth.register_device(Some("dev-a"), Some("Mac"));
        auth.register_device(Some("dev-b"), Some("Phone"));

        // Neither device is initially blocked.
        assert!(!auth.is_blocked("dev-a"));
        assert!(!auth.is_blocked("dev-b"));

        // Blocking dev-a returns true, adds it to the blocklist, removes it from display, and spares dev-b.
        assert!(auth.block_device("dev-a"));
        assert!(auth.is_blocked("dev-a"));
        assert!(!auth.is_blocked("dev-b"));
        assert_eq!(auth.list_devices().len(), 1);
        assert_eq!(auth.list_devices()[0].device_id, "dev-b");

        // Blocking an unknown ID returns false but still rejects future handshakes using it.
        assert!(!auth.block_device("dev-x"));
        assert!(auth.is_blocked("dev-x"));

        // Rotation fully resets the blocklist as well.
        auth.rotate_pairing_token();
        assert!(!auth.is_blocked("dev-a"));
        assert!(!auth.is_blocked("dev-x"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Token, device registry, and blocklist survive a "restart" (a second AuthState from the same
    /// directory), which is exactly the invariant GitHub issue #15 demands.
    #[test]
    fn pairing_state_persists_across_instances() {
        let dir = tempdir("persist");
        let phc = hash_password("pw").unwrap();

        let a = AuthState::load_or_create(&phc, &dir);
        let token = a.pairing_token();
        a.register_device(Some("dev-a"), Some("Phone"));
        a.register_device(Some("dev-b"), Some("Tablet"));
        assert!(a.block_device("dev-b"));

        // A fresh instance from the same data dir sees the same token, registry, and blocklist.
        let b = AuthState::load_or_create(&phc, &dir);
        assert_eq!(b.pairing_token(), token);
        assert!(b.validate_pairing_token(&token));
        assert_eq!(b.list_devices().len(), 1);
        assert_eq!(b.list_devices()[0].device_id, "dev-a");
        assert!(b.is_blocked("dev-b"));
        assert!(!b.is_blocked("dev-a"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Rotation overwrites the persisted file: a later instance sees the new token and empty blocklist.
    #[test]
    fn rotate_persists_new_token_and_clears_state() {
        let dir = tempdir("rotate-persist");
        let phc = hash_password("pw").unwrap();

        let a = AuthState::load_or_create(&phc, &dir);
        let old = a.pairing_token();
        a.register_device(Some("dev-a"), Some("Phone"));
        a.block_device("dev-x");
        let rotated = a.rotate_pairing_token();
        assert_ne!(old, rotated);

        let b = AuthState::load_or_create(&phc, &dir);
        assert_eq!(b.pairing_token(), rotated);
        assert!(!b.validate_pairing_token(&old));
        assert!(b.list_devices().is_empty());
        assert!(!b.is_blocked("dev-x"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// hash_password produces a PHC verifier that accepts the original password and rejects others.
    #[test]
    fn hash_password_roundtrip() {
        let dir = tempdir("hash");
        let phc = hash_password("correct horse").unwrap();
        assert!(phc.starts_with("$argon2id$"), "expected Argon2id PHC, got: {phc}");
        let auth = AuthState::load_or_create(&phc, &dir);
        assert!(auth.verify_password("correct horse"));
        assert!(!auth.verify_password("battery staple"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
