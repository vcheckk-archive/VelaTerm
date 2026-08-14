//! Persistence for remote-access pairing state: shared pairing token, device display registry, and
//! device blocklist. Follows the `e2ee::ServerKeys::load_or_create` pattern — one file in the data
//! directory, mode 0600 on Unix — so pairing links and revocations survive app/server restarts
//! (GitHub issue #15). The explicit "Regenerate link" rotation remains the invalidation path: it
//! overwrites this file with a fresh token and empty registry/blocklist.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::auth::DeviceEntry;

/// Pairing-state filename in the data directory.
const FILENAME: &str = "vlx-web-access.json";

/// On-disk pairing state, serialized in camelCase like the other web-facing structs.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistedAccess {
    /// Shared admission token embedded in pairing links.
    pub pairing_token: String,
    /// Blocked device IDs; must survive restarts so a revoked device cannot return with a long-lived token.
    #[serde(default)]
    pub blocked_devices: Vec<String>,
    /// Display registry of client-reported devices, persisted so the panel stays coherent after restart.
    #[serde(default)]
    pub devices: Vec<DeviceEntry>,
}

/// Full path of the pairing-state file inside a data directory.
fn path(data_dir: &Path) -> PathBuf {
    data_dir.join(FILENAME)
}

/// Load persisted pairing state; None when the file is missing, unreadable, corrupt, or has an empty
/// token — callers then create a fresh token and rewrite the file, matching the E2EE key-file pattern.
pub fn load(data_dir: &Path) -> Option<PersistedAccess> {
    let text = std::fs::read_to_string(path(data_dir)).ok()?;
    serde_json::from_str::<PersistedAccess>(&text)
        .ok()
        .filter(|p| !p.pairing_token.trim().is_empty())
}

/// Atomically save pairing state: write a temp file created owner-only (0600 at open time, so the token
/// never exists with default umask permissions), then rename over the target so a crash mid-write never
/// leaves a truncated token file.
pub fn save(data_dir: &Path, access: &PersistedAccess) -> Result<(), String> {
    let target = path(data_dir);
    let tmp = data_dir.join(format!("{FILENAME}.tmp"));
    let json = serde_json::to_string(access)
        .map_err(|e| format!("failed to serialize remote-access state: {e}"))?;
    super::write_owner_only(&tmp, json.as_bytes())
        .map_err(|e| format!("failed to write remote-access state: {e}"))?;
    std::fs::rename(&tmp, &target)
        .map_err(|e| format!("failed to persist remote-access state: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vlx-access-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = tempdir("roundtrip");
        let access = PersistedAccess {
            pairing_token: "tok-123".into(),
            blocked_devices: vec!["bad-device".into()],
            devices: vec![DeviceEntry {
                device_id: "dev-a".into(),
                name: "Phone".into(),
                first_seen_at: 1,
                last_seen_at: 2,
            }],
        };
        save(&dir, &access).unwrap();
        let loaded = load(&dir).expect("saved state should load");
        assert_eq!(loaded.pairing_token, "tok-123");
        assert_eq!(loaded.blocked_devices, vec!["bad-device".to_string()]);
        assert_eq!(loaded.devices.len(), 1);
        assert_eq!(loaded.devices[0].device_id, "dev-a");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_corrupt_or_empty_token_yields_none() {
        let dir = tempdir("corrupt");
        // Missing file.
        assert!(load(&dir).is_none());
        // Corrupt JSON.
        std::fs::write(dir.join(FILENAME), "{not json").unwrap();
        assert!(load(&dir).is_none());
        // Valid JSON but empty token must not be treated as a usable credential.
        std::fs::write(dir.join(FILENAME), r#"{"pairingToken":"  "}"#).unwrap();
        assert!(load(&dir).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn saved_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir("perm");
        let access = PersistedAccess {
            pairing_token: "tok".into(),
            blocked_devices: Vec::new(),
            devices: Vec::new(),
        };
        save(&dir, &access).unwrap();
        let mode = std::fs::metadata(dir.join(FILENAME))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
