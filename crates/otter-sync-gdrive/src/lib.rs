use chrono::{DateTime, Utc};
use otter_model::VaultEnvelope;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const GDRIVE_APPDATA_FOLDER: &str = "appDataFolder";
pub const GDRIVE_VAULT_FILENAME: &str = "au1password-vault.enc";
pub const GDRIVE_LEGACY_FILENAME: &str = "otter-vault.enc";
pub const GDRIVE_SCOPE_APPDATA: &str = "https://www.googleapis.com/auth/drive.appdata";

#[derive(Error, Debug)]
pub enum SyncError {
    #[error("Network HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Authentication required: no valid Google Drive OAuth token")]
    Unauthenticated,
    #[error("Google Drive API error: {0}")]
    Api(String),
    #[error("Remote and local conflict detected: {0}")]
    Conflict(String),
    #[error("JSON decode error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthToken {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub token_type: String,
}

impl OAuthToken {
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncResolution {
    InSync,
    UploadLocalToRemote,
    DownloadRemoteToLocal,
    Conflict {
        local_timestamp: i64,
        remote_timestamp: i64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GDriveFileInfo {
    pub id: String,
    pub name: String,
    pub modified_time: DateTime<Utc>,
    pub size: Option<u64>,
}

pub struct GoogleDriveClient {
    #[allow(dead_code)]
    client: reqwest::Client,
    token: Option<OAuthToken>,
}

impl GoogleDriveClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder().build().unwrap(),
            token: None,
        }
    }

    pub fn set_token(&mut self, token: OAuthToken) {
        self.token = Some(token);
    }

    pub fn token(&self) -> Option<&OAuthToken> {
        self.token.as_ref()
    }

    /// Compare local envelope metadata against remote file info to determine sync direction
    pub fn resolve_sync_action(
        local_envelope: &VaultEnvelope,
        remote_file: Option<&GDriveFileInfo>,
    ) -> SyncResolution {
        let local_time = local_envelope.meta.last_modified;

        match remote_file {
            None => SyncResolution::UploadLocalToRemote,
            Some(remote) => {
                let remote_time = remote.modified_time.timestamp();
                let diff = local_time - remote_time;

                if diff.abs() <= 2 {
                    SyncResolution::InSync
                } else if local_time > remote_time {
                    SyncResolution::UploadLocalToRemote
                } else {
                    SyncResolution::DownloadRemoteToLocal
                }
            }
        }
    }

    /// Generates the Google OAuth 2.0 PKCE Authorization URL
    pub fn generate_auth_url(client_id: &str, redirect_uri: &str, state: &str) -> String {
        format!(
            "https://accounts.google.com/o/oauth2/v2/auth?\
            client_id={}&\
            redirect_uri={}&\
            response_type=code&\
            scope={}&\
            access_type=offline&\
            prompt=consent&\
            state={}",
            urlencoding(client_id),
            urlencoding(redirect_uri),
            urlencoding(GDRIVE_SCOPE_APPDATA),
            urlencoding(state)
        )
    }
}

fn urlencoding(input: &str) -> String {
    url::form_urlencoded::byte_serialize(input.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use otter_model::{CipherParams, EnvelopeMeta, KdfParams, VaultEnvelope};

    fn make_test_envelope(last_modified: i64) -> VaultEnvelope {
        VaultEnvelope {
            version: 1,
            format: "au1password-vault-v1".into(),
            kdf: KdfParams {
                algorithm: "PBKDF2-HMAC-SHA256".into(),
                salt_base64: "c2FsdA==".into(),
                iterations: 250000,
            },
            cipher: CipherParams {
                algorithm: "AES-256-GCM".into(),
                iv_base64: "aXY=".into(),
                tag_base64: "dGFn".into(),
            },
            ciphertext_base64: "Y2lwaGVy".into(),
            meta: EnvelopeMeta {
                last_modified,
                item_count: 3,
            },
        }
    }

    #[test]
    fn test_sync_resolution_upload_when_no_remote() {
        let local = make_test_envelope(1700000000);
        let action = GoogleDriveClient::resolve_sync_action(&local, None);
        assert_eq!(action, SyncResolution::UploadLocalToRemote);
    }

    #[test]
    fn test_sync_resolution_in_sync_when_timestamps_match() {
        let local = make_test_envelope(1700000000);
        let remote = GDriveFileInfo {
            id: "drive-file-123".into(),
            name: GDRIVE_VAULT_FILENAME.into(),
            modified_time: DateTime::from_timestamp(1700000001, 0).unwrap(),
            size: Some(1024),
        };
        let action = GoogleDriveClient::resolve_sync_action(&local, Some(&remote));
        assert_eq!(action, SyncResolution::InSync);
    }

    #[test]
    fn test_sync_resolution_download_when_remote_newer() {
        let local = make_test_envelope(1700000000);
        let remote = GDriveFileInfo {
            id: "drive-file-123".into(),
            name: GDRIVE_VAULT_FILENAME.into(),
            modified_time: DateTime::from_timestamp(1700000500, 0).unwrap(),
            size: Some(1024),
        };
        let action = GoogleDriveClient::resolve_sync_action(&local, Some(&remote));
        assert_eq!(action, SyncResolution::DownloadRemoteToLocal);
    }

    #[test]
    fn test_generate_auth_url_contains_appdata_scope() {
        let url = GoogleDriveClient::generate_auth_url("my-client-id.apps.googleusercontent.com", "http://localhost:8085", "state123");
        assert!(url.contains("accounts.google.com"));
        assert!(url.contains("my-client-id"));
        assert!(url.contains("drive.appdata"));
    }
}
