use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const CURRENT_VAULT_VERSION: u32 = 1;
pub const CURRENT_FORMAT_ID: &str = "otter-vault-v1";
pub const DEFAULT_KDF_ITERATIONS: u32 = 250_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemType {
    Login,
    Note,
    Image,
    File,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginPayload {
    pub username: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp_secret: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotePayload {
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImagePayload {
    pub filename: String,
    pub mime_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dimensions: Option<String>,
    pub data_base64: String,
    pub checksum_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilePayload {
    pub filename: String,
    pub mime_type: String,
    pub size_bytes: u64,
    pub data_base64: String,
    pub checksum_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum ItemPayload {
    Login(LoginPayload),
    Note(NotePayload),
    Image(ImagePayload),
    File(FilePayload),
}

impl ItemPayload {
    pub fn item_type(&self) -> ItemType {
        match self {
            ItemPayload::Login(_) => ItemType::Login,
            ItemPayload::Note(_) => ItemType::Note,
            ItemPayload::Image(_) => ItemType::Image,
            ItemPayload::File(_) => ItemType::File,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultItem {
    pub id: Uuid,
    pub title: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub payload: ItemPayload,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl VaultItem {
    pub fn new_login(
        title: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
        url: Option<String>,
        tags: Vec<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            title: title.into(),
            tags,
            notes: None,
            payload: ItemPayload::Login(LoginPayload {
                username: username.into(),
                password: password.into(),
                url,
                totp_secret: None,
            }),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn new_note(
        title: impl Into<String>,
        content: impl Into<String>,
        tags: Vec<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            title: title.into(),
            tags,
            notes: None,
            payload: ItemPayload::Note(NotePayload {
                content: content.into(),
            }),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn new_image(
        title: impl Into<String>,
        filename: impl Into<String>,
        mime_type: impl Into<String>,
        dimensions: Option<String>,
        data_base64: impl Into<String>,
        checksum_sha256: impl Into<String>,
        tags: Vec<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            title: title.into(),
            tags,
            notes: None,
            payload: ItemPayload::Image(ImagePayload {
                filename: filename.into(),
                mime_type: mime_type.into(),
                dimensions,
                data_base64: data_base64.into(),
                checksum_sha256: checksum_sha256.into(),
            }),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn new_file(
        title: impl Into<String>,
        filename: impl Into<String>,
        mime_type: impl Into<String>,
        size_bytes: u64,
        data_base64: impl Into<String>,
        checksum_sha256: impl Into<String>,
        tags: Vec<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            title: title.into(),
            tags,
            notes: None,
            payload: ItemPayload::File(FilePayload {
                filename: filename.into(),
                mime_type: mime_type.into(),
                size_bytes,
                data_base64: data_base64.into(),
                checksum_sha256: checksum_sha256.into(),
            }),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn item_type(&self) -> ItemType {
        self.payload.item_type()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vault {
    pub version: u32,
    pub items: Vec<VaultItem>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Default for Vault {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            version: CURRENT_VAULT_VERSION,
            items: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }
}

impl Vault {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_item(&mut self, item: VaultItem) {
        self.items.push(item);
        self.updated_at = Utc::now();
    }

    pub fn get_item(&self, id: Uuid) -> Option<&VaultItem> {
        self.items.iter().find(|i| i.id == id)
    }

    pub fn remove_item(&mut self, id: Uuid) -> bool {
        let initial_len = self.items.len();
        self.items.retain(|i| i.id != id);
        if self.items.len() != initial_len {
            self.updated_at = Utc::now();
            true
        } else {
            false
        }
    }
}

/// Parameters for Key Derivation Function (PBKDF2-HMAC-SHA256)
/// Designed for 100% interoperability with WebCrypto in Chrome Extensions
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: String,
    pub salt_base64: String,
    pub iterations: u32,
}

/// Parameters for Symmetric Cipher (AES-256-GCM)
/// Standard 96-bit (12-byte) IV and 128-bit (16-byte) Tag
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CipherParams {
    pub algorithm: String,
    pub iv_base64: String,
    pub tag_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeMeta {
    pub last_modified: i64,
    pub item_count: usize,
}

/// Top-level encrypted envelope stored in disk and synced to Google Drive
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultEnvelope {
    pub version: u32,
    pub format: String,
    pub kdf: KdfParams,
    pub cipher: CipherParams,
    pub ciphertext_base64: String,
    pub meta: EnvelopeMeta,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_item_login_thai_utf8() {
        let item = VaultItem::new_login(
            "บัญชีกสิกรไทย",
            "user@kbank.co.th",
            "Superรหัสผ่าน!@#99",
            Some("https://online.kasikornbank.com".into()),
            vec!["การเงิน".into(), "ธนาคาร".into()],
        );

        let json = serde_json::to_string(&item).expect("serialize");
        let decoded: VaultItem = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(item.id, decoded.id);
        assert_eq!(decoded.title, "บัญชีกสิกรไทย");
        assert_eq!(decoded.item_type(), ItemType::Login);
    }

    #[test]
    fn test_empty_vault_serialization() {
        let vault = Vault::new();
        assert_eq!(vault.items.len(), 0);
        let json = serde_json::to_string(&vault).expect("serialize empty vault");
        let decoded: Vault = serde_json::from_str(&json).expect("deserialize empty vault");
        assert_eq!(decoded.items.len(), 0);
        assert_eq!(decoded.version, CURRENT_VAULT_VERSION);
    }
}
