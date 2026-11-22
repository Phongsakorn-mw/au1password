use otter_crypto::{decrypt_vault, encrypt_vault, CryptoError};
use otter_model::{Vault, VaultEnvelope};
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("JSON format error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Could not resolve default user data directory")]
    NoDataDir,
}

pub struct VaultStorage {
    path: PathBuf,
}

impl VaultStorage {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn default_location() -> Result<Self, StorageError> {
        let data_dir = dirs::data_dir().ok_or(StorageError::NoDataDir)?;
        let vault_dir = data_dir.join("otter-vault");
        Ok(Self {
            path: vault_dir.join("vault.enc"),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Read raw encrypted envelope from disk
    pub fn read_envelope(&self) -> Result<VaultEnvelope, StorageError> {
        let content = fs::read_to_string(&self.path)?;
        let envelope: VaultEnvelope = serde_json::from_str(&content)?;
        Ok(envelope)
    }

    /// Atomic write: writes to temporary file then renames to avoid corruption on crash
    pub fn write_envelope(&self, envelope: &VaultEnvelope) -> Result<(), StorageError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        let temp_path = self.path.with_extension("tmp");
        let json = serde_json::to_string_pretty(envelope)?;

        {
            let mut file = File::create(&temp_path)?;
            file.write_all(json.as_bytes())?;
            file.sync_all()?;
        }

        // Backup existing vault if present
        if self.path.exists() {
            let backup_path = self.path.with_extension("bak");
            let _ = fs::copy(&self.path, backup_path);
        }

        fs::rename(temp_path, &self.path)?;
        Ok(())
    }

    /// Load and decrypt vault
    pub fn load_vault(&self, password: &str) -> Result<Vault, StorageError> {
        let envelope = self.read_envelope()?;
        let vault = decrypt_vault(&envelope, password)?;
        Ok(vault)
    }

    /// Encrypt and save vault atomically
    pub fn save_vault(&self, vault: &Vault, password: &str) -> Result<VaultEnvelope, StorageError> {
        let envelope = encrypt_vault(vault, password)?;
        self.write_envelope(&envelope)?;
        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use otter_model::VaultItem;

    #[test]
    fn test_storage_atomic_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test_vault.enc");
        let storage = VaultStorage::new(file_path);

        assert!(!storage.exists());

        let mut vault = Vault::new();
        vault.add_item(VaultItem::new_login(
            "Account",
            "user",
            "pass",
            None,
            vec!["unit-test".into()],
        ));

        let password = "TestMasterPassword_123!";
        storage.save_vault(&vault, password).expect("save succeeds");
        assert!(storage.exists());

        let loaded = storage.load_vault(password).expect("load succeeds");
        assert_eq!(loaded.items.len(), 1);
        assert_eq!(loaded.items[0].title, "Account");
    }
}
