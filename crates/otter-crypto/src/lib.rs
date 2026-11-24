use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use otter_model::{
    CipherParams, EnvelopeMeta, KdfParams, Vault, VaultEnvelope, CURRENT_FORMAT_ID,
    CURRENT_VAULT_VERSION, DEFAULT_KDF_ITERATIONS,
};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Authentication failed: invalid master password or corrupted ciphertext")]
    AuthenticationFailed,
    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),
    #[error("Invalid nonce/IV length, expected 12 bytes")]
    InvalidIvLength,
    #[error("Invalid tag length, expected 16 bytes")]
    InvalidTagLength,
    #[error("Unsupported envelope format: {0}")]
    UnsupportedFormat(String),
    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// Derive a 256-bit AES key using PBKDF2-HMAC-SHA256
/// This matches WebCrypto's subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations })
pub fn derive_key(password: &str, salt: &[u8], iterations: u32) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut *key);
    key
}

/// Encrypts an in-memory Vault into an encrypted VaultEnvelope
pub fn encrypt_vault(vault: &Vault, password: &str) -> Result<VaultEnvelope, CryptoError> {
    let mut rng = rand::thread_rng();

    // 1. Generate 32 bytes cryptographically secure salt
    let mut salt = [0u8; 32];
    rng.fill_bytes(&mut salt);

    // 2. Derive 256-bit AES key
    let key = derive_key(password, &salt, DEFAULT_KDF_ITERATIONS);

    // 3. Generate 12 bytes (96 bits) standard GCM nonce
    let mut iv = [0u8; 12];
    rng.fill_bytes(&mut iv);
    let nonce = Nonce::from_slice(&iv);

    // 4. Serialize Vault payload to JSON bytes
    let plaintext = serde_json::to_vec(vault)?;

    // 5. Encrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&*key)
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    // aes_gcm appends 16-byte tag to the ciphertext
    let ciphertext_and_tag = cipher
        .encrypt(nonce, Payload { msg: &plaintext, aad: b"au1password-vault-v1" })
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    // Split ciphertext and tag
    let split_idx = ciphertext_and_tag.len() - 16;
    let ciphertext = &ciphertext_and_tag[..split_idx];
    let tag = &ciphertext_and_tag[split_idx..];

    let envelope = VaultEnvelope {
        version: CURRENT_VAULT_VERSION,
        format: CURRENT_FORMAT_ID.to_string(),
        kdf: KdfParams {
            algorithm: "PBKDF2-HMAC-SHA256".to_string(),
            salt_base64: B64.encode(salt),
            iterations: DEFAULT_KDF_ITERATIONS,
        },
        cipher: CipherParams {
            algorithm: "AES-256-GCM".to_string(),
            iv_base64: B64.encode(iv),
            tag_base64: B64.encode(tag),
        },
        ciphertext_base64: B64.encode(ciphertext),
        meta: EnvelopeMeta {
            last_modified: vault.updated_at.timestamp(),
            item_count: vault.items.len(),
        },
    };

    Ok(envelope)
}

/// Decrypts a VaultEnvelope back into an in-memory Vault using the master password
pub fn decrypt_vault(envelope: &VaultEnvelope, password: &str) -> Result<Vault, CryptoError> {
    if envelope.format != CURRENT_FORMAT_ID {
        return Err(CryptoError::UnsupportedFormat(envelope.format.clone()));
    }

    // 1. Decode Salt and derive key
    let salt = B64.decode(&envelope.kdf.salt_base64)?;
    let key = derive_key(password, &salt, envelope.kdf.iterations);

    // 2. Decode IV
    let iv_bytes = B64.decode(&envelope.cipher.iv_base64)?;
    if iv_bytes.len() != 12 {
        return Err(CryptoError::InvalidIvLength);
    }
    let nonce = Nonce::from_slice(&iv_bytes);

    // 3. Decode Tag
    let tag_bytes = B64.decode(&envelope.cipher.tag_base64)?;
    if tag_bytes.len() != 16 {
        return Err(CryptoError::InvalidTagLength);
    }

    // 4. Decode Ciphertext and reconstruct combined [ciphertext || tag]
    let ciphertext = B64.decode(&envelope.ciphertext_base64)?;
    let mut ciphertext_and_tag = Vec::with_capacity(ciphertext.len() + 16);
    ciphertext_and_tag.extend_from_slice(&ciphertext);
    ciphertext_and_tag.extend_from_slice(&tag_bytes);

    // 5. Decrypt and authenticate
    let cipher = Aes256Gcm::new_from_slice(&*key)
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    let plaintext = cipher
        .decrypt(nonce, Payload { msg: &ciphertext_and_tag, aad: b"au1password-vault-v1" })
        .or_else(|_| cipher.decrypt(nonce, Payload { msg: &ciphertext_and_tag, aad: b"otter-vault-v1" }))
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    // 6. Deserialize
    let vault: Vault = serde_json::from_slice(&plaintext)?;
    Ok(vault)
}

#[cfg(test)]
mod tests {
    use super::*;
    use otter_model::VaultItem;

    #[test]
    fn test_roundtrip_encryption_decryption() {
        let mut vault = Vault::new();
        vault.add_item(VaultItem::new_login(
            "Test Account",
            "tester@example.com",
            "SuperP@ssw0rd123!",
            Some("https://example.com".into()),
            vec!["test".into()],
        ));
        vault.add_item(VaultItem::new_note(
            "Secret Notes",
            "# Highly confidential notes\n- Key: value",
            vec!["notes".into()],
        ));

        let password = "MyMasterPassword_9988";
        let envelope = encrypt_vault(&vault, password).expect("encryption succeeds");

        assert_eq!(envelope.format, "au1password-vault-v1");
        assert_eq!(envelope.meta.item_count, 2);

        let decrypted = decrypt_vault(&envelope, password).expect("decryption succeeds");
        assert_eq!(decrypted.items.len(), 2);
        assert_eq!(decrypted.items[0].title, "Test Account");
        assert_eq!(decrypted.items[1].title, "Secret Notes");
    }

    #[test]
    fn test_wrong_password_fails_authentication() {
        let mut vault = Vault::new();
        vault.add_item(VaultItem::new_login(
            "Bank Login",
            "admin",
            "secret",
            None,
            vec![],
        ));

        let envelope = encrypt_vault(&vault, "correct_password").expect("encrypt");
        let result = decrypt_vault(&envelope, "WRONG_password");

        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let mut vault = Vault::new();
        vault.add_item(VaultItem::new_note("Test", "Content", vec![]));

        let mut envelope = encrypt_vault(&vault, "password").expect("encrypt");
        let mut raw = B64.decode(&envelope.ciphertext_base64).expect("decode");
        if let Some(b) = raw.first_mut() {
            *b ^= 0xFF; // Flip bits
        }
        envelope.ciphertext_base64 = B64.encode(raw);

        let result = decrypt_vault(&envelope, "password");
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }
}
