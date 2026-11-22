const fs = require('fs');

async function testWebCryptoInterop() {
  const envelope = JSON.parse(fs.readFileSync('/tmp/test-otter-vault.enc', 'utf8'));
  const password = "test_master_pass_123";

  // Base64 helper
  function base64ToBytes(b64) {
    return Uint8Array.from(Buffer.from(b64, 'base64'));
  }

  const salt = base64ToBytes(envelope.kdf.salt_base64);
  const iv = base64ToBytes(envelope.cipher.iv_base64);
  const tag = base64ToBytes(envelope.cipher.tag_base64);
  const ciphertext = base64ToBytes(envelope.ciphertext_base64);

  // Concatenate [ciphertext || tag] for WebCrypto AES-GCM
  const combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext, 0);
  combined.set(tag, ciphertext.length);

  // 1. Derive Key with PBKDF2
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  const aesKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: envelope.kdf.iterations,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );

  // 2. Decrypt with AES-GCM
  const decryptedBytes = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv,
      additionalData: enc.encode("otter-vault-v1")
    },
    aesKey,
    combined
  );

  const decryptedJson = new TextDecoder().decode(decryptedBytes);
  const vault = JSON.parse(decryptedJson);

  console.log("WebCrypto Decryption SUCCESS!");
  console.log("Decrypted item count:", vault.items.length);
  console.log("First item title:", vault.items[0].title);
  console.log("First item username:", vault.items[0].payload.data.username);
  console.log("Second item title:", vault.items[1].title);

  if (vault.items[0].title === "Google Account" && vault.items[1].title === "Linux SSH Keys") {
    console.log("ASSERTION PASSED: 100% interoperability between Rust and WebCrypto!");
    process.exit(0);
  } else {
    console.error("Assertion failed: items mismatch");
    process.exit(1);
  }
}

testWebCryptoInterop().catch(err => {
  console.error("WebCrypto interop failed:", err);
  process.exit(1);
});
