// Au1Password Chrome Extension - Background Service Worker
const DEFAULT_SERVER_URL = "https://au1password.onrender.com";

async function getServerUrl() {
  try {
    if (chrome.storage?.local) {
      const data = await chrome.storage.local.get("serverUrl");
      if (data && data.serverUrl && data.serverUrl.trim()) {
        return data.serverUrl.trim().replace(/\/+$/, "");
      }
    }
  } catch (e) {
    // Ignore storage errors in restricted contexts
  }
  return DEFAULT_SERVER_URL;
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 15000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchWithTimeout(url, { ...options, signal: controller.signal });
    return res;
  } catch (err) {
    if (err.name === "AbortError") {
      throw new Error("Connection timed out (server may be waking up, please retry)");
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

let extensionSessionToken = null;

// Persistent Session Token Manager (Survives MV3 Service Worker Inactivity Termination)
async function getSessionToken() {
  if (extensionSessionToken) return extensionSessionToken;
  try {
    if (chrome.storage?.session) {
      const data = await chrome.storage.session.get("vaultSessionToken");
      if (data && data.vaultSessionToken) {
        extensionSessionToken = data.vaultSessionToken;
        return extensionSessionToken;
      }
    }
  } catch (e) {
    // Ignore storage errors in restricted contexts
  }
  return extensionSessionToken;
}

async function setSessionToken(token) {
  extensionSessionToken = token;
  try {
    if (chrome.storage?.session) {
      if (token) {
        await chrome.storage.session.set({ vaultSessionToken: token });
      } else {
        await chrome.storage.session.remove("vaultSessionToken");
      }
    }
  } catch (e) {
    // Ignore storage errors in restricted contexts
  }
}

async function getAuthHeaders(extra = {}) {
  const h = { ...extra };
  const token = await getSessionToken();
  if (token) {
    h["Authorization"] = `Bearer ${token}`;
    h["X-Vault-Token"] = token;
  }
  return h;
}

// Strict hostname extractor (RFC standard)
function extractDomainHostname(urlStr) {
  try {
    if (!urlStr) return "";
    let formatted = urlStr.trim();
    if (!formatted.includes("://")) formatted = "https://" + formatted;
    return new URL(formatted).hostname.toLowerCase();
  } catch (e) {
    return "";
  }
}

// Strict domain matching (Prevent loose substring and phishing cross-domain matches)
function domainMatches(itemUrl, targetHost) {
  const itemHost = extractDomainHostname(itemUrl);
  if (!itemHost || !targetHost) return false;
  if (itemHost === targetHost) return true;
  // Subdomain matching: e.g. login.live.com matches live.com or vice-versa
  if (itemHost.endsWith("." + targetHost) || targetHost.endsWith("." + itemHost)) return true;
  return false;
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // Wrap async execution inside an immediately-invoked function expression
  (async () => {
    try {
      const serverUrl = await getServerUrl();

      // Server configuration actions
      if (request.action === "getServerUrl") {
        sendResponse({ success: true, serverUrl });
        return;
      }

      if (request.action === "setServerUrl") {
        const newUrl = (request.serverUrl || DEFAULT_SERVER_URL).trim().replace(/\/+$/, "");
        if (chrome.storage?.local) {
          await chrome.storage.local.set({ serverUrl: newUrl });
        }
        await setSessionToken(null);
        sendResponse({ success: true, serverUrl: newUrl });
        return;
      }

      // 1. Get Vault Status
      if (request.action === "getStatus") {
        const headers = await getAuthHeaders();
        const res = await fetchWithTimeout(`${serverUrl}/api/vault/status`, { headers });
        const data = await res.json();
        if (data && data.unlocked && data.session_token) {
          await setSessionToken(data.session_token);
        } else if (data && !data.unlocked) {
          await setSessionToken(null);
        }
        sendResponse({ success: true, data, serverUrl });
        return;
      }

      // 2. Unlock Vault
      if (request.action === "unlock") {
        const payload = { password: request.password };
        if (request.username) payload.username = request.username.trim();
        if (request.totp_code) payload.totp_code = request.totp_code.trim();

        const res = await fetchWithTimeout(`${serverUrl}/api/vault/unlock`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!res.ok || data.error) throw new Error(data.error || "Incorrect master password or username");
        if (data.requires_2fa) {
          sendResponse({
            success: true,
            requires_2fa: true,
            temp_token: data.temp_token,
            username: data.username,
            serverUrl
          });
          return;
        }
        if (data.token) {
          await setSessionToken(data.token);
        }
        sendResponse({ success: true, data, serverUrl });
        return;
      }

      // 2b. Verify 2FA Code
      if (request.action === "verify2fa") {
        const res = await fetchWithTimeout(`${serverUrl}/api/auth/2fa/verify`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            temp_token: request.temp_token,
            totp_code: request.totp_code
          })
        });
        const data = await res.json();
        if (!res.ok || data.error) throw new Error(data.error || "Invalid 2FA code");
        if (data.token) {
          await setSessionToken(data.token);
        }
        sendResponse({ success: true, data, serverUrl });
        return;
      }

      // 3. Lock Vault
      if (request.action === "lock") {
        const headers = await getAuthHeaders({ "Content-Type": "application/json" });
        try {
          const res = await fetchWithTimeout(`${serverUrl}/api/vault/lock`, {
            method: "POST",
            headers
          });
          const data = await res.json();
          await setSessionToken(null);
          sendResponse({ success: true, data });
        } catch (err) {
          await setSessionToken(null);
          sendResponse({ success: true, message: "Locked locally" });
        }
        return;
      }

      // 4. Get All Vault Items
      if (request.action === "getItems") {
        const headers = await getAuthHeaders();
        const res = await fetchWithTimeout(`${serverUrl}/api/vault/items`, { headers });
        if (res.status === 401) {
          await setSessionToken(null);
          throw new Error("Vault session expired. Please unlock again.");
        }
        if (!res.ok) throw new Error("Vault is locked or unavailable");
        const data = await res.json();
        sendResponse({ success: true, items: data.items || [] });
        return;
      }

      // 5. Save Item (Create or Update item & auto-sync to cloud)
      if (request.action === "saveItem") {
        const headers = await getAuthHeaders();
        const res = await fetchWithTimeout(`${serverUrl}/api/vault/items`, { headers });
        if (!res.ok) throw new Error("Vault is locked. Unlock before saving.");
        const data = await res.json();

        let items = data.items || [];
        const itemToSave = request.item;
        if (!itemToSave.id) {
          itemToSave.id = "item_" + Date.now() + "_" + Math.random().toString(36).substr(2, 6);
        }
        itemToSave.updated_at = Math.floor(Date.now() / 1000);

        const idx = items.findIndex(it => it.id === itemToSave.id);
        if (idx >= 0) {
          items[idx] = Object.assign({}, items[idx], itemToSave);
        } else {
          items.push(itemToSave);
        }

        const saveHeaders = await getAuthHeaders({ "Content-Type": "application/json" });
        const saveRes = await fetchWithTimeout(`${serverUrl}/api/vault/save`, {
          method: "POST",
          headers: saveHeaders,
          body: JSON.stringify({ items })
        });
        const saveJson = await saveRes.json();
        if (saveJson.error) throw new Error(saveJson.error);
        sendResponse({ success: true, data: saveJson });
        return;
      }

      // 6. Delete Item (Soft-delete or trash & auto-sync)
      if (request.action === "deleteItem") {
        const headers = await getAuthHeaders();
        const res = await fetchWithTimeout(`${serverUrl}/api/vault/items`, { headers });
        if (!res.ok) throw new Error("Vault is locked");
        const data = await res.json();

        let items = data.items || [];
        const itemId = request.id;
        const idx = items.findIndex(it => it.id === itemId);
        if (idx >= 0) {
          if (request.permanent) {
            items.splice(idx, 1);
          } else {
            items[idx].trashed = true;
            items[idx].trashed_at = Math.floor(Date.now() / 1000);
            items[idx].updated_at = Math.floor(Date.now() / 1000);
          }
        }

        const saveHeaders = await getAuthHeaders({ "Content-Type": "application/json" });
        const delRes = await fetchWithTimeout(`${serverUrl}/api/vault/save`, {
          method: "POST",
          headers: saveHeaders,
          body: JSON.stringify({ items })
        });
        const delJson = await delRes.json();
        if (delJson.error) throw new Error(delJson.error);
        sendResponse({ success: true, data: delJson });
        return;
      }

      // 7. Get Logins For Specific Host
      if (request.action === "getLoginsForHost") {
        let targetHost = (request.host || "").toLowerCase().trim();

        // Check if query comes from extension popup/internal page vs external web tab
        const isExtensionInternal = (sender?.url && sender.url.startsWith("chrome-extension://")) ||
                                    (sender?.tab?.url && sender.tab.url.startsWith("chrome-extension://"));

        if (!isExtensionInternal && sender.tab && sender.tab.url) {
          try {
            const tabHost = new URL(sender.tab.url).hostname.toLowerCase().trim();
            // Disallow a tab on evil.com from asking credentials for bank.com
            if (targetHost && tabHost !== targetHost && !tabHost.endsWith("." + targetHost) && !targetHost.endsWith("." + tabHost)) {
              console.warn(`[Security Alert] Rejected spoofed credential query. Tab origin: ${tabHost}, Requested host: ${targetHost}`);
              sendResponse({ success: false, error: "Security violation: Host mismatch between tab and query", matched: [] });
              return;
            }
            targetHost = tabHost;
          } catch (e) {
            sendResponse({ success: false, error: "Invalid tab URL", matched: [] });
            return;
          }
        }

        const headers = await getAuthHeaders();
        const res = await fetchWithTimeout(`${serverUrl}/api/vault/items`, { headers });
        if (!res.ok) throw new Error("Vault locked");
        const data = await res.json();
        const items = data.items || [];
        const matched = items.filter(it => {
          if (it.trashed || it.archived) return false;
          // Strict URL/RP domain matching (NO loose substring in path, query, or title)
          if (domainMatches(it.url, targetHost)) return true;
          if (Array.isArray(it.urls) && it.urls.some(u => domainMatches(u, targetHost))) return true;
          if (it.rpId && (it.rpId.toLowerCase() === targetHost || targetHost.endsWith("." + it.rpId.toLowerCase()))) return true;
          return false;
        });

        sendResponse({ success: true, matched, total: items.length });
        return;
      }

      // 8. Multi-Cloud Sync Status (Google Drive, GitHub, GitLab, SafeHost)
      if (request.action === "getSyncStatus") {
        try {
          const res = await fetchWithTimeout(`${serverUrl}/api/sync/status`);
          if (res.ok) {
            const data = await res.json();
            sendResponse({ success: true, data });
            return;
          }
        } catch (e) {}
        // Fallback to legacy gdrive status
        const res = await fetchWithTimeout(`${serverUrl}/api/gdrive/status`);
        const data = await res.json();
        sendResponse({ success: true, data });
        return;
      }

      // 9. Multi-Cloud Push (Upload Zero-Knowledge Vault to Active Provider)
      if (request.action === "syncPush") {
        const headers = await getAuthHeaders({ "Content-Type": "application/json" });
        try {
          const res = await fetchWithTimeout(`${serverUrl}/api/sync/push`, { method: "POST", headers });
          const data = await res.json();
          if (res.ok && data.success) {
            sendResponse({ success: true, data });
            return;
          }
          if (data.error && !res.ok && res.status !== 404) throw new Error(data.error);
        } catch (e) {
          if (!e.message?.includes("404")) throw e;
        }
        // Fallback to gdrive
        const res = await fetchWithTimeout(`${serverUrl}/api/gdrive/sync-push`, { method: "POST", headers });
        const data = await res.json();
        if (data.error) throw new Error(data.error);
        sendResponse({ success: true, data });
        return;
      }

      // 10. Multi-Cloud Pull (Download Zero-Knowledge Vault from Active Provider)
      if (request.action === "syncPull") {
        const headers = await getAuthHeaders({ "Content-Type": "application/json" });
        try {
          const res = await fetchWithTimeout(`${serverUrl}/api/sync/pull`, { method: "POST", headers });
          const data = await res.json();
          if (res.ok && data.success) {
            sendResponse({ success: true, data });
            return;
          }
          if (data.error && !res.ok && res.status !== 404) throw new Error(data.error);
        } catch (e) {
          if (!e.message?.includes("404")) throw e;
        }
        // Fallback to gdrive
        const res = await fetchWithTimeout(`${serverUrl}/api/gdrive/sync-pull`, { method: "POST", headers });
        const data = await res.json();
        if (data.error) throw new Error(data.error);
        sendResponse({ success: true, data });
        return;
      }

      // 11. Autofill Credentials in Webpage
      if (request.action === "autofill") {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          if (tabs && tabs[0]?.id) {
            chrome.tabs.sendMessage(tabs[0].id, {
              action: "fillCredentials",
              username: request.username,
              password: request.password,
              totp: request.totp
            }, () => {
              if (chrome.runtime.lastError) {
                // Ignore tab error if content script not loaded
              }
            });
          }
        });
        sendResponse({ success: true });
        return;
      }

      // 12. Inspect Login Submit for Smart Save Suggestion
      if (request.action === "inspectLoginSubmit") {
        const creds = request.creds;
        if (!creds || !creds.password) {
          sendResponse({ success: false });
          return;
        }
        const headers = await getAuthHeaders();
        const res = await fetchWithTimeout(`${serverUrl}/api/vault/items`, { headers });
        if (!res.ok) throw new Error("Vault locked");
        const data = await res.json();
        const items = data.items || [];
        const host = (creds.host || "").toLowerCase();
        const rootHost = host.split(".").slice(-2).join(".");
        const inputUser = (creds.username || "").toLowerCase();

        // Find matches for this domain
        const matches = items.filter(it => {
          if (it.trashed || it.archived) return false;
          return domainMatches(it.url, host) || (Array.isArray(it.urls) && it.urls.some(u => domainMatches(u, host)));
        });

        if (matches.length === 0) {
          // Completely new site
          sendResponse({
            success: true,
            suggestion: {
              actionType: "new",
              host: creds.host,
              username: creds.username,
              password: creds.password,
              title: host.charAt(0).toUpperCase() + host.slice(1)
            }
          });
        } else {
          // Domain exists: check if same username exists
          const sameUser = matches.find(m => (m.username || m.user || "").toLowerCase() === inputUser);
          if (sameUser) {
            if (sameUser.password === creds.password) {
              // Identical - no prompt needed
              sendResponse({ success: true, suggestion: null });
            } else {
              // Password changed -> Update suggestion
              sendResponse({
                success: true,
                suggestion: {
                  actionType: "update",
                  id: sameUser.id,
                  host: creds.host,
                  username: creds.username,
                  password: creds.password,
                  title: sameUser.title
                }
              });
            }
          } else {
            // New account on existing domain -> Add account suggestion
            sendResponse({
              success: true,
              suggestion: {
                actionType: "add_account",
                host: creds.host,
                username: creds.username,
                password: creds.password,
                title: host.charAt(0).toUpperCase() + host.slice(1)
              }
            });
          }
        }
        return;
      }

      // Default fallback
      sendResponse({ success: false, error: "Unknown action" });
    } catch (err) {
      sendResponse({ success: false, error: err.message || "Execution error" });
    }
  })();
  return true; // Keep message channel open for async response
});
