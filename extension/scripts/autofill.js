// Au1Password Content Script - Inline Field Badge & Form Autofill
(function() {
  // Safety: Never inject inline badges into Au1Password's own vault pages, popups, or search boxes
  if (
    window.location.hostname === "au1password.onrender.com" ||
    (window.location.hostname === "127.0.0.1" && window.location.port === "8765") ||
    (window.location.hostname === "localhost" && window.location.port === "8765") ||
    window.location.protocol === "chrome-extension:" ||
    document.querySelector(".popup-container") ||
    document.querySelector(".vault-container") ||
    document.querySelector("#sidebarNav")
  ) {
    return;
  }

  // Safety: Prevent execution inside cross-origin or untrusted iframes (CVE-2023-28121 / Chromium Sandboxed Iframe mitigation)
  if (window.self !== window.top) {
    let isSameOrigin = false;
    try {
      isSameOrigin = window.top.location.origin === window.location.origin;
    } catch (e) {
      isSameOrigin = false;
    }
    if (!isSameOrigin) {
      return;
    }
  }

  const BADGE_ATTR = "data-au1-injected";
  let activeDropdown = null;

  // The A1P Monogram (A + 1 + P in Classic Tech Blue & White)
  const SHIELD_SVG = `
    <svg width="15" height="15" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M7.5 24.5L15 7.5" stroke="#3B82F6" stroke-width="2.6" stroke-linecap="round"/>
      <path d="M15 7.5V24.5" stroke="#FFFFFF" stroke-width="2.6" stroke-linecap="round"/>
      <path d="M15 7.5H19.5C22 7.5 24 9.5 24 12C24 14.5 22 16.5 19.5 16.5H15" stroke="#3B82F6" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/>
      <path d="M11 17.5H15" stroke="#FFFFFF" stroke-width="2.2" stroke-linecap="round"/>
    </svg>
  `;

  // DEF CON 33 / DOM Clickjacking & UI Redressing Defense (Marek Tóth 2025/2026 Disclosure)
  // Ensure the element is genuinely rendered on-screen, not zero-sized, not hidden, not transparent, not pointer-disabled
  function isElementVisiblyRendered(el) {
    if (!el || !el.isConnected) return false;
    if (el.offsetWidth <= 0 || el.offsetHeight <= 0) return false;

    const style = window.getComputedStyle ? window.getComputedStyle(el) : null;
    if (style) {
      if (style.display === "none") return false;
      if (style.visibility === "hidden" || style.visibility === "collapse") return false;
      if (style.pointerEvents === "none") return false;
      const opacity = parseFloat(style.opacity || "1");
      if (opacity < 0.1) return false; // Hidden via transparency
    }

    const rect = el.getBoundingClientRect();
    if (rect.width < 10 || rect.height < 10) return false; // Micro-input clickjacking trap
    if (rect.bottom < 0 || rect.right < 0) return false; // Completely off-screen
    return true;
  }

  // Strict detector for Search or Non-Login Inputs (ไม่ฉีด badge ในช่องค้นหา/แชท/คอมเมนต์)
  function isSearchOrNonLoginInput(el) {
    if (!el) return true;

    // 1. Explicit ignore flags (Au1 / Bitwarden / 1Password standards)
    if (el.hasAttribute && (
      el.hasAttribute("data-au1-ignore") ||
      el.hasAttribute("data-1p-ignore") ||
      el.hasAttribute("data-bwignore")
    )) {
      return true;
    }

    // 2. Element type checks
    const type = (el.type || "").toLowerCase();
    const nonLoginTypes = [
      "search", "hidden", "checkbox", "radio", "submit", "button",
      "file", "image", "reset", "date", "datetime-local", "month",
      "week", "time", "number", "range", "color"
    ];
    if (nonLoginTypes.includes(type)) return true;

    // 3. ARIA / Role
    const role = (el.getAttribute ? el.getAttribute("role") || "" : "").toLowerCase();
    if (role === "search" || role === "searchbox" || role === "combobox") return true;

    // 4. Gather text signals from attributes
    const id = (el.id || "").toLowerCase();
    const name = (el.name || "").toLowerCase();
    const placeholder = (el.placeholder || "").toLowerCase();
    const className = (typeof el.className === "string" ? el.className : "").toLowerCase();
    const ariaLabel = (el.getAttribute ? el.getAttribute("aria-label") || "" : "").toLowerCase();
    const title = (el.getAttribute ? el.getAttribute("title") || "" : "").toLowerCase();

    const combined = `${id} ${name} ${placeholder} ${className} ${ariaLabel} ${title}`;

    // 5. Search & Filter Keywords (English & Thai)
    const searchPattern = /(^|\b|_|-)(search|query|filter|find|lookup|keyword|q)($|\b|_|-)|(ค้นหา|ตัวกรอง|กรองข้อมูล|ค้น)/i;
    if (searchPattern.test(combined)) {
      return true;
    }

    // 6. Non-login semantic keywords (chat, comment, promo, captcha, amount)
    const nonLoginPattern = /(^|\b|_|-)(comment|message|chat|reply|post|feedback|review|prompt|caption|coupon|promo|voucher|discount|captcha|recaptcha|turnstile|amount|qty|quantity|price)($|\b|_|-)/i;
    if (nonLoginPattern.test(combined)) {
      return true;
    }

    // 7. Check parent container (closest search container)
    if (el.closest) {
      if (el.closest("form[role='search']") || el.closest("[role='search']") ||
          el.closest(".search-box, .search-bar, .search-container, .search-input-box, .list-header-search, .header-search, .nav-search")) {
        return true;
      }
    }

    return false;
  }

  // Detect whether an input is a genuine Login / Credential field
  function isLoginOrCredentialField(el) {
    if (!el || el.readOnly || el.disabled) return false;
    if (!isElementVisiblyRendered(el)) return false;
    if (isSearchOrNonLoginInput(el)) return false;

    const type = (el.type || "").toLowerCase();

    // A. Password field is always a credential target
    if (type === "password") return true;

    // B. Email field
    if (type === "email") return true;

    // C. Inside a form/container that contains a password field
    if (el.closest) {
      const container = el.closest("form") || el.closest(".login-card, .login-box, .signin-box, .auth-container, .auth-card, [role='form']");
      if (container && container.querySelector && container.querySelector("input[type='password']")) {
        return true;
      }
    }

    // D. Standalone Username / Identity field (2-step login flows)
    const autocomplete = (el.autocomplete || "").toLowerCase();
    if (autocomplete === "username" || autocomplete === "email" || autocomplete === "webauthn") {
      return true;
    }

    const id = (el.id || "").toLowerCase();
    const name = (el.name || "").toLowerCase();
    const placeholder = (el.placeholder || "").toLowerCase();
    const combined = `${id} ${name} ${placeholder}`;

    // Strict username patterns
    const usernamePattern = /(^|\b|_|-)(username|uname|usr|userid|user_id|user_name|login_id|loginid|login_name|citizen|citizen_id|id_card|idcard)($|\b|_|-)|(เลขประจำตัว|เลขประชาชน|บัตรประชาชน|เลขบัตร|ประชาชน|ชื่อผู้ใช้|รหัสผู้ใช้)/i;
    if (usernamePattern.test(combined)) {
      return true;
    }

    return false;
  }

  // Detect inputs that need inline autofill badge
  function findTargetInputs() {
    const list = new Set();
    const allInputs = document.querySelectorAll(`input:not([${BADGE_ATTR}])`);
    for (const input of allInputs) {
      if (isLoginOrCredentialField(input)) {
        list.add(input);
      }
    }
    return Array.from(list);
  }

  // Centralized high-performance badge repositioning listener (Throttled via requestAnimationFrame)
  const activeBadges = new Set();
  let badgeRafId = null;
  function scheduleBadgeReposition() {
    if (badgeRafId) return;
    badgeRafId = requestAnimationFrame(() => {
      badgeRafId = null;
      for (const updateFn of activeBadges) {
        try { updateFn(); } catch (e) {}
      }
    });
  }
  window.addEventListener("scroll", scheduleBadgeReposition, { passive: true });
  window.addEventListener("resize", scheduleBadgeReposition, { passive: true });

  // Inject floating shield badge aligned to input right edge
  function injectBadge(input) {
    if (input.hasAttribute(BADGE_ATTR)) return;
    input.setAttribute(BADGE_ATTR, "true");

    const badge = document.createElement("div");
    badge.className = "au1-field-badge";
    badge.title = "Au1Password Autofill";
    badge.innerHTML = SHIELD_SVG;

    // Styling for inline badge inside input (Au1 Tech Blue Minimal)
    Object.assign(badge.style, {
      position: "fixed",
      zIndex: "2147483640",
      cursor: "pointer",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      width: "24px",
      height: "24px",
      borderRadius: "6px",
      background: "rgba(59, 130, 246, 0.12)",
      border: "1px solid rgba(59, 130, 246, 0.35)",
      boxShadow: "0 1px 3px rgba(0, 0, 0, 0.1)",
      transition: "all 0.15s ease",
      userSelect: "none"
    });

    badge.addEventListener("mouseenter", () => {
      badge.style.background = "rgba(59, 130, 246, 0.25)";
      badge.style.borderColor = "#3B82F6";
      badge.style.boxShadow = "0 0 8px rgba(59, 130, 246, 0.4)";
      badge.style.transform = "scale(1.08)";
    });
    badge.addEventListener("mouseleave", () => {
      badge.style.background = "rgba(59, 130, 246, 0.12)";
      badge.style.borderColor = "rgba(59, 130, 246, 0.35)";
      badge.style.boxShadow = "0 1px 3px rgba(0, 0, 0, 0.1)";
      badge.style.transform = "scale(1)";
    });

    document.body.appendChild(badge);

    // Centralized batch badge tracking
    function updateBadgePosition() {
      if (!input.isConnected) {
        activeBadges.delete(updateBadgePosition);
        badge.remove();
        return;
      }
      if (!isElementVisiblyRendered(input)) {
        badge.style.display = "none";
        return;
      }
      badge.style.display = "flex";
      const rect = input.getBoundingClientRect();
      const top = rect.top + (rect.height - 24) / 2;
      const left = rect.right - 28;
      badge.style.top = `${top}px`;
      badge.style.left = `${left}px`;
    }

    activeBadges.add(updateBadgePosition);
    updateBadgePosition();
    requestAnimationFrame(updateBadgePosition);

    badge.addEventListener("click", (e) => {
      e.stopPropagation();
      e.preventDefault();
      toggleDropdown(input, badge);
    });
  }

  // Close active dropdown
  function closeDropdown() {
    if (activeDropdown) {
      activeDropdown.remove();
      activeDropdown = null;
    }
  }

  document.addEventListener("click", () => closeDropdown());
  window.addEventListener("scroll", () => closeDropdown(), { passive: true });

  // Show dropdown with matched credentials
  function toggleDropdown(input, badge) {
    if (activeDropdown) {
      closeDropdown();
      return;
    }

    if (!window.chrome?.runtime?.id) return;
    const host = window.location.hostname;
    chrome.runtime.sendMessage({ action: "getLoginsForHost", host }, (res) => {
      const dd = document.createElement("div");
      dd.className = "au1-autofill-dropdown";
      activeDropdown = dd;

      const rect = input.getBoundingClientRect();
      Object.assign(dd.style, {
        position: "fixed",
        top: `${rect.bottom + 4}px`,
        left: `${rect.left}px`,
        width: `${Math.max(260, rect.width)}px`,
        maxHeight: "280px",
        overflowY: "auto",
        background: "#0f172a",
        color: "#f8fafc",
        border: "1px solid #334155",
        borderRadius: "8px",
        boxShadow: "0 10px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.4)",
        zIndex: "2147483647",
        fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
        fontSize: "13px",
        padding: "6px"
      });

      dd.addEventListener("click", (e) => e.stopPropagation());

      if (!res || !res.success) {
        dd.innerHTML = `
          <div style="padding: 12px; text-align: center; color: #94a3b8;">
            <div style="font-weight: 600; color: #f43f5e; margin-bottom: 4px;">Vault Locked or Offline</div>
            <div style="font-size: 11px;">Open Au1Password extension icon to unlock with Master Password.</div>
          </div>
        `;
        appendGeneratorControls(dd, input);
      document.body.appendChild(dd);
        return;
      }

      const items = res.matched || [];
      if (items.length === 0) {
        dd.innerHTML = `
          <div style="padding: 12px; text-align: center; color: #94a3b8;">
            <div style="font-weight: 500; margin-bottom: 4px;">No logins for ${host}</div>
            <div style="font-size: 11px;">Add an item in Au1Password with URL containing this domain.</div>
          </div>
        `;
        appendGeneratorControls(dd, input);
      document.body.appendChild(dd);
        return;
      }

      dd.innerHTML = `
        <div style="padding: 4px 8px 6px; font-size: 11px; font-weight: 600; color: #64748b; text-transform: uppercase; border-bottom: 1px solid #1e293b;">
          Au1Password Logins (${items.length})
        </div>
      `;

      items.forEach(it => {
        const itemRow = document.createElement("div");
        Object.assign(itemRow.style, {
          display: "flex",
          alignItems: "center",
          gap: "10px",
          padding: "8px 10px",
          borderRadius: "6px",
          cursor: "pointer",
          transition: "background 0.12s ease"
        });

        itemRow.addEventListener("mouseenter", () => {
          itemRow.style.background = "#1e293b";
        });
        itemRow.addEventListener("mouseleave", () => {
          itemRow.style.background = "transparent";
        });

        const sub = it.username || it.user || "No username";
        const hasTotp = !!it.totp;

        itemRow.innerHTML = `
          <div style="width: 28px; height: 28px; border-radius: 6px; background: rgba(59,130,246,0.12); border: 1px solid rgba(59,130,246,0.3); display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
            <svg width="15" height="15" viewBox="0 0 32 32" fill="none">
              <path d="M7.5 24.5L15 7.5" stroke="#3B82F6" stroke-width="2.6" stroke-linecap="round"/>
              <path d="M15 7.5V24.5" stroke="#FFFFFF" stroke-width="2.6" stroke-linecap="round"/>
              <path d="M15 7.5H19.5C22 7.5 24 9.5 24 12C24 14.5 22 16.5 19.5 16.5H15" stroke="#3B82F6" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/>
              <path d="M11 17.5H15" stroke="#FFFFFF" stroke-width="2.2" stroke-linecap="round"/>
            </svg>
          </div>
          <div style="flex: 1; min-width: 0;">
            <div style="font-weight: 600; color: #f1f5f9; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(it.title || "Untitled")}</div>
            <div style="font-size: 11.5px; color: #94a3b8; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(sub)}</div>
          </div>
          ${hasTotp ? `<span style="font-size: 9px; padding: 2px 5px; background: rgba(59,130,246,0.18); color: #60a5fa; border-radius: 4px; font-weight: 700;">2FA</span>` : ""}
        `;

        itemRow.addEventListener("click", (e) => {
          if (e && !e.isTrusted) return; // Prevent synthetic clickjacking
          fillAccount(it, input);
          closeDropdown();
        });

        dd.appendChild(itemRow);
      });

      appendGeneratorControls(dd, input);
      document.body.appendChild(dd);
    });
  }

  function escapeHtml(str) {
    return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  // Pure Native TOTP Computation in Content Script
  async function getTotp(secret) {
    try {
      if (!secret) return null;
      const b32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
      const clean = secret.toUpperCase().replace(/[^A-Z2-7]/g, "");
      if (!clean) return null;
      let bits = "";
      for (let i = 0; i < clean.length; i++) {
        const val = b32chars.indexOf(clean.charAt(i));
        if (val === -1) return null;
        bits += val.toString(2).padStart(5, "0");
      }
      const bytes = [];
      for (let i = 0; i + 8 <= bits.length; i += 8) {
        bytes.push(parseInt(bits.substring(i, i + 8), 2));
      }
      const keyBytes = new Uint8Array(bytes);
      const epoch = Math.floor(Date.now() / 1000);
      const timeStep = Math.floor(epoch / 30);
      const timeBuf = new ArrayBuffer(8);
      const timeView = new DataView(timeBuf);
      timeView.setUint32(4, timeStep, false);

      const cryptoKey = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "HMAC", hash: "SHA-1" },
        false,
        ["sign"]
      );
      const signature = await crypto.subtle.sign("HMAC", cryptoKey, timeBuf);
      const hmac = new Uint8Array(signature);
      const offset = hmac[19] & 0x0f;
      const code =
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff);
      const otp = (code % 1000000).toString().padStart(6, "0");
      const secondsLeft = 30 - (epoch % 30);
      return { otp, secondsLeft };
    } catch (e) {
      return null;
    }
  }

  // Perform form autofill (Targeted to active form/container only, never touching search inputs)
  function fillAccount(item, originInput) {
    const username = item.username || item.user || "";
    const password = item.password || "";
    const totpSecret = item.totp || "";

    // Determine target form / container
    let container = document;
    if (originInput && originInput.closest) {
      container = originInput.closest("form") ||
                  originInput.closest(".login-card, .login-box, .signin-box, .auth-container, .auth-card, [role='form']") ||
                  originInput.parentElement?.parentElement ||
                  document;
    }

    // 1. Identify target username input
    let targetUserInput = null;
    if (originInput && originInput.type !== "password" && !isSearchOrNonLoginInput(originInput) && isElementVisiblyRendered(originInput)) {
      targetUserInput = originInput;
    } else {
      const candidates = container.querySelectorAll('input[type="text"], input[type="email"], input:not([type])');
      for (const el of candidates) {
        if (isLoginOrCredentialField(el) && el.type !== "password" && isElementVisiblyRendered(el)) {
          targetUserInput = el;
          break;
        }
      }
    }

    // 2. Identify target password input
    let targetPassInput = null;
    if (originInput && originInput.type === "password" && isElementVisiblyRendered(originInput)) {
      targetPassInput = originInput;
    } else {
      const pwdCandidates = container.querySelectorAll('input[type="password"]');
      for (const el of pwdCandidates) {
        if (!isSearchOrNonLoginInput(el) && isElementVisiblyRendered(el)) {
          targetPassInput = el;
          break;
        }
      }
    }

    // 3. Fill values
    if (username && targetUserInput) {
      targetUserInput.focus();
      targetUserInput.value = username;
      targetUserInput.dispatchEvent(new Event("input", { bubbles: true }));
      targetUserInput.dispatchEvent(new Event("change", { bubbles: true }));
    }

    if (password && targetPassInput) {
      targetPassInput.value = password;
      targetPassInput.dispatchEvent(new Event("input", { bubbles: true }));
      targetPassInput.dispatchEvent(new Event("change", { bubbles: true }));
    }

    // 4. Handle 2FA TOTP Code Autofill & Clipboard Copy
    if (totpSecret) {
      getTotp(totpSecret).then(td => {
        if (td && td.otp) {
          const otpCandidates = Array.from(document.querySelectorAll('input[autocomplete="one-time-code"], input[name*="otp" i], input[name*="2fa" i], input[id*="otp" i], input[id*="2fa" i], input[placeholder*="code" i], input[placeholder*="otp" i]'));
          const visibleOtp = otpCandidates.find(isElementVisiblyRendered);
          if (visibleOtp) {
            visibleOtp.value = td.otp;
            visibleOtp.dispatchEvent(new Event("input", { bubbles: true }));
            visibleOtp.dispatchEvent(new Event("change", { bubbles: true }));
          }
          if (navigator.clipboard?.writeText) {
            navigator.clipboard.writeText(td.otp).catch(() => {});
          }
          showInlineToast(`Autofilled & 2FA Code copied: ${td.otp.slice(0, 3)} ${td.otp.slice(3)}`);
        }
      });
    }

    // Check for CAPTCHA
    const captchaFrame = document.querySelector('iframe[src*="recaptcha"], iframe[src*="turnstile"], iframe[src*="hcaptcha"], .g-recaptcha, .cf-turnstile');
    if (captchaFrame) {
      showInlineToast("Credentials filled! Please complete the human verification prompt.");
      captchaFrame.scrollIntoView({ behavior: "smooth", block: "center" });
    } else if (!totpSecret) {
      showInlineToast(`Autofilled ${item.title || "credentials"}!`);
    }
  }

  function showInlineToast(text) {
    const toast = document.createElement("div");
    Object.assign(toast.style, {
      position: "fixed",
      bottom: "24px",
      right: "24px",
      background: "#0f172a",
      color: "#38bdf8",
      border: "1px solid #0284c7",
      padding: "10px 16px",
      borderRadius: "8px",
      boxShadow: "0 10px 15px -3px rgba(0, 0, 0, 0.4)",
      zIndex: "2147483647",
      fontSize: "12px",
      fontWeight: "500",
      fontFamily: "sans-serif"
    });
    toast.textContent = text;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 2500);
  }

  // Scan and attach badges (Debounced & Performance Guarded)
  let scanDebounceTimer = null;
  function debouncedScan() {
    if (scanDebounceTimer) clearTimeout(scanDebounceTimer);
    scanDebounceTimer = setTimeout(() => {
      scanDebounceTimer = null;
      scanAndInject();
    }, 200);
  }

  function scanAndInject() {
    const inputs = findTargetInputs();
    inputs.forEach(injectBadge);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", scanAndInject);
  } else {
    scanAndInject();
  }
  window.addEventListener("load", scanAndInject);

  // Throttled MutationObserver: only triggers when actual inputs or form elements are added
  const observer = new MutationObserver((mutations) => {
    let relevantNodeAdded = false;
    for (const m of mutations) {
      if (m.addedNodes && m.addedNodes.length > 0) {
        for (const n of m.addedNodes) {
          if (n.nodeType === 1) { // ELEMENT_NODE
            if (n.tagName === "INPUT" || (n.querySelector && n.querySelector("input"))) {
              relevantNodeAdded = true;
              break;
            }
          }
        }
      }
      if (relevantNodeAdded) break;
    }
    if (relevantNodeAdded) {
      debouncedScan();
    }
  });

  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
  } else {
    document.addEventListener("DOMContentLoaded", () => {
      if (document.body) observer.observe(document.body, { childList: true, subtree: true });
    });
  }

  // Listen for background messages
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === "fillCredentials") {
      fillAccount({ username: msg.username, password: msg.password, totp: msg.totp, title: "Requested Account" });
      sendResponse({ filled: true });
    }
  });

  // ==============================================================================
  // PURE NATIVE PASSWORD & USERNAME GENERATOR (ZERO EXTERNAL LIBRARIES)
  // ==============================================================================
  function nativeCryptoRand(min, max) {
    const range = max - min + 1;
    const maxUint32 = 0xFFFFFFFF;
    const limit = maxUint32 - (maxUint32 % range);
    const buf = new Uint32Array(1);
    let rand;
    do {
      window.crypto.getRandomValues(buf);
      rand = buf[0];
    } while (rand >= limit);
    return min + (rand % range);
  }

  function generatePassword(len = 20, useSymbols = true) {
    const lowers = "abcdefghjkmnpqrstuvwxyz";
    const uppers = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    const numbers = "23456789";
    const symbols = "!@#$%^&*-_=+?";
    
    let pool = lowers + uppers + numbers;
    if (useSymbols) pool += symbols;

    let res = "";
    // Guaranteed diversity
    res += lowers[nativeCryptoRand(0, lowers.length - 1)];
    res += uppers[nativeCryptoRand(0, uppers.length - 1)];
    res += numbers[nativeCryptoRand(0, numbers.length - 1)];
    if (useSymbols) res += symbols[nativeCryptoRand(0, symbols.length - 1)];

    while (res.length < len) {
      res += pool[nativeCryptoRand(0, pool.length - 1)];
    }

    // Shuffle characters
    const arr = res.split("");
    for (let i = arr.length - 1; i > 0; i--) {
      const j = nativeCryptoRand(0, i);
      const tmp = arr[i];
      arr[i] = arr[j];
      arr[j] = tmp;
    }
    return arr.join("");
  }

  function generateUsername(serviceHint = "") {
    const adjectives = ["swift", "cosmic", "stealth", "azure", "quantum", "crimson", "silent", "prime", "shadow", "apex"];
    const nouns = ["falcon", "matrix", "shield", "cipher", "vault", "pilot", "spark", "orbit", "phoenix", "beacon"];
    const adj = adjectives[nativeCryptoRand(0, adjectives.length - 1)];
    const noun = nouns[nativeCryptoRand(0, nouns.length - 1)];
    const num = nativeCryptoRand(100, 9999);
    return `${adj}_${noun}${num}`;
  }

  // Inject Generator panel into Dropdown
  function appendGeneratorControls(dd, targetInput) {
    const foot = document.createElement("div");
    foot.style.borderTop = "1px solid #1e293b";
    foot.style.padding = "8px 10px 4px 10px";
    foot.style.display = "flex";
    foot.style.flexDirection = "column";
    foot.style.gap = "8px";

    const btnRow = document.createElement("div");
    btnRow.style.display = "flex";
    btnRow.style.gap = "6px";

    const btnGen = document.createElement("button");
    btnGen.innerHTML = `⚡ Generate Password`;
    Object.assign(btnGen.style, {
      flex: "1",
      padding: "7px 10px",
      background: "rgba(59, 130, 246, 0.15)",
      border: "1px solid rgba(59, 130, 246, 0.35)",
      color: "#60a5fa",
      borderRadius: "6px",
      fontSize: "11.5px",
      fontWeight: "700",
      cursor: "pointer",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      gap: "6px"
    });

    const btnUser = document.createElement("button");
    btnUser.innerHTML = `👤 User`;
    Object.assign(btnUser.style, {
      padding: "7px 10px",
      background: "#1e293b",
      border: "1px solid #334155",
      color: "#cbd5e1",
      borderRadius: "6px",
      fontSize: "11.5px",
      fontWeight: "600",
      cursor: "pointer"
    });

    btnGen.addEventListener("click", (e) => {
      e.stopPropagation();
      const generated = generatePassword(20, true);
      fillGeneratedCredential(generated, targetInput, "password");
      closeDropdown();
      showInlineToast("Generated Strong Password & Filled");
    });

    btnUser.addEventListener("click", (e) => {
      e.stopPropagation();
      const generated = generateUsername();
      fillGeneratedCredential(generated, targetInput, "username");
      closeDropdown();
      showInlineToast(`Generated Username: ${generated}`);
    });

    btnRow.appendChild(btnGen);
    btnRow.appendChild(btnUser);
    foot.appendChild(btnRow);
    dd.appendChild(foot);
  }

  function fillGeneratedCredential(val, targetInput, type) {
    if (!targetInput) return;
    targetInput.value = val;
    targetInput.dispatchEvent(new Event("input", { bubbles: true }));
    targetInput.dispatchEvent(new Event("change", { bubbles: true }));

    // If filling password, also find and fill confirm password field if present
    if (type === "password" && targetInput.type === "password") {
      const container = targetInput.closest("form") || document;
      const allPass = Array.from(container.querySelectorAll('input[type="password"]'));
      allPass.forEach(p => {
        if (p !== targetInput) {
          p.value = val;
          p.dispatchEvent(new Event("input", { bubbles: true }));
          p.dispatchEvent(new Event("change", { bubbles: true }));
        }
      });
    }
  }

  function showInlineToast(msg) {
    const t = document.createElement("div");
    Object.assign(t.style, {
      position: "fixed",
      bottom: "24px",
      right: "24px",
      background: "#090a0f",
      border: "1px solid #3b82f6",
      color: "#f1f5f9",
      padding: "10px 16px",
      borderRadius: "8px",
      fontSize: "12px",
      fontWeight: "600",
      zIndex: "2147483647",
      boxShadow: "0 10px 25px rgba(0,0,0,0.5)",
      display: "flex",
      alignItems: "center",
      gap: "8px",
      transition: "opacity 0.2s ease"
    });
    t.innerHTML = `
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
      <span>${escapeHtml(msg)}</span>
    `;
    document.body.appendChild(t);
    setTimeout(() => {
      t.style.opacity = "0";
      setTimeout(() => t.remove(), 250);
    }, 2800);
  }

  // ==============================================================================
  // SMART SAVE / UPDATE FLOATING BANNER (Form Submit Interceptor)
  // ==============================================================================
  function showSmartSaveBanner(suggestion) {
    const existing = document.getElementById("au1-save-banner");
    if (existing) existing.remove();

    const banner = document.createElement("div");
    banner.id = "au1-save-banner";
    Object.assign(banner.style, {
      position: "fixed",
      top: "16px",
      right: "16px",
      width: "320px",
      background: "#090a0f",
      border: "1px solid #1e2638",
      borderLeft: "3px solid #3b82f6",
      borderRadius: "10px",
      padding: "14px",
      color: "#f4f4f5",
      zIndex: "2147483647",
      boxShadow: "0 12px 30px rgba(0,0,0,0.6)",
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
    });

    const isUpdate = suggestion.actionType === "update";
    const titleText = isUpdate ? "Update Password in Au1Password?" : "Save Password to Au1Password?";
    const actionBtnText = isUpdate ? "Update" : "Save";

    banner.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
        <div style="display: flex; align-items: center; gap: 8px;">
          <svg width="18" height="18" viewBox="0 0 32 32" fill="none">
            <path d="M7.5 24.5L15 7.5" stroke="#3B82F6" stroke-width="2.6" stroke-linecap="round"/>
            <path d="M15 7.5V24.5" stroke="#FFFFFF" stroke-width="2.6" stroke-linecap="round"/>
            <path d="M15 7.5H19.5C22 7.5 24 9.5 24 12C24 14.5 22 16.5 19.5 16.5H15" stroke="#3B82F6" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/>
            <path d="M11 17.5H15" stroke="#FFFFFF" stroke-width="2.2" stroke-linecap="round"/>
          </svg>
          <span style="font-size: 13px; font-weight: 700; color: #f4f4f5;">${titleText}</span>
        </div>
        <button id="btnDismissAu1Save" style="background: transparent; border: none; color: #64748b; font-size: 16px; cursor: pointer; padding: 0 4px;">&times;</button>
      </div>

      <div style="font-size: 12px; color: #94a3b8; margin-bottom: 12px; line-height: 1.4;">
        <div style="color: #cbd5e1; font-weight: 600;">${escapeHtml(suggestion.username || "No username")}</div>
        <div style="font-size: 11px; color: #64748b;">${escapeHtml(suggestion.host)}</div>
      </div>

      <div style="display: flex; gap: 8px;">
        <button id="btnConfirmAu1Save" style="flex: 1; padding: 7px 12px; background: #3b82f6; border: none; color: #ffffff; border-radius: 6px; font-size: 12px; font-weight: 700; cursor: pointer;">
          ${actionBtnText}
        </button>
        <button id="btnIgnoreAu1Save" style="padding: 7px 12px; background: #131622; border: 1px solid #1e2638; color: #94a3b8; border-radius: 6px; font-size: 12px; cursor: pointer;">
          Never
        </button>
      </div>
    `;

    document.body.appendChild(banner);

    document.getElementById("btnDismissAu1Save").onclick = () => banner.remove();
    document.getElementById("btnIgnoreAu1Save").onclick = () => banner.remove();

    document.getElementById("btnConfirmAu1Save").onclick = () => {
      const itemToSave = {
        title: suggestion.title,
        url: "https://" + suggestion.host,
        username: suggestion.username,
        password: suggestion.password,
        type: "login",
        category: "General",
        folder: "Personal",
        updated_at: Math.floor(Date.now() / 1000)
      };
      if (suggestion.id) itemToSave.id = suggestion.id;

      chrome.runtime.sendMessage({ action: "saveItem", item: itemToSave }, (resp) => {
        banner.innerHTML = `
          <div style="display: flex; align-items: center; gap: 8px; color: #3b82f6; font-weight: 700; font-size: 12.5px; padding: 4px 0;">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
            <span>Password Saved to Au1Password!</span>
          </div>
        `;
        setTimeout(() => banner.remove(), 2200);
      });
    };
  }

  // Detect username field with intelligent priority
  function detectUsernameInput(form) {
    const inputs = Array.from(form.querySelectorAll('input:not([type="hidden"]):not([type="password"])'));
    if (inputs.length === 0) return null;

    // 1. High confidence: explicit autocomplete or type email
    const high = inputs.find(i => {
      const ac = (i.autocomplete || "").toLowerCase();
      const t = (i.type || "").toLowerCase();
      return ac === "username" || ac === "email" || t === "email";
    });
    if (high) return high;

    // 2. Name / ID / Placeholder matches username pattern
    const pattern = /(^|\b|_|-)(username|uname|user|email|login|account|userid|user_id)($|\b|_|-)/i;
    const named = inputs.find(i => {
      const n = (i.name || "").toLowerCase();
      const id = (i.id || "").toLowerCase();
      const ph = (i.placeholder || "").toLowerCase();
      return pattern.test(n) || pattern.test(id) || pattern.test(ph);
    });
    if (named) return named;

    // 3. Fallback to first non-search visible input
    return inputs.find(i => !isSearchOrNonLoginInput(i) && isElementVisiblyRendered(i)) || inputs[0];
  }

  // Intercept form submissions
  function handleFormSubmit(form) {
    if (!form || !form.querySelector) return;
    const passInput = form.querySelector('input[type="password"]');
    if (!passInput || !passInput.value) return;

    const userInput = detectUsernameInput(form);
    const username = userInput ? userInput.value.trim() : "";
    const password = passInput.value;

    const creds = {
      host: window.location.hostname,
      username,
      password
    };

    if (!window.chrome?.runtime?.id) return;
    chrome.runtime.sendMessage({ action: "inspectLoginSubmit", creds }, (res) => {
      if (res && res.success && res.suggestion) {
        showSmartSaveBanner(res.suggestion);
      }
    });
  }

  document.addEventListener("submit", (e) => {
    handleFormSubmit(e.target);
  }, true);

  // Capture button clicks for Single Page Apps (React/Vue/Next)
  document.addEventListener("click", (e) => {
    const btn = e.target.closest("button, input[type='button'], input[type='submit'], [role='button']");
    if (!btn) return;
    const btnText = (btn.innerText || btn.value || btn.getAttribute("aria-label") || "").toLowerCase();
    const isSubmit = btn.type === "submit" || /(log ?in|sign ?in|submit|บันทึก|เข้าสู่ระบบ|ยืนยัน)/i.test(btnText);
    if (isSubmit) {
      const form = btn.closest("form") || btn.closest(".login-card, .login-box, .signin-box, .auth-container, [role='form']") || document;
      setTimeout(() => handleFormSubmit(form), 100);
    }
  }, true);

  // Capture Enter key on password inputs
  document.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && e.target && e.target.type === "password") {
      const form = e.target.closest("form") || e.target.closest(".login-card, .login-box, .signin-box, .auth-container, [role='form']") || document;
      setTimeout(() => handleFormSubmit(form), 100);
    }
  }, true);

})();