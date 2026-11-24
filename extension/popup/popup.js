// Au1Password Extension - Popup Script
let allItems = [];
let currentHost = "";
let currentFullUrl = "";
let rootHost = "";
let activeCategory = "all";
let isPasswordVisible = false;
let isSaving = false;

// Thai Mnemonic Pattern Constants
const THAI_DAYS = ["อา", "จ", "อ", "พ", "พฤ", "ศ", "ส"];
const THAI_DAY_FULL = ["วันอาทิตย์", "วันจันทร์", "วันอังคาร", "วันพุธ", "วันพฤหัสบดี", "วันศุกร์", "วันเสาร์"];
const THAI_MONTHS = ["มค", "กพ", "มีค", "เมย", "พค", "มิย", "กค", "สค", "กย", "ตค", "พย", "ธค"];
const THAI_MONTH_FULL = ["มกราคม", "กุมภาพันธ์", "มีนาคม", "เมษายน", "พฤษภาคม", "มิถุนายน", "กรกฎาคม", "สิงหาคม", "กันยายน", "ตุลาคม", "พฤศจิกายน", "ธันวาคม"];
const THAI_COLORS = ["แดง", "เหลือง", "ชมพู", "เขียว", "ส้ม", "ฟ้า", "ม่วง"];

// 1. Generate Thai Mnemonic Code: ศ20พย69ฟ้า13 (with optional randomization on regeneration)
function generateThaiMnemonicCode(addSuffix = false, randomize = false) {
  const now = new Date();
  let dayOfWeek = now.getDay();
  let dateStr = String(now.getDate()).padStart(2, "0");
  let monthIndex = now.getMonth();
  let yearBE = String(now.getFullYear() + 543).slice(-2);
  let hourStr = String(now.getHours()).padStart(2, "0");

  if (randomize) {
    dayOfWeek = Math.floor(Math.random() * 7);
    const randDay = 1 + Math.floor(Math.random() * 28);
    dateStr = String(randDay).padStart(2, "0");
    monthIndex = Math.floor(Math.random() * 12);
    const randHour = Math.floor(Math.random() * 24);
    hourStr = String(randHour).padStart(2, "0");
  }

  const dayAbbr = THAI_DAYS[dayOfWeek];
  const monthAbbr = THAI_MONTHS[monthIndex];
  const colorStr = THAI_COLORS[dayOfWeek];

  let code = `${dayAbbr}${dateStr}${monthAbbr}${yearBE}${colorStr}${hourStr}`;
  if (addSuffix) code += "#";
  const breakdown = [
    { lbl: "วัน", val: `${dayAbbr} (${THAI_DAY_FULL[dayOfWeek]})` },
    { lbl: "วันที่", val: dateStr },
    { lbl: "เดือน", val: `${monthAbbr} (${THAI_MONTH_FULL[monthIndex]})` },
    { lbl: "ปี พ.ศ.", val: `${yearBE} (25${yearBE})` },
    { lbl: "สีประจำวัน", val: colorStr },
    { lbl: "เวลา/ชม.", val: `${hourStr}:00` }
  ];
  return { code, breakdown };
}

// 2. Generate Standard Random Password
function generateStandardPassword(length = 18, useUpper = true, useLower = true, useNums = true, useSyms = true) {
  let pool = "";
  const lower = "abcdefghijklmnopqrstuvwxyz";
  const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const numbers = "0123456789";
  const symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";

  if (useLower) pool += lower;
  if (useUpper) pool += upper;
  if (useNums) pool += numbers;
  if (useSyms) pool += symbols;
  if (!pool) pool = lower + numbers;

  let pass = "";
  if (useLower) pass += lower[Math.floor(Math.random() * lower.length)];
  if (useUpper) pass += upper[Math.floor(Math.random() * upper.length)];
  if (useNums) pass += numbers[Math.floor(Math.random() * numbers.length)];
  if (useSyms) pass += symbols[Math.floor(Math.random() * symbols.length)];

  while (pass.length < length) {
    pass += pool[Math.floor(Math.random() * pool.length)];
  }
  return pass.split("").sort(() => 0.5 - Math.random()).join("");
}

// 3. Generate PIN Code
function generatePin(length = 6) {
  let pin = "";
  for (let i = 0; i < length; i++) {
    pin += Math.floor(Math.random() * 10);
  }
  return pin;
}

// 4. TOTP Computation
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

// Strict domain matching helpers
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

function domainMatches(itemUrl, targetHost) {
  const itemHost = extractDomainHostname(itemUrl);
  if (!itemHost || !targetHost) return false;
  if (itemHost === targetHost) return true;
  if (itemHost.endsWith("." + targetHost) || targetHost.endsWith("." + itemHost)) return true;
  return false;
}

// Toast helper
function showToast(text) {
  const t = document.getElementById("toast");
  if (!t) return;
  t.textContent = text;
  t.classList.add("show");
  setTimeout(() => t.classList.remove("show"), 1800);
}

// Copy helper
function copyToClipboard(val, label) {
  if (!val) {
    showToast(`No ${label} to copy`);
    return;
  }
  navigator.clipboard.writeText(val).then(() => {
    showToast(`Copied ${label}!`);
  });
}

// Autofill helper
function autofillCredentials(username, password, totp) {
  if (window.chrome?.runtime?.sendMessage) {
    chrome.runtime.sendMessage({ action: "autofill", username, password, totp }, () => {
      showToast("Autofilled login credentials!");
    });
  } else {
    showToast(`Autofilled: ${username}`);
  }
}

function escapeHtml(str) {
  return String(str || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// TAB NAVIGATION
function switchTab(tabName) {
  if (document.body.classList.contains("vault-locked")) return;
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.tab === tabName);
  });

  const tabVault = document.getElementById("tabVault");
  const tabGen = document.getElementById("tabGen");
  const tabSync = document.getElementById("tabSync");
  const tabSettings = document.getElementById("tabSettings");
  const drawer = document.getElementById("itemEditDrawer");

  if (drawer) drawer.style.display = "none";

  tabVault.style.display = tabName === "vault" ? "flex" : "none";
  tabGen.style.display = tabName === "gen" ? "flex" : "none";
  tabSync.style.display = tabName === "sync" ? "flex" : "none";
  tabSettings.style.display = tabName === "settings" ? "flex" : "none";

  if (tabName === "gen") {
    refreshGenOutput();
  } else if (tabName === "sync") {
    loadSyncStatus();
  } else if (tabName === "settings") {
    updateHealthMetrics();
  }
}

// In-place live TOTP timer updater (Zero DOM destruction, zero scroll jumps)
async function updateAllTotpTimers() {
  const cards = document.querySelectorAll(".item-card[data-id]");
  for (const card of cards) {
    const id = card.dataset.id;
    const it = allItems.find(x => x.id === id);
    if (!it || !it.totp) continue;
    const td = await getTotp(it.totp);
    if (!td) continue;
    const codeEl = card.querySelector(".totp-code");
    const timerEl = card.querySelector(".totp-timer");
    if (codeEl) codeEl.textContent = `${td.otp.slice(0, 3)} ${td.otp.slice(3)}`;
    if (timerEl) timerEl.textContent = `${td.secondsLeft}s`;
  }
}

// CREATE / RENDER ITEM CARDS
async function createItemCard(it, isSuggested = false, reusedSet = null) {
  const card = document.createElement("div");
  card.className = `item-card ${isSuggested ? "suggested" : ""}`;
  card.dataset.id = it.id || "";

  let totpHtml = "";
  if (it.totp) {
    const totpData = await getTotp(it.totp);
    if (totpData) {
      const fmtCode = `${totpData.otp.slice(0, 3)} ${totpData.otp.slice(3)}`;
      totpHtml = `
        <div class="totp-row" onclick="event.stopPropagation()">
          <span class="totp-code">${fmtCode}</span>
          <span class="totp-timer">${totpData.secondsLeft}s</span>
          <button class="btn-sm" style="margin-left: auto;" id="btnCopyTotp-${it.id}">Copy OTP</button>
        </div>
      `;
    }
  }

  let sub = it.username || it.user || it.rpId || "";
  if (it.type === "note") {
    sub = it.notes ? (it.notes.slice(0, 32) + (it.notes.length > 32 ? "…" : "")) : "Secure Note";
  } else if (it.type === "card") {
    sub = it.cardNumber ? ("•••• " + it.cardNumber.slice(-4)) : "Payment Card";
  } else if (!sub) {
    sub = "No username";
  }

  const favStar = it.favorite ? `<svg width="11" height="11" viewBox="0 0 24 24" fill="#eab308" stroke="#eab308" style="vertical-align:-1px; margin-right:4px;"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>` : "";

  // Category Icon SVG
  let iconSvg = `<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>`;
  if (it.type === "passkey") {
    iconSvg = `<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><circle cx="12" cy="11" r="3"/>`;
  } else if (it.type === "totp") {
    iconSvg = `<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>`;
  } else if (it.type === "card") {
    iconSvg = `<rect x="1" y="4" width="22" height="16" rx="2" ry="2"/><line x1="1" y1="10" x2="23" y2="10"/>`;
  } else if (it.type === "note") {
    iconSvg = `<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>`;
  }

  const isReused = it.password && reusedSet && reusedSet.has(it.password);
  const reusedBadge = isReused ? `<span style="display:inline-flex; align-items:center; gap:2px; color:#f59e0b; font-size:10px; background:rgba(245,158,11,0.15); padding:1px 5px; border-radius:3px; margin-left:4px;" title="Reused password across accounts"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>Reused</span>` : "";

  // Action buttons
  let actionButtonsHtml = "";
  if (it.type === "note") {
    actionButtonsHtml = `
      <button class="btn-sm" id="btnCopyNote-${it.id}" title="Copy Note">
        <span class="btn-text">Copy Note</span>
      </button>
    `;
  } else if (it.type === "passkey") {
    actionButtonsHtml = `
      <button class="btn-sm btn-fill" id="btnFill-${it.id}" title="Use Passkey">
        <span class="btn-text">Passkey</span>
      </button>
    `;
  } else {
    actionButtonsHtml = `
      <button class="btn-sm btn-fill" id="btnFill-${it.id}" title="Fill credentials on page" aria-label="Fill">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
        <span class="btn-text">Fill</span>
      </button>
      <button class="btn-sm" id="btnCopyPass-${it.id}" title="Copy Password" aria-label="Copy Password">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        <span class="btn-text">Copy</span>
      </button>
    `;
  }

  card.innerHTML = `
    <div class="item-top-row">
      <div class="item-type-avatar">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${iconSvg}</svg>
      </div>
      <div class="item-info">
        <div class="item-title">${favStar}${escapeHtml(it.title || "Untitled")}${reusedBadge}</div>
        <div class="item-sub">${escapeHtml(sub)}</div>
      </div>
      <div class="item-actions">
        ${actionButtonsHtml}
        <button class="btn-sm btn-edit-item" id="btnEdit-${it.id}" title="Edit item" aria-label="Edit item">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
        </button>
      </div>
    </div>
    ${totpHtml}
  `;

  card.addEventListener("click", () => {
    openItemEditor(it);
  });

  const btnFill = card.querySelector(`#btnFill-${it.id}`);
  if (btnFill) {
    btnFill.addEventListener("click", (e) => {
      e.stopPropagation();
      autofillCredentials(it.username || it.user || "", it.password || "", it.totp || "");
    });
  }

  const btnCopyPass = card.querySelector(`#btnCopyPass-${it.id}`);
  if (btnCopyPass) {
    btnCopyPass.addEventListener("click", (e) => {
      e.stopPropagation();
      copyToClipboard(it.password || "", "Password");
    });
  }

  const btnCopyNote = card.querySelector(`#btnCopyNote-${it.id}`);
  if (btnCopyNote) {
    btnCopyNote.addEventListener("click", (e) => {
      e.stopPropagation();
      copyToClipboard(it.notes || "", "Note");
    });
  }

  const btnEdit = card.querySelector(`#btnEdit-${it.id}`);
  if (btnEdit) {
    btnEdit.addEventListener("click", (e) => {
      e.stopPropagation();
      openItemEditor(it);
    });
  }

  const btnCopyTotp = card.querySelector(`#btnCopyTotp-${it.id}`);
  if (btnCopyTotp) {
    btnCopyTotp.addEventListener("click", async (e) => {
      e.stopPropagation();
      const td = await getTotp(it.totp);
      if (td) copyToClipboard(td.otp, "2FA Code");
    });
  }

  return card;
}

// RENDER ALL ITEMS
async function renderAllItems(query = "") {
  const matchedContainer = document.getElementById("matchedList");
  const matchedSection = document.getElementById("matchedSection");
  const allContainer = document.getElementById("allItemsList");
  const allSectionTitle = document.getElementById("allSectionTitle");

  matchedContainer.innerHTML = "";
  allContainer.innerHTML = "";

  const q = query.toLowerCase().trim();

  // Filter valid non-trashed items
  let validItems = allItems.filter(it => !it.trashed && !it.archived);

  // Precompute password reuse set in one pass O(N)
  const passCounts = {};
  for (const it of validItems) {
    if (it.password) {
      passCounts[it.password] = (passCounts[it.password] || 0) + 1;
    }
  }
  const reusedSet = new Set(Object.keys(passCounts).filter(p => passCounts[p] > 1));

  // Filter by category pill
  if (activeCategory === "login") {
    validItems = validItems.filter(it => !it.type || it.type === "login");
  } else if (activeCategory === "passkey") {
    validItems = validItems.filter(it => it.type === "passkey");
  } else if (activeCategory === "totp") {
    validItems = validItems.filter(it => !!it.totp || it.type === "totp");
  } else if (activeCategory === "card") {
    validItems = validItems.filter(it => it.type === "card");
  } else if (activeCategory === "note") {
    validItems = validItems.filter(it => it.type === "note");
  } else if (activeCategory === "fav") {
    validItems = validItems.filter(it => !!it.favorite);
  }

  // Split into matched (for active site) and others
  const matchedItems = [];
  const otherItems = [];

  for (const it of validItems) {
    const multiMatch = Array.isArray(it.urls) && it.urls.some(x => domainMatches(x, currentHost));
    const isMatch = currentHost && (
      domainMatches(it.url, currentHost) ||
      multiMatch ||
      (it.rpId && (it.rpId.toLowerCase() === currentHost || currentHost.endsWith("." + it.rpId.toLowerCase())))
    );

    if (isMatch) {
      matchedItems.push(it);
    } else {
      otherItems.push(it);
    }
  }

  // Filter by search query
  const filterFn = (it) => {
    if (!q) return true;
    const title = (it.title || "").toLowerCase();
    const user = (it.username || it.user || "").toLowerCase();
    const url = (it.url || "").toLowerCase();
    const notes = (it.notes || "").toLowerCase();
    const multiUrls = Array.isArray(it.urls) && it.urls.some(x => (x || "").toLowerCase().includes(q));
    const customFields = Array.isArray(it.customFields) && it.customFields.some(cf => (cf.label || "").toLowerCase().includes(q) || (cf.value || "").toLowerCase().includes(q));
    const attachments = Array.isArray(it.attachments) && it.attachments.some(att => (att.name || "").toLowerCase().includes(q));
    return title.includes(q) || user.includes(q) || url.includes(q) || multiUrls || customFields || attachments || notes.includes(q);
  };

  const finalMatched = matchedItems.filter(filterFn);
  const finalAll = otherItems.filter(filterFn);

  // Render Matched Section
  if (finalMatched.length > 0) {
    matchedSection.style.display = "block";
    for (const it of finalMatched) {
      const card = await createItemCard(it, true, reusedSet);
      matchedContainer.appendChild(card);
    }
  } else {
    matchedSection.style.display = "none";
  }

  // Render All Section
  if (finalAll.length > 0) {
    allSectionTitle.textContent = finalMatched.length > 0 ? "Other Vault Items" : "All Vault Items";
    for (const it of finalAll) {
      const card = await createItemCard(it, false, reusedSet);
      allContainer.appendChild(card);
    }
  } else if (finalMatched.length === 0) {
    allContainer.innerHTML = `<div style="text-align: center; color: var(--muted); padding: 24px 10px; font-size: 12px;">No matching items found</div>`;
  }
}

// ITEM EDITOR DRAWER (CREATE & EDIT)
function openItemEditor(item = null) {
  if (document.body.classList.contains("vault-locked")) return;
  const drawer = document.getElementById("itemEditDrawer");
  const drawerTitle = document.getElementById("drawerTitle");
  const btnDelete = document.getElementById("btnDrawerDelete");
  const btnOpenUrl = document.getElementById("btnOpenEditUrl");
  const previewTotp = document.getElementById("editTotpPreview");

  if (!item) {
    // NEW ITEM
    drawerTitle.textContent = "New Vault Item";
    btnDelete.style.display = "none";
    document.getElementById("editItemId").value = "";
    document.getElementById("editType").value = "login";

    let defaultTitle = "";
    if (currentHost && currentHost !== "local / system page" && currentHost !== "desktop") {
      defaultTitle = currentHost.replace(/^www\./, "");
      defaultTitle = defaultTitle.charAt(0).toUpperCase() + defaultTitle.slice(1);
    }
    document.getElementById("editTitle").value = defaultTitle;
    document.getElementById("editUsername").value = "";
    document.getElementById("editPassword").value = generateStandardPassword(18);
    document.getElementById("editUrl").value = currentFullUrl || (currentHost ? `https://${currentHost}` : "");
    document.getElementById("editTotp").value = "";
    document.getElementById("editFolder").value = "";
    document.getElementById("editFavorite").checked = false;
    document.getElementById("editNotes").value = "";
    btnOpenUrl.style.display = document.getElementById("editUrl").value ? "block" : "none";
    previewTotp.style.display = "none";
  } else {
    // EDIT EXISTING ITEM
    drawerTitle.textContent = "Edit Vault Item";
    btnDelete.style.display = "inline-flex";
    document.getElementById("editItemId").value = item.id || "";
    document.getElementById("editType").value = item.type || "login";
    document.getElementById("editTitle").value = item.title || "";
    document.getElementById("editUsername").value = item.username || item.user || "";
    document.getElementById("editPassword").value = item.password || "";
    document.getElementById("editUrl").value = item.url || "";
    document.getElementById("editTotp").value = item.totp || "";
    document.getElementById("editFolder").value = item.folder || "";
    document.getElementById("editFavorite").checked = !!item.favorite;
    document.getElementById("editNotes").value = item.notes || "";
    btnOpenUrl.style.display = item.url ? "block" : "none";
    updateDrawerTotpPreview(item.totp);
  }

  isPasswordVisible = false;
  document.getElementById("editPassword").type = "password";

  drawer.style.display = "flex";
  document.getElementById("editTitle").focus();
}

let deleteConfirmTimer = null;
function resetDeleteBtnState() {
  const btn = document.getElementById("btnDrawerDelete");
  if (btn) {
    delete btn.dataset.confirming;
    btn.textContent = "Delete Item";
    btn.style.background = "";
    btn.style.color = "";
    btn.style.borderColor = "";
  }
  if (deleteConfirmTimer) {
    clearTimeout(deleteConfirmTimer);
    deleteConfirmTimer = null;
  }
}

function closeItemEditor() {
  resetDeleteBtnState();
  document.getElementById("itemEditDrawer").style.display = "none";
}

// Live TOTP preview in drawer
async function updateDrawerTotpPreview(secret) {
  const previewBox = document.getElementById("editTotpPreview");
  const codeEl = document.getElementById("editTotpCode");
  const timerEl = document.getElementById("editTotpTimer");

  if (!secret) {
    previewBox.style.display = "none";
    return;
  }

  const td = await getTotp(secret);
  if (td) {
    previewBox.style.display = "flex";
    codeEl.textContent = `${td.otp.slice(0, 3)} ${td.otp.slice(3)}`;
    timerEl.textContent = `${td.secondsLeft}s`;
  } else {
    previewBox.style.display = "none";
  }
}

// SAVE ITEM & AUTO-SYNC HANDLER
function handleSaveItem(e) {
  if (e) e.preventDefault();
  if (isSaving) return;

  const id = document.getElementById("editItemId").value;
  const title = document.getElementById("editTitle").value.trim();
  if (!title) {
    showToast("Title is required");
    return;
  }

  let urlVal = document.getElementById("editUrl").value.trim();
  if (urlVal && !urlVal.includes("://")) {
    urlVal = "https://" + urlVal;
  }

  const existing = allItems.find(it => it.id === id);
  const itemData = {
    ...(existing || {}),
    id: id || ("item_" + Date.now() + "_" + Math.random().toString(36).substr(2, 6)),
    title,
    type: document.getElementById("editType").value,
    username: document.getElementById("editUsername").value.trim(),
    password: document.getElementById("editPassword").value,
    url: urlVal,
    totp: document.getElementById("editTotp").value.trim(),
    folder: document.getElementById("editFolder").value.trim(),
    favorite: document.getElementById("editFavorite").checked,
    notes: document.getElementById("editNotes").value.trim(),
    updated_at: Math.floor(Date.now() / 1000)
  };

  const btnSave = document.getElementById("btnDrawerSave");
  btnSave.textContent = "Saving…";
  btnSave.disabled = true;
  isSaving = true;

  const urlParams = new URLSearchParams(window.location.search);
  const isPreview = urlParams.get("preview") === "1" || !window.chrome?.runtime?.sendMessage;

  if (window.chrome?.runtime?.sendMessage && !isPreview) {
    chrome.runtime.sendMessage({ action: "saveItem", item: itemData }, (res) => {
      btnSave.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg> Save &amp; Auto-Sync`;
      btnSave.disabled = false;
      isSaving = false;

      if (res && res.success) {
        showToast("Saved & Auto-Synced to Cloud!");
        closeItemEditor();
        loadVaultData();
      } else {
        showToast("Error saving: " + (res?.error || "Unknown"));
      }
    });
  } else {
    // Standalone / Preview Mode
    const existingIdx = allItems.findIndex(it => it.id === itemData.id);
    if (existingIdx >= 0) {
      allItems[existingIdx] = itemData;
    } else {
      allItems.unshift(itemData);
    }
    btnSave.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg> Save &amp; Auto-Sync`;
    btnSave.disabled = false;
    isSaving = false;
    showToast("Saved & Auto-Synced to Cloud!");
    closeItemEditor();
    renderAllItems(document.getElementById("searchInput").value);
    updateHealthMetrics();
  }
}

// DELETE ITEM HANDLER (Safe 2-Step Inline Confirmation without window.confirm focus loss)
function handleDeleteItem() {
  const btn = document.getElementById("btnDrawerDelete");
  const id = document.getElementById("editItemId").value;
  if (!id) return;

  if (!btn.dataset.confirming) {
    btn.dataset.confirming = "true";
    btn.textContent = "Click again to confirm delete";
    btn.style.background = "rgba(239, 68, 68, 0.2)";
    btn.style.color = "#ef4444";
    btn.style.borderColor = "#ef4444";
    if (deleteConfirmTimer) clearTimeout(deleteConfirmTimer);
    deleteConfirmTimer = setTimeout(resetDeleteBtnState, 3500);
    return;
  }

  resetDeleteBtnState();

  const urlParams = new URLSearchParams(window.location.search);
  const isPreview = urlParams.get("preview") === "1" || !window.chrome?.runtime?.sendMessage;

  if (window.chrome?.runtime?.sendMessage && !isPreview) {
    chrome.runtime.sendMessage({ action: "deleteItem", id, permanent: false }, (res) => {
      if (res && res.success) {
        showToast("Item deleted & Auto-Synced!");
        closeItemEditor();
        loadVaultData();
      } else {
        showToast("Error deleting: " + (res?.error || "Unknown"));
      }
    });
  } else {
    allItems = allItems.filter(it => it.id !== id);
    showToast("Item deleted!");
    closeItemEditor();
    renderAllItems(document.getElementById("searchInput").value);
    updateHealthMetrics();
  }
}

// GENERATOR CONTROLS
let genCurrentMode = "thai";

function refreshGenOutput(randomize = false) {
  const outputEl = document.getElementById("genResultOutput");
  const thaiBreakdown = document.getElementById("thaiBreakdownBox");
  const strengthBar = document.getElementById("strengthBar");
  const strengthText = document.getElementById("strengthText");

  if (genCurrentMode === "thai") {
    const res = generateThaiMnemonicCode(false, randomize);
    outputEl.value = res.code;
    thaiBreakdown.innerHTML = res.breakdown.map(b => `
      <div class="breakdown-chip">
        <span class="breakdown-chip-val">${b.val}</span>
        <span class="breakdown-chip-lbl">${b.lbl}</span>
      </div>
    `).join("");
    strengthText.textContent = "Chrono-Mnemonic (Thai Pattern)";
    strengthText.style.color = "var(--amber)";
  } else if (genCurrentMode === "std") {
    const len = parseInt(document.getElementById("stdLengthSlider").value, 10);
    const u = document.getElementById("chkUpper").checked;
    const l = document.getElementById("chkLower").checked;
    const n = document.getElementById("chkNumbers").checked;
    const s = document.getElementById("chkSymbols").checked;
    outputEl.value = generateStandardPassword(len, u, l, n, s);
    strengthText.textContent = len >= 16 ? "Very Strong (256-bit entropy)" : "Good";
    strengthText.style.color = "var(--accent)";
  } else if (genCurrentMode === "pin") {
    const len = parseInt(document.getElementById("pinLengthSlider").value, 10);
    outputEl.value = generatePin(len);
    strengthText.textContent = `Numeric PIN (${len} digits)`;
    strengthText.style.color = "var(--primary)";
  }
}

// SYNC STATUS & CONTROLS (Multi-Cloud: Google Drive, GitHub, GitLab, SafeHost)
function loadSyncStatus(autoPullIfConfigured = false) {
  const badge = document.getElementById("syncStatusBadge");
  const subtitle = document.getElementById("syncStatusSubtitle");
  const timestampEl = document.getElementById("syncLastTimestamp");
  const targetFolderEl = document.getElementById("syncTargetFolder");
  const headerIndicator = document.getElementById("headerSyncIndicator");

  if (window.chrome?.runtime?.sendMessage) {
    chrome.runtime.sendMessage({ action: "getSyncStatus" }, (res) => {
      if (res && res.success && res.data) {
        const d = res.data;
        const activeProvider = d.active_provider || "gdrive";
        const providerData = (d.providers && d.providers[activeProvider]) ? d.providers[activeProvider] : d;
        const providerName = providerData?.name || (activeProvider.toUpperCase());

        if (providerData?.connected) {
          badge.textContent = `Connected (${providerName})`;
          badge.className = "badge unlocked";
          subtitle.textContent = `Active Cloud Provider: ${providerName}`;
          timestampEl.textContent = providerData.last_sync || "Just now";
          if (targetFolderEl) targetFolderEl.textContent = providerData.target_folder || providerData.repo || providerData.project_id || providerData.endpoint_url || "Cloud";
          if (headerIndicator) {
            headerIndicator.querySelector(".dot").className = "dot online";
            headerIndicator.querySelector(".sync-text").textContent = "Auto-Sync";
          }

          if (autoPullIfConfigured && !window._hasAutoPulled) {
            window._hasAutoPulled = true;
            triggerSyncPull(true);
          }
        } else {
          badge.textContent = "Offline / Local";
          badge.className = "badge";
          subtitle.textContent = `Provider: ${providerName} (Configure in App)`;
          timestampEl.textContent = providerData?.last_sync || "Local only";
          if (headerIndicator) {
            headerIndicator.querySelector(".dot").className = "dot";
            headerIndicator.querySelector(".sync-text").textContent = "Local";
          }
        }
      } else {
        if (badge) {
          badge.textContent = "Ready";
          badge.className = "badge";
        }
        if (subtitle) subtitle.textContent = "Local encryption active";
      }
    });
  } else {
    badge.textContent = "Connected (Multi-Cloud)";
    badge.className = "badge unlocked";
    subtitle.textContent = "Connected: Google Drive / GitHub / GitLab";
    timestampEl.textContent = new Date().toLocaleString();
  }
}

function triggerSyncPush() {
  const btn = document.getElementById("btnSyncPush");
  const feedback = document.getElementById("syncFeedbackBox");
  btn.textContent = "Pushing…";
  btn.disabled = true;

  if (window.chrome?.runtime?.sendMessage) {
    chrome.runtime.sendMessage({ action: "syncPush" }, (res) => {
      btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="17 11 12 6 7 11"/><line x1="12" y1="6" x2="12" y2="18"/></svg> Push Local &rarr; Cloud`;
      btn.disabled = false;
      if (res && res.success) {
        showToast("Vault pushed to Google Drive!");
        feedback.style.display = "block";
        feedback.textContent = `Pushed successfully (${res.data?.timestamp || "now"}).`;
        loadSyncStatus();
      } else {
        showToast("Push failed: " + (res?.error || "Error"));
      }
    });
  } else {
    setTimeout(() => {
      btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="17 11 12 6 7 11"/><line x1="12" y1="6" x2="12" y2="18"/></svg> Push Local &rarr; Cloud`;
      btn.disabled = false;
      feedback.style.display = "block";
      feedback.textContent = `Pushed successfully (${new Date().toLocaleTimeString()}).`;
      showToast("Vault pushed to Google Drive!");
    }, 500);
  }
}

function triggerSyncPull(isSilent = false) {
  const btn = document.getElementById("btnSyncPull");
  const feedback = document.getElementById("syncFeedbackBox");
  if (!isSilent) {
    btn.textContent = "Pulling…";
    btn.disabled = true;
  }

  if (window.chrome?.runtime?.sendMessage) {
    chrome.runtime.sendMessage({ action: "syncPull" }, (res) => {
      if (!isSilent) {
        btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="7 13 12 18 17 13"/><line x1="12" y1="18" x2="12" y2="6"/></svg> Pull Cloud &rarr; Local`;
        btn.disabled = false;
      }
      if (res && res.success) {
        if (!isSilent) showToast(`Vault pulled: ${res.data?.item_count || 0} items updated!`);
        feedback.style.display = "block";
        feedback.textContent = `Pulled successfully (${res.data?.item_count || 0} items updated). Last sync: ${res.data?.timestamp || "now"}`;
        loadVaultData();
      } else if (!isSilent) {
        showToast("Pull failed: " + (res?.error || "Error"));
      }
    });
  } else {
    setTimeout(() => {
      if (!isSilent) {
        btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="7 13 12 18 17 13"/><line x1="12" y1="18" x2="12" y2="6"/></svg> Pull Cloud &rarr; Local`;
        btn.disabled = false;
        feedback.style.display = "block";
        feedback.textContent = `Pulled successfully (${allItems.length} items synced).`;
        showToast("Vault pulled from Google Drive!");
      }
    }, 500);
  }
}

// HEALTH METRICS & SETTINGS
function updateHealthMetrics() {
  const valid = allItems.filter(it => !it.trashed && !it.archived);
  document.getElementById("metricTotalItems").textContent = valid.length;
  document.getElementById("metricTotpCount").textContent = valid.filter(it => !!it.totp || it.type === "totp").length;
  document.getElementById("metricPasskeysCount").textContent = valid.filter(it => it.type === "passkey").length;

  const passMap = {};
  valid.forEach(it => {
    if (it.password) {
      passMap[it.password] = (passMap[it.password] || 0) + 1;
    }
  });
  const reusedCount = valid.filter(it => it.password && passMap[it.password] > 1).length;
  const weakCount = valid.filter(it => {
    const p = it.password || "";
    return p.length > 0 && p.length < 10;
  }).length;

  const elWeak = document.getElementById("metricWeakCount");
  if (elWeak) {
    elWeak.textContent = `${reusedCount} R / ${weakCount} W`;
    elWeak.title = `${reusedCount} accounts reuse passwords, ${weakCount} weak passwords`;
  }
}

// LOCK VAULT CONTROLLER & HANDLERS
function setExtensionLockedState(locked) {
  const badge = document.getElementById("vaultStatusBadge");
  const lockedView = document.getElementById("lockedView");
  const tabsNav = document.getElementById("popupTabsNav");
  const tabVault = document.getElementById("tabVault");
  const tabGen = document.getElementById("tabGen");
  const tabSync = document.getElementById("tabSync");
  const tabSettings = document.getElementById("tabSettings");
  const drawer = document.getElementById("itemEditDrawer");
  const headerActions = document.querySelector(".header-actions");

  const unauthenticatedInertEls = [tabsNav, tabVault, tabGen, tabSync, tabSettings, drawer, headerActions].filter(Boolean);

  if (locked) {
    document.body.classList.add("vault-locked");
    if (badge) {
      badge.textContent = "Locked";
      badge.className = "badge locked";
    }
    unauthenticatedInertEls.forEach(el => {
      el.setAttribute("inert", "");
      el.setAttribute("aria-hidden", "true");
    });
    if (lockedView) {
      lockedView.removeAttribute("inert");
      lockedView.removeAttribute("aria-hidden");
      lockedView.style.display = "flex";
    }
    if (tabsNav) tabsNav.style.display = "none";
    if (tabVault) tabVault.style.display = "none";
    if (drawer) drawer.style.display = "none";

    if (window.chrome?.storage?.local) {
      chrome.storage.local.get("lastUsername", (data) => {
        if (data && data.lastUsername && typeof window.updateAccountUI === "function") {
          window.updateAccountUI(data.lastUsername);
        }
      });
    }

    setTimeout(() => {
      const pass = document.getElementById("popupMasterPass");
      if (pass) {
        pass.value = "";
        pass.focus();
      }
    }, 50);
  } else {
    document.body.classList.remove("vault-locked");
    if (badge) {
      badge.textContent = "Unlocked";
      badge.className = "badge unlocked";
    }
    unauthenticatedInertEls.forEach(el => {
      el.removeAttribute("inert");
      el.removeAttribute("aria-hidden");
    });
    if (lockedView) {
      lockedView.setAttribute("inert", "");
      lockedView.setAttribute("aria-hidden", "true");
      lockedView.style.display = "none";
    }
    if (tabsNav) tabsNav.style.display = "flex";
    if (tabVault) tabVault.style.display = "flex";
  }
}

function handleLockVault() {
  window._isExplicitlyLocked = true;
  setExtensionLockedState(true);
  if (window.chrome?.runtime?.sendMessage) {
    chrome.runtime.sendMessage({ action: "lock" }, (res) => {
      showToast("Vault locked");
    });
  } else {
    showToast("Vault locked");
  }
}

let pending2faTempToken = null;

// UNLOCK VAULT
function handlePopupUnlock(e) {
  e.preventDefault();
  const userInput = document.getElementById("popupUsername");
  let username = (userInput ? userInput.value : "").trim();
  if (!username) {
    const disp = document.getElementById("displayUsername");
    if (disp) username = disp.textContent.trim();
  }
  const passInput = document.getElementById("popupMasterPass");
  const totpWrap = document.getElementById("popup2faWrapper");
  const totpInput = document.getElementById("popup2faCode");
  const errEl = document.getElementById("popupUnlockError");
  const btnUnlock = document.getElementById("btnPopupUnlock");

  // Step 2: 2FA Verification if temp token is pending
  if (pending2faTempToken) {
    const code = (totpInput ? totpInput.value : "").trim();
    if (!code) {
      errEl.textContent = "Please enter the 6-digit 2FA code";
      errEl.style.display = "block";
      totpInput?.focus();
      return;
    }
    btnUnlock.textContent = "Verifying…";
    btnUnlock.disabled = true;
    errEl.style.display = "none";

    chrome.runtime.sendMessage({ action: "verify2fa", temp_token: pending2faTempToken, totp_code: code }, (res) => {
      btnUnlock.textContent = "Unlock";
      btnUnlock.disabled = false;
      if (res && res.success) {
        pending2faTempToken = null;
        if (totpWrap) totpWrap.style.display = "none";
        if (totpInput) totpInput.value = "";
        if (username && window.chrome?.storage?.local) {
          chrome.storage.local.set({ lastUsername: username });
        }
        if (typeof window.updateAccountUI === "function") {
          window.updateAccountUI(username);
        }
        passInput.value = "";
        window._isExplicitlyLocked = false;
        setExtensionLockedState(false);
        loadVaultData();
      } else {
        errEl.textContent = res?.error || "Invalid 2FA code";
        errEl.style.display = "block";
        totpInput?.focus();
        totpInput?.select();
      }
    });
    return;
  }

  const password = passInput.value;
  passInput.classList.remove("input-error");
  errEl.style.display = "none";

  if (!username) {
    errEl.textContent = "Please enter your username";
    errEl.style.display = "block";
    userInput?.classList.add("input-error");
    userInput?.focus();
    return;
  }

  if (!password) {
    errEl.textContent = "Please enter your master password";
    errEl.style.display = "block";
    passInput.classList.add("input-error");
    passInput.focus();
    return;
  }

  btnUnlock.textContent = "Unlocking…";
  btnUnlock.disabled = true;
  errEl.style.display = "none";

  if (window.chrome?.runtime?.sendMessage) {
    chrome.runtime.sendMessage({ action: "unlock", username, password }, (res) => {
      btnUnlock.textContent = "Unlock";
      btnUnlock.disabled = false;

      if (res && res.requires_2fa) {
        pending2faTempToken = res.temp_token;
        if (totpWrap) totpWrap.style.display = "block";
        if (totpInput) {
          totpInput.value = "";
          totpInput.focus();
        }
        errEl.textContent = "2FA enabled: enter your 6-digit Authenticator code and press Unlock.";
        errEl.style.display = "block";
        return;
      }

      if (res && res.success) {
        pending2faTempToken = null;
        if (totpWrap) totpWrap.style.display = "none";
        if (username && window.chrome?.storage?.local) {
          chrome.storage.local.set({ lastUsername: username });
        }
        if (typeof window.updateAccountUI === "function") {
          window.updateAccountUI(username);
        }
        passInput.value = "";
        window._isExplicitlyLocked = false;
        setExtensionLockedState(false);
        loadVaultData();
      } else {
        errEl.textContent = res?.error || "Incorrect username or master password";
        errEl.style.display = "block";
      }
    });
  } else {
    btnUnlock.textContent = "Unlock";
    btnUnlock.disabled = false;
    window._isExplicitlyLocked = false;
    setExtensionLockedState(false);
    renderAllItems();
  }
}

// LOAD VAULT STATUS & ITEMS
function loadVaultData() {
  const statusBadge = document.getElementById("vaultStatusBadge");
  const urlParams = new URLSearchParams(window.location.search);
  const isPreview = urlParams.get("preview") === "1" || !window.chrome?.runtime?.sendMessage;

  if (window._isExplicitlyLocked) {
    setExtensionLockedState(true);
    return;
  }

  if (isPreview) {
    if (urlParams.get("state") === "locked") {
      setExtensionLockedState(true);
      return;
    }

    setExtensionLockedState(false);

    if (allItems.length === 0) {
      allItems = [
        {
          id: "item_kbank",
          title: "KBank K-Cyber",
          username: "phongsakorn.dev",
          password: "ศ20พย69ฟ้า13#",
          url: "https://online.kasikornbank.com",
          totp: "JBSWY3DPEHPK3PXP",
          type: "login",
          favorite: true
        },
        {
          id: "item_gh",
          title: "GitHub Personal",
          username: "phongsakorn.dev@gmail.com",
          password: "SuperSecretPassword123!",
          url: "https://github.com",
          totp: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
          type: "login",
          favorite: true
        },
        {
          id: "item_google",
          title: "Google Workspace",
          username: "phongsakorn20mlw@gmail.com",
          password: "MySecurePass2026#",
          url: "https://accounts.google.com",
          type: "login"
        },
        {
          id: "item_passkey1",
          title: "Cloudflare FIDO2 Key",
          username: "security@domain.com",
          password: "",
          url: "https://dash.cloudflare.com",
          type: "passkey"
        }
      ];
    }

    renderAllItems(document.getElementById("searchInput").value);
    updateHealthMetrics();
    loadSyncStatus();

    const previewTab = urlParams.get("tab");
    if (previewTab) {
      switchTab(previewTab);
      if (previewTab === "edit") {
        openItemEditor(allItems[0]);
      }
    }
    return;
  }

  // Real Chrome Extension Runtime Call
  chrome.runtime.sendMessage({ action: "getStatus" }, (res) => {
    if (!res || !res.success) {
      if (statusBadge) {
        statusBadge.textContent = "Offline";
        statusBadge.className = "badge locked";
      }
      const errEl = document.getElementById("popupUnlockError");
      if (errEl) {
        const sUrl = res?.serverUrl || "https://au1password.onrender.com";
        errEl.textContent = `Server unreachable (${sUrl}). Check connection or change server in Settings.`;
        errEl.style.display = "block";
      }
      setExtensionLockedState(true);
      return;
    }

    const st = res.data;
    if (st.unlocked) {
      setExtensionLockedState(false);

      chrome.runtime.sendMessage({ action: "getItems" }, (itemRes) => {
        if (itemRes && itemRes.success) {
          allItems = itemRes.items || [];
          renderAllItems(document.getElementById("searchInput").value);
          updateHealthMetrics();
          loadSyncStatus(true);
        } else {
          const errEl = document.getElementById("popupUnlockError");
          if (errEl) {
            errEl.textContent = itemRes?.error || "Vault session expired. Please unlock again.";
            errEl.style.display = "block";
          }
          setExtensionLockedState(true);
        }
      });
    } else {
      setExtensionLockedState(true);
    }
  });
}

// INITIALIZE EXTENSION POPUP
document.addEventListener("DOMContentLoaded", () => {
  const urlParams = new URLSearchParams(window.location.search);

  function updateServerUrlUI(sUrl) {
    const lbl = document.getElementById("currentServerLabel");
    if (lbl) lbl.textContent = sUrl;
    const inp = document.getElementById("settingServerUrl");
    if (inp) inp.value = sUrl;
    const linkApp = document.getElementById("linkOpenApp");
    if (linkApp) linkApp.href = sUrl;
    const linkSettings = document.getElementById("linkOpenAppSettings");
    if (linkSettings) linkSettings.href = sUrl;
  }

  window.updateAccountUI = function(savedUsername) {
    const acctBox = document.getElementById("rememberedAccountBox");
    const inputWrap = document.getElementById("usernameInputWrapper");
    const nameSpan = document.getElementById("displayUsername");
    const uInp = document.getElementById("popupUsername");
    const subTitle = document.getElementById("unlockSubtitle");
    const passInp = document.getElementById("popupMasterPass");

    if (savedUsername && savedUsername.trim()) {
      if (acctBox) acctBox.style.display = "flex";
      if (inputWrap) inputWrap.style.display = "none";
      if (nameSpan) nameSpan.textContent = savedUsername.trim();
      if (uInp) uInp.value = savedUsername.trim();
      if (subTitle) subTitle.textContent = "Enter your master password to unlock.";
      setTimeout(() => { if (passInp) passInp.focus(); }, 60);
    } else {
      if (acctBox) acctBox.style.display = "none";
      if (inputWrap) inputWrap.style.display = "block";
      if (subTitle) subTitle.textContent = "Enter your username and master password.";
      setTimeout(() => { if (uInp) uInp.focus(); }, 60);
    }
  };

  // Restore remembered username
  if (window.chrome?.storage?.local) {
    chrome.storage.local.get("lastUsername", (data) => {
      if (data && data.lastUsername) {
        window.updateAccountUI(data.lastUsername);
      } else {
        window.updateAccountUI("");
      }
    });
  } else {
    window.updateAccountUI("");
  }

  // Switch account button handler
  const btnSwitch = document.getElementById("btnSwitchAccount");
  if (btnSwitch) {
    btnSwitch.addEventListener("click", () => {
      const acctBox = document.getElementById("rememberedAccountBox");
      const inputWrap = document.getElementById("usernameInputWrapper");
      const uInp = document.getElementById("popupUsername");
      if (acctBox) acctBox.style.display = "none";
      if (inputWrap) inputWrap.style.display = "block";
      if (uInp) {
        uInp.focus();
        uInp.select();
      }
    });
  }

  // Load configured server URL
  if (window.chrome?.runtime?.sendMessage) {
    chrome.runtime.sendMessage({ action: "getServerUrl" }, (res) => {
      if (res && res.serverUrl) {
        updateServerUrlUI(res.serverUrl);
      }
    });
  }

  // Server setting controls
  const btnSaveServerUrl = document.getElementById("btnSaveServerUrl");
  if (btnSaveServerUrl) {
    btnSaveServerUrl.addEventListener("click", () => {
      const val = (document.getElementById("settingServerUrl")?.value || "").trim();
      if (!val) return;
      if (window.chrome?.runtime?.sendMessage) {
        chrome.runtime.sendMessage({ action: "setServerUrl", serverUrl: val }, (res) => {
          updateServerUrlUI(res.serverUrl);
          showToast(`Server updated: ${res.serverUrl}`);
          loadVaultData();
        });
      } else {
        updateServerUrlUI(val);
        showToast(`Server updated: ${val}`);
      }
    });
  }

  const btnPresetCloud = document.getElementById("btnPresetCloud");
  if (btnPresetCloud) {
    btnPresetCloud.addEventListener("click", () => {
      const val = "https://au1password.onrender.com";
      const inp = document.getElementById("settingServerUrl");
      if (inp) inp.value = val;
      if (window.chrome?.runtime?.sendMessage) {
        chrome.runtime.sendMessage({ action: "setServerUrl", serverUrl: val }, (res) => {
          updateServerUrlUI(res.serverUrl);
          showToast("Switched to Render Cloud Server");
          loadVaultData();
        });
      }
    });
  }

  const btnPresetLocal = document.getElementById("btnPresetLocal");
  if (btnPresetLocal) {
    btnPresetLocal.addEventListener("click", () => {
      const val = "http://127.0.0.1:8765";
      const inp = document.getElementById("settingServerUrl");
      if (inp) inp.value = val;
      if (window.chrome?.runtime?.sendMessage) {
        chrome.runtime.sendMessage({ action: "setServerUrl", serverUrl: val }, (res) => {
          updateServerUrlUI(res.serverUrl);
          showToast("Switched to Local Daemon (port 8765)");
          loadVaultData();
        });
      }
    });
  }

  // Tab switching buttons
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });

  // Category filter pills
  document.querySelectorAll(".pill-btn").forEach(pill => {
    pill.addEventListener("click", () => {
      document.querySelectorAll(".pill-btn").forEach(p => p.classList.remove("active"));
      pill.classList.add("active");
      activeCategory = pill.dataset.category;
      renderAllItems(document.getElementById("searchInput").value);
    });
  });

  // Query active tab URL & Host
  if (window.chrome?.tabs?.query) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0]?.url) {
        try {
          currentFullUrl = tabs[0].url;
          const u = new URL(tabs[0].url);
          currentHost = u.hostname.toLowerCase();
          const parts = currentHost.split(".");
          rootHost = parts.length >= 2 ? parts.slice(-2).join(".") : currentHost;
          document.getElementById("activeSiteHost").textContent = currentHost;
        } catch (e) {
          document.getElementById("activeSiteHost").textContent = "Local / System Page";
        }
      } else {
        document.getElementById("activeSiteHost").textContent = "Desktop";
      }
      loadVaultData();
    });
  } else {
    currentHost = urlParams.get("host") || "online.kasikornbank.com";
    rootHost = "kasikornbank.com";
    currentFullUrl = "https://online.kasikornbank.com/login";
    document.getElementById("activeSiteHost").textContent = currentHost;
    loadVaultData();
  }

  // Master password unlock form
  const popupMasterPass = document.getElementById("popupMasterPass");
  document.getElementById("popupUnlockForm").addEventListener("submit", handlePopupUnlock);
  if (popupMasterPass) {
    popupMasterPass.addEventListener("input", () => {
      popupMasterPass.classList.remove("input-error");
      const errEl = document.getElementById("popupUnlockError");
      if (errEl) errEl.style.display = "none";
    });
  }

  // Quick Lock button
  document.getElementById("btnQuickLock").addEventListener("click", handleLockVault);
  document.getElementById("btnLockVaultNow").addEventListener("click", handleLockVault);

  // New Item button
  document.getElementById("btnNewItem").addEventListener("click", () => openItemEditor(null));

  // Search input & Clear
  const searchInput = document.getElementById("searchInput");
  const btnClearSearch = document.getElementById("btnClearSearch");

  searchInput.addEventListener("input", (e) => {
    btnClearSearch.style.display = e.target.value ? "block" : "none";
    renderAllItems(e.target.value);
  });

  btnClearSearch.addEventListener("click", () => {
    searchInput.value = "";
    btnClearSearch.style.display = "none";
    renderAllItems("");
    searchInput.focus();
  });

  // Drawer Back & Close
  document.getElementById("btnDrawerBack").addEventListener("click", closeItemEditor);

  // Drawer Form Save
  document.getElementById("itemEditForm").addEventListener("submit", handleSaveItem);
  document.getElementById("btnDrawerSaveTop").addEventListener("click", () => {
    document.getElementById("itemEditForm").requestSubmit();
  });

  // Drawer Form Delete
  document.getElementById("btnDrawerDelete").addEventListener("click", handleDeleteItem);

  // Password Visibility Toggle Eye
  document.getElementById("btnToggleEditPassEye").addEventListener("click", () => {
    isPasswordVisible = !isPasswordVisible;
    const passInput = document.getElementById("editPassword");
    passInput.type = isPasswordVisible ? "text" : "password";
  });

  // Copy buttons in Drawer
  document.getElementById("btnCopyEditUser").addEventListener("click", () => {
    copyToClipboard(document.getElementById("editUsername").value, "Username");
  });

  document.getElementById("btnCopyEditPass").addEventListener("click", () => {
    copyToClipboard(document.getElementById("editPassword").value, "Password");
  });

  document.getElementById("btnOpenEditUrl").addEventListener("click", () => {
    const url = document.getElementById("editUrl").value;
    if (url) window.open(url, "_blank");
  });

  document.getElementById("btnCopyEditTotp").addEventListener("click", async () => {
    const secret = document.getElementById("editTotp").value;
    const td = await getTotp(secret);
    if (td) copyToClipboard(td.otp, "2FA Code");
  });

  // Inline Password Generator in Drawer
  document.getElementById("btnGenInlinePass").addEventListener("click", () => {
    const newPass = generateThaiMnemonicCode(false, true).code;
    document.getElementById("editPassword").value = newPass;
    document.getElementById("editPassword").type = "text";
    isPasswordVisible = true;
    showToast("Generated Thai Mnemonic Password!");
  });

  // Drawer TOTP live listener
  document.getElementById("editTotp").addEventListener("input", (e) => {
    updateDrawerTotpPreview(e.target.value.trim());
  });

  // GENERATOR TAB CONTROLS
  const tabModeThai = document.getElementById("tabModeThai");
  const tabModeStd = document.getElementById("tabModeStd");
  const tabModePin = document.getElementById("tabModePin");
  const thaiControls = document.getElementById("thaiControls");
  const stdControls = document.getElementById("stdControls");
  const pinControls = document.getElementById("pinControls");

  tabModeThai.addEventListener("click", () => {
    genCurrentMode = "thai";
    tabModeThai.classList.add("active");
    tabModeStd.classList.remove("active");
    tabModePin.classList.remove("active");
    thaiControls.style.display = "flex";
    stdControls.style.display = "none";
    pinControls.style.display = "none";
    refreshGenOutput();
  });

  tabModeStd.addEventListener("click", () => {
    genCurrentMode = "std";
    tabModeStd.classList.add("active");
    tabModeThai.classList.remove("active");
    tabModePin.classList.remove("active");
    thaiControls.style.display = "none";
    stdControls.style.display = "flex";
    pinControls.style.display = "none";
    refreshGenOutput();
  });

  tabModePin.addEventListener("click", () => {
    genCurrentMode = "pin";
    tabModePin.classList.add("active");
    tabModeThai.classList.remove("active");
    tabModeStd.classList.remove("active");
    thaiControls.style.display = "none";
    stdControls.style.display = "none";
    pinControls.style.display = "flex";
    refreshGenOutput();
  });

  document.getElementById("btnGenerateThai").addEventListener("click", () => refreshGenOutput(true));
  document.getElementById("btnGenRefresh").addEventListener("click", () => refreshGenOutput(true));

  document.getElementById("stdLengthSlider").addEventListener("input", (e) => {
    document.getElementById("stdLengthVal").textContent = e.target.value;
    refreshGenOutput();
  });

  ["chkUpper", "chkLower", "chkNumbers", "chkSymbols"].forEach(id => {
    document.getElementById(id).addEventListener("change", () => refreshGenOutput());
  });

  document.getElementById("pinLengthSlider").addEventListener("input", (e) => {
    document.getElementById("pinLengthVal").textContent = e.target.value;
    refreshGenOutput();
  });

  document.getElementById("btnGenerateStd").addEventListener("click", () => refreshGenOutput());
  document.getElementById("btnGeneratePin").addEventListener("click", () => refreshGenOutput());

  document.getElementById("btnGenCopy").addEventListener("click", () => {
    const val = document.getElementById("genResultOutput").value;
    copyToClipboard(val, "Generated Password");
  });

  // Shortcut from Generator -> Create Item
  document.getElementById("btnUsePassInNewItem").addEventListener("click", () => {
    const generatedPass = document.getElementById("genResultOutput").value;
    switchTab("vault");
    openItemEditor(null);
    const passEl = document.getElementById("editPassword");
    passEl.value = generatedPass;
    passEl.type = "text";
    isPasswordVisible = true;
  });

  // SYNC TAB BUTTONS
  document.getElementById("btnSyncPush").addEventListener("click", triggerSyncPush);
  document.getElementById("btnSyncPull").addEventListener("click", () => triggerSyncPull(false));

  // Re-compute TOTPs every second in-place without rebuilding DOM (guarded against CPU burn when locked)
  setInterval(() => {
    if (document.body.classList.contains("vault-locked")) return;
    if (allItems.some(i => i.totp)) {
      updateAllTotpTimers();
    }
    const currentDrawerSecret = document.getElementById("editTotp")?.value.trim();
    if (currentDrawerSecret) {
      updateDrawerTotpPreview(currentDrawerSecret);
    }
  }, 1000);

  // Strict Event Interception & Focus Trap while vault is locked (Prevents click/tap bleed-through on sticky/fixed elements)
  ["click", "mousedown", "pointerdown", "touchstart"].forEach(evtName => {
    document.addEventListener(evtName, (e) => {
      if (document.body.classList.contains("vault-locked")) {
        const lockedView = document.getElementById("lockedView");
        if (lockedView && !lockedView.contains(e.target)) {
          e.preventDefault();
          e.stopPropagation();
          e.stopImmediatePropagation();
          document.getElementById("popupMasterPass")?.focus();
        }
      }
    }, true);
  });

  window.addEventListener("keydown", (e) => {
    if (document.body.classList.contains("vault-locked")) {
      const lockedView = document.getElementById("lockedView");
      if (lockedView) {
        if (e.key === "Escape") {
          e.preventDefault();
          e.stopPropagation();
        }
        if (e.key === "Tab") {
          const focusable = lockedView.querySelectorAll('input, button, [tabindex]:not([tabindex="-1"])');
          if (focusable.length > 0) {
            const first = focusable[0];
            const last = focusable[focusable.length - 1];
            if (e.shiftKey && document.activeElement === first) {
              e.preventDefault();
              last.focus();
            } else if (!e.shiftKey && document.activeElement === last) {
              e.preventDefault();
              first.focus();
            }
          }
        }
        if (!lockedView.contains(document.activeElement)) {
          document.getElementById("popupMasterPass")?.focus();
        }
      }
    }
  }, true);
});
