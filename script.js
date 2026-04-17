// ============================================================
//  script.js — Frontend Logic
//  Talks to Flask backend at http://localhost:5000
// ============================================================

const API = "http://localhost:5000/api";

// ── Tab routing ────────────────────────────────────────────
const tabTitles = {
  dashboard: ["Dashboard",      "System overview and live statistics"],
  validate:  ["Validate Token", "Test if a token is allowed or denied"],
  tokens:    ["Tokens",         "All issued tokens and their status"],
  clients:   ["Clients",        "Registered API client applications"],
  requests:  ["Request Logs",   "History of every API request"],
  audit:     ["Audit Log",      "Security audit trail from triggers"],
  issue:     ["Issue Token",    "Generate a new access token for a client"],
  revoke:    ["Revoke Token",   "Permanently revoke an existing token"],
};

function showTab(name) {
  // Hide all pages
  document.querySelectorAll(".tab-page").forEach(p => p.classList.remove("active"));
  document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));

  // Activate selected
  document.getElementById("tab-" + name).classList.add("active");
  document.getElementById("nav-" + name).classList.add("active");

  // Update topbar
  const [title, subtitle] = tabTitles[name] || ["", ""];
  document.getElementById("pageTitle").textContent = title;
  document.getElementById("pageSubtitle").textContent = subtitle;

  // Load data for the tab
  if (name === "dashboard") loadStats();
  if (name === "tokens")    loadTokens();
  if (name === "clients")   loadClients();
  if (name === "requests")  loadRequests();
  if (name === "audit")     loadAudit();
  if (name === "issue")     loadIssueTab();
}

// ── Health check ────────────────────────────────────────────
async function checkServer() {
  const dot    = document.getElementById("serverDot");
  const status = document.getElementById("serverStatus");
  try {
    const r = await fetch("http://localhost:5000/health", { signal: AbortSignal.timeout(3000) });
    if (r.ok) {
      dot.classList.add("green");
      status.textContent = "Backend online";
    } else {
      throw new Error();
    }
  } catch {
    dot.style.background = "#f87171";
    status.textContent = "Backend offline";
  }
}

// ── Toast ────────────────────────────────────────────────────
function toast(msg, type = "success") {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.className = `show ${type}`;
  setTimeout(() => { t.className = ""; }, 3000);
}

// ── Helpers ──────────────────────────────────────────────────
function badge(status) {
  return `<span class="badge badge-${status}">${status.toUpperCase()}</span>`;
}

function scopePills(scopeStr) {
  if (!scopeStr) return "<span style='color:#4a5568'>none</span>";
  return scopeStr.split(",").map(s =>
    `<span class="scope-pill">${s.trim()}</span>`
  ).join("");
}

function methodBadge(m) {
  return `<span class="method method-${m}">${m}</span>`;
}

function emptyRow(cols, msg = "No data") {
  return `<tr><td colspan="${cols}" class="empty">${msg}</td></tr>`;
}

// ── DASHBOARD STATS ──────────────────────────────────────────
async function loadStats() {
  try {
    const r = await fetch(`${API}/stats`);
    const d = await r.json();
    document.getElementById("s-clients").textContent  = d.total_clients  ?? "—";
    document.getElementById("s-active").textContent   = d.active_tokens  ?? "—";
    document.getElementById("s-expired").textContent  = d.expired_tokens ?? "—";
    document.getElementById("s-revoked").textContent  = d.revoked_tokens ?? "—";
    document.getElementById("s-total").textContent    = d.total_requests ?? "—";
    document.getElementById("s-allowed").textContent  = d.allowed        ?? "—";
    document.getElementById("s-denied").textContent   = d.denied         ?? "—";
  } catch {
    toast("Could not load stats — is the backend running?", "error");
  }
}

// ── VALIDATE TOKEN ───────────────────────────────────────────
async function validateToken() {
  const token = document.getElementById("val-token").value.trim();
  const ep    = document.getElementById("val-endpoint").value.trim();
  const meth  = document.getElementById("val-method").value;
  const scope = document.getElementById("val-scope").value;

  if (!token) { toast("Please enter a token", "error"); return; }

  const btn = document.getElementById("val-btn");
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Validating…';

  try {
    const r = await fetch(`${API}/validate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, endpoint: ep, method: meth, required_scope: scope })
    });
    const d = await r.json();
    if (d.error) throw new Error(d.error);

    const box = document.getElementById("val-result");
    box.className = `result-box show ${d.verdict}`;
    document.getElementById("val-verdict").textContent = d.verdict === "allowed" ? "✅ ALLOWED" : "❌ DENIED";
    document.getElementById("val-reason").textContent  = d.reason;
    document.getElementById("val-hash").textContent    = "Token hash: " + (d.token_hash || "—");

    // Reload stats & requests in background
    loadStats();

  } catch (e) {
    toast("Validation error: " + e.message, "error");
  } finally {
    btn.disabled = false;
    btn.innerHTML = "🔐 Validate Token";
  }
}

// Quick test helper
function quickTest(tokenVal, scope, _hint) {
  document.getElementById("val-token").value = tokenVal;
  document.getElementById("val-scope").value = scope;
  document.getElementById("val-result").className = "result-box";
  // Auto-submit
  validateToken();
}

// ── TOKENS TABLE ─────────────────────────────────────────────
async function loadTokens() {
  const tbody = document.getElementById("tokensBody");
  tbody.innerHTML = `<tr><td colspan="6" class="empty"><div class="spinner"></div></td></tr>`;
  try {
    const r = await fetch(`${API}/tokens`);
    const data = await r.json();
    if (!data.length) { tbody.innerHTML = emptyRow(6, "No tokens found"); return; }

    tbody.innerHTML = data.map(t => `
      <tr>
        <td class="mono">#${t.token_id}</td>
        <td style="font-weight:500">${t.client_name}</td>
        <td>${badge(t.status)}</td>
        <td class="mono">${t.issued_at || "—"}</td>
        <td class="mono">${t.expires_at || "—"}</td>
        <td>${scopePills(t.scopes)}</td>
      </tr>
    `).join("");
  } catch {
    tbody.innerHTML = emptyRow(6, "⚠ Could not load — is the backend running?");
  }
}

// ── CLIENTS TABLE ────────────────────────────────────────────
async function loadClients() {
  const tbody = document.getElementById("clientsBody");
  tbody.innerHTML = `<tr><td colspan="5" class="empty"><div class="spinner"></div></td></tr>`;
  try {
    const r = await fetch(`${API}/clients`);
    const data = await r.json();
    if (!data.length) { tbody.innerHTML = emptyRow(5, "No clients found"); return; }

    tbody.innerHTML = data.map(c => `
      <tr>
        <td class="mono">#${c.client_id}</td>
        <td style="font-weight:600">${c.client_name}</td>
        <td style="color:#94a3b8;font-size:12px">${c.owner_email}</td>
        <td>${c.is_active
              ? '<span class="badge badge-on">● ACTIVE</span>'
              : '<span class="badge badge-off">● INACTIVE</span>'}</td>
        <td class="mono">${c.created_at || "—"}</td>
      </tr>
    `).join("");
  } catch {
    tbody.innerHTML = emptyRow(5, "⚠ Could not load — is the backend running?");
  }
}

// ── REQUESTS TABLE ───────────────────────────────────────────
async function loadRequests() {
  const tbody = document.getElementById("requestsBody");
  tbody.innerHTML = `<tr><td colspan="8" class="empty"><div class="spinner"></div></td></tr>`;
  try {
    const r = await fetch(`${API}/requests?limit=30`);
    const data = await r.json();
    if (!data.length) { tbody.innerHTML = emptyRow(8, "No requests logged"); return; }

    tbody.innerHTML = data.map(req => `
      <tr>
        <td class="mono">#${req.request_id}</td>
        <td style="font-weight:500">${req.client_name}</td>
        <td>${methodBadge(req.method)}</td>
        <td class="mono" style="font-size:11px">${req.endpoint}</td>
        <td><span class="scope-pill">${req.required_scope}</span></td>
        <td>${badge(req.status)}</td>
        <td style="font-size:11px;color:#94a3b8">${req.deny_reason || "—"}</td>
        <td class="mono" style="font-size:11px">${req.requested_at || "—"}</td>
      </tr>
    `).join("");
  } catch {
    tbody.innerHTML = emptyRow(8, "⚠ Could not load — is the backend running?");
  }
}

// ── AUDIT TABLE ──────────────────────────────────────────────
async function loadAudit() {
  const tbody = document.getElementById("auditBody");
  tbody.innerHTML = `<tr><td colspan="7" class="empty"><div class="spinner"></div></td></tr>`;
  try {
    const r = await fetch(`${API}/audit`);
    const data = await r.json();
    if (!data.length) { tbody.innerHTML = emptyRow(7, "No audit events yet"); return; }

    tbody.innerHTML = data.map(log => `
      <tr>
        <td class="mono">#${log.log_id}</td>
        <td><span style="font-size:11px;font-weight:700;color:#a78bfa;background:rgba(167,139,250,0.1);padding:3px 8px;border-radius:6px;">${log.event_type}</span></td>
        <td class="mono" style="font-size:11px">${log.table_name}</td>
        <td class="mono">${log.record_id}</td>
        <td style="font-size:11px;color:#94a3b8">${log.old_value || "—"}</td>
        <td style="font-size:11px;color:#22d3a0">${log.new_value || "—"}</td>
        <td class="mono" style="font-size:11px">${log.logged_at || "—"}</td>
      </tr>
    `).join("");
  } catch {
    tbody.innerHTML = emptyRow(7, "⚠ Could not load — is the backend running?");
  }
}

// ── ISSUE TOKEN TAB ──────────────────────────────────────────
async function loadIssueTab() {
  try {
    // Load clients
    const cr = await fetch(`${API}/clients`);
    const clients = await cr.json();
    const sel = document.getElementById("iss-client");
    sel.innerHTML = clients.map(c =>
      `<option value="${c.client_id}">${c.client_name} (ID:${c.client_id})</option>`
    ).join("");

    // Load scopes as checkboxes
    const sr = await fetch(`${API}/scopes`);
    const scopes = await sr.json();
    document.getElementById("scope-checkboxes").innerHTML = scopes.map(s => `
      <label style="display:inline-flex;align-items:center;gap:6px;background:rgba(99,130,255,0.05);
        border:1px solid rgba(99,130,255,0.15);border-radius:8px;padding:6px 12px;cursor:pointer;font-size:12px;">
        <input type="checkbox" value="${s.scope_name}" id="sc-${s.scope_id}"
          style="width:auto;accent-color:#6382ff;cursor:pointer;">
        <span class="scope-pill" style="margin:0">${s.scope_name}</span>
      </label>
    `).join("");
  } catch {
    toast("Could not load clients/scopes — is the backend running?", "error");
  }
}

async function issueToken() {
  const clientId = document.getElementById("iss-client").value;
  const days     = document.getElementById("iss-days").value;
  const checked  = [...document.querySelectorAll("#scope-checkboxes input:checked")].map(c => c.value);

  if (!clientId)         { toast("Please select a client", "error"); return; }
  if (!checked.length)   { toast("Select at least one scope", "error"); return; }

  const btn = document.getElementById("iss-btn");
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Issuing…';

  try {
    const r = await fetch(`${API}/tokens/issue`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ client_id: clientId, valid_days: days, scopes: checked.join(",") })
    });
    const d = await r.json();
    if (d.error) throw new Error(d.error);

    document.getElementById("iss-token-val").textContent = d.token;
    document.getElementById("iss-token-id").textContent  = "#" + d.token_id;
    document.getElementById("iss-result").style.display  = "block";
    toast("Token issued successfully!", "success");

  } catch (e) {
    toast("Error: " + e.message, "error");
  } finally {
    btn.disabled = false;
    btn.innerHTML = "🔑 Issue Token";
  }
}

// ── REVOKE TOKEN ─────────────────────────────────────────────
async function revokeToken() {
  const token = document.getElementById("rev-token").value.trim();
  if (!token) { toast("Please enter a token value", "error"); return; }

  if (!confirm(`Revoke token "${token}"? This cannot be undone.`)) return;

  const btn = document.getElementById("rev-btn");
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Revoking…';

  try {
    const r = await fetch(`${API}/tokens/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token })
    });
    const d = await r.json();

    const resultDiv = document.getElementById("rev-result");
    resultDiv.style.display = "block";

    if (d.success) {
      resultDiv.style.background = "var(--green-bg)";
      resultDiv.style.border     = "1px solid rgba(34,211,160,0.3)";
      resultDiv.style.color      = "var(--green)";
      resultDiv.textContent      = "✅ " + d.message;
      toast("Token revoked", "success");
      document.getElementById("rev-token").value = "";
    } else {
      resultDiv.style.background = "var(--red-bg)";
      resultDiv.style.border     = "1px solid rgba(248,113,113,0.3)";
      resultDiv.style.color      = "var(--red)";
      resultDiv.textContent      = "❌ " + (d.message || d.error);
    }
  } catch (e) {
    toast("Error: " + e.message, "error");
  } finally {
    btn.disabled = false;
    btn.innerHTML = "🚫 Revoke Token";
  }
}

// ── Enter key for token validation ───────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  checkServer();
  loadStats();

  document.getElementById("val-token").addEventListener("keydown", e => {
    if (e.key === "Enter") validateToken();
  });
  document.getElementById("rev-token").addEventListener("keydown", e => {
    if (e.key === "Enter") revokeToken();
  });
});
