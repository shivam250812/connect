"use strict";
// Values coming from external sources are untrusted. Always render them through esc().
const $ = (s, r = document) => r.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const state = { view: "connections", overview: null, schema: null, mode: "form", filters: {}, drawer: null };
let adminToken = null;
try { adminToken = localStorage.getItem("cfAdminToken"); } catch (_) { /* storage not available */ }

async function api(path, opts = {}) {
  opts.headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
  if (adminToken) opts.headers["X-Admin-Token"] = adminToken;
  const res = await fetch(path, opts);
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch (_) { data = text; }
  if (res.status === 401 && !path.startsWith("/api/auth/")) {
    showAuth();  // session ended: back to the sign-in page
    throw new Error("Please log in");
  }
  if (!res.ok) {
    const d = data && data.detail;
    throw new Error(d && d.errors ? d.errors.join("; ") : (typeof d === "string" ? d : res.statusText));
  }
  return data;
}

function toast(msg, bad = false) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast" + (bad ? " err" : "");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.add("hidden"), bad ? 8000 : 4000);
}

function ago(iso) {
  if (!iso) return "never";
  const s = Math.max(0, (Date.now() - new Date(iso)) / 1000);
  if (s < 60) return `${Math.round(s)}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}
function dur(s) {
  if (s == null) return "";
  if (s < 120) return `${s}s`;
  if (s < 3600) return `${Math.round(s / 60)}m`;
  const h = s / 3600;
  return Number.isInteger(Math.round(h * 10) / 10) ? `${Math.round(h)}h` : `${h.toFixed(1)}h`;
}
const every = (s) => (s % 86400 === 0 ? `${s / 86400}d` : s % 3600 === 0 ? `${s / 3600}h` : s % 60 === 0 ? `${s / 60}m` : `${s}s`);
const n = (v) => (v == null ? "" : Number(v).toLocaleString());
const shortTime = (v) => (v ? String(v).replace("T", " ").slice(0, 19) : "");

// ---------------------------------------------------------------- data presentation (every view)

const GOOD = /^(active|enabled|online|healthy|normal|ok|success|succeeded|resolved|closed|good|passed|allowed|accept(ed)?|true|1)$/i;
const BAD = /^(inactive|disabled|offline|failed|failure|error|blocked|denied|deny|suspended|locked|deprovisioned|bad|critical|open|unhealthy|0)$/i;
const SEV = /^(critical|high|medium|moderate|low|info|informational|unknown)$/i;

function fmtTime(v) {
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return esc(v);
  const local = d.toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  return `<span title="${esc(v)}">${esc(local)}</span> <span class="muted small">${esc(ago(v))}</span>`;
}

// One cell, formatted by column type. Values from sources are untrusted: everything goes through esc().
function cell(col, v) {
  if (v === null || v === undefined || v === "") return '<td class="muted">-</td>';
  const k = col.key;
  if (col.type === "datetime") return `<td class="nowrap">${fmtTime(v)}</td>`;
  if (col.type === "bool") return `<td>${v === true || v === 1 || v === "true" ? "Yes" : "No"}</td>`;
  if (col.type === "number") return `<td class="num">${esc(typeof v === "number" ? v.toLocaleString() : v)}</td>`;
  if (col.type === "ip" || k === "mac") return `<td class="mono">${esc(v)}</td>`;
  if (col.type === "url" || k === "url") {
    const ok = /^https?:\/\//.test(String(v));
    return `<td>${ok ? `<a href="${esc(v)}" target="_blank" rel="noopener noreferrer">${esc(String(v).replace(/^https?:\/\//, "").slice(0, 48))}</a>` : esc(v)}</td>`;
  }
  if (col.type === "json" || typeof v === "object") return `<td class="raw">${esc(JSON.stringify(v).slice(0, 160))}</td>`;
  const s = String(v);
  if (/(^|_)severity|^level$|^priority$|^risk/.test(k) && SEV.test(s)) return `<td><span class="pill sev-${esc(s.toLowerCase())}">${esc(s)}</span></td>`;
  if (/(^|_)(status|state|outcome|action|health)$/.test(k) && s.length < 30) {
    return `<td><span class="pill ${GOOD.test(s) ? "good" : BAD.test(s) ? "bad" : ""}">${esc(s)}</span></td>`;
  }
  if (k === "id" || /(^|_)id$/.test(k)) return `<td class="mono" title="${esc(s)}">${esc(s.length > 28 ? s.slice(0, 26) + "..." : s)}</td>`;
  if (s.length <= 48) return `<td>${esc(s)}</td>`;
  const plain = s.replace(/[#*_`>|]+/g, " ").replace(/\[([^\]]*)\]\([^)]*\)/g, "$1").replace(/\s+/g, " ").trim();
  return `<td class="long"><div class="clamp" title="${esc(plain.slice(0, 600))}">${esc(plain.slice(0, 400))}</div></td>`;
}

function emptyReason(lr, q) {
  if (q) return "No stored records match this search.";
  if (!lr) return "This endpoint has not run yet. Click Run now.";
  if (lr.status === "error") return `The last run failed, so nothing was stored: ${lr.error}`;
  if (!lr.fetched) return `The source answered (last run ${ago(lr.finished_at)}, ${lr.pages} page${lr.pages === 1 ? "" : "s"}) but returned 0 records. There is no data on that account yet.`;
  if (lr.rejected === lr.fetched) return `All ${lr.fetched} records from the last run were rejected. See the Quarantine tab for the reasons.`;
  return "No records stored yet.";
}

function dataTable(columns, rows, emptyText = "No records yet. Run the connector to fetch data.") {
  if (!rows.length) return `<div class="table-wrap"><div class="empty">${esc(emptyText)}</div></div>`;
  return `<div class="table-wrap"><table class="data">
    <tr>${columns.map((c) => `<th class="${c.type === "number" ? "num" : ""}">${esc(c.label)}</th>`).join("")}</tr>
    ${rows.map((r, i) => `<tr class="click" data-expand="${i}">${columns.map((c) => cell(c, r[c.key])).join("")}</tr>
      <tr class="detail hidden" data-detail="${i}"><td colspan="${columns.length}"><pre>${esc(JSON.stringify(r._raw || r, null, 2))}</pre></td></tr>`).join("")}
  </table></div>`;
}

// ---------------------------------------------------------------- data refresh

async function refresh() {
  try {
    state.overview = await api("/api/overview");
    $("#updated").textContent = `Updated ${new Date().toLocaleTimeString()}`;
    const le = state.overview.load_errors;
    $("#load-errors").innerHTML = Object.entries(le).map(([f, errs]) =>
      `<div class="notice bad"><b>${esc(f)}</b> was not loaded: ${errs.map(esc).join("; ")}</div>`).join("");
    if (state.view === "connections") renderConnections();
  } catch (e) {
    $("#updated").textContent = "Server not reachable";
  }
}

// ---------------------------------------------------------------- views

function setView(view) {
  state.view = view;
  history.replaceState(null, "", view === "connections" ? location.pathname : `#${view}`);
  document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("on", a.dataset.view === view));
  render();
}

async function render() {
  const v = state.view;
  if (v === "connections") return renderConnections();
  if (["users", "devices", "events", "records"].includes(v)) return renderRecords(v);
  if (v === "quarantine") return renderQuarantine();
  if (v === "alerts") return renderAlerts();
  if (v === "secrets") return renderSecrets();
  return renderAudit();
}

function renderConnections() {
  const o = state.overview;
  if (!o) { $("#view").innerHTML = '<div class="empty">Loading</div>'; return; }
  const t = o.totals;
  const groups = {};
  o.connectors.forEach((c) => { (groups[c.integration] = groups[c.integration] || []).push(c); });
  const row = (c, child) => {
    const lr = c.last_run || {};
    const status = c.running ? "running" : c.status;
    const err = lr.error || (c.reasons[0] || "");
    return `<tr class="click ${child ? "child" : ""}" data-open="${esc(c.id)}">
      <td><div>${esc(c.name)}${c.id.startsWith("lab-") ? '<span class="tag">lab</span>' : ""}</div><div class="muted mono">${esc(c.id)}</div></td>
      <td><span class="st ${esc(status)}">${esc(status)}</span></td>
      <td>${esc(c.entity)}s</td>
      <td>${esc(c.auth.replace(/_/g, " "))}</td>
      <td>every ${esc(every(c.every_seconds))}</td>
      <td>${esc(ago(lr.finished_at))}</td>
      <td class="num">${n(lr.fetched)}</td>
      <td class="num">${n(c.records_stored)}</td>
      <td class="num ${lr.rejected ? "warn-text" : ""}">${n(lr.rejected)}</td>
      <td>${c.paused ? "paused" : esc(dur(c.next_run_in_s))}</td>
      <td class="wrap ${lr.error ? "err-text" : "warn-text"}">${esc(err.length > 90 ? err.slice(0, 90) + "..." : err)}</td>
    </tr>`;
  };
  const rows = Object.values(groups).map((list) => {
    if (!list[0].endpoint) return list.map((c) => row(c, false)).join("");
    const worst = list.find((c) => c.status === "failing") || list.find((c) => c.status === "degraded") || list[0];
    return `<tr class="group"><td colspan="11"><b>${esc(list[0].integration_name)}</b>
        <span class="muted">${list.length} endpoint${list.length > 1 ? "s" : ""}, shared login, <span class="mono">${esc(list[0].integration)}</span></span>
        <span class="st ${esc(worst.status)}" style="margin-left:8px">${esc(worst.status)}</span></td></tr>` +
      list.map((c) => row(c, true)).join("");
  }).join("");
  $("#view").innerHTML = `
    <div class="page-head"><h1>Connections</h1>
      <div class="actions"><button class="btn" id="btn-reload" title="Re-read connector files changed on disk">Reload configs</button>
      <button class="btn primary" id="btn-add">Add connector</button></div></div>
    <div class="totals">
      <div><span>${n(t.connectors)}</span>Connections</div>
      <div><span>${n(t.healthy)}</span>Healthy</div>
      <div><span class="${t.attention ? "err-text" : ""}">${n(t.attention)}</span>Need attention</div>
      <div><span>${n(o.tables.users)}</span>Users</div>
      <div><span>${n(o.tables.devices)}</span>Devices</div>
      <div><span>${n(o.tables.events)}</span>Events</div>
      ${o.tables.records ? `<div><span>${n(o.tables.records)}</span>Other records</div>` : ""}
      <div><span>${n(t.quarantined)}</span>Quarantined</div>
    </div>
    <div class="table-wrap"><table>
      <tr><th>Name</th><th>Status</th><th>Writes to</th><th>Auth</th><th>Schedule</th><th>Last run</th>
        <th style="text-align:right">Pulled</th><th style="text-align:right">Stored</th><th style="text-align:right">Rejected</th><th>Next run</th><th>Last error</th></tr>
      ${rows || '<tr><td colspan="11" class="empty">No connectors yet. Use Add connector to create one.</td></tr>'}
    </table></div>`;
}

const COLS = {
  users: ["id", "name", "email", "status", "title", "department", "mfa_enabled", "last_login", "source", "fetched_at"],
  devices: ["id", "hostname", "ip", "os", "owner", "status", "last_seen", "source", "fetched_at"],
  events: ["id", "type", "severity", "timestamp", "description", "user", "src_ip", "score", "source", "fetched_at"],
  records: ["id", "title", "timestamp", "data", "source", "fetched_at"],
};
const TITLES = { users: "Users", devices: "Devices", events: "Events", records: "Other records" };
const ENTITY_OF = { users: "user", devices: "device", events: "event", records: "record" };
function columnsFor(table, rows) {
  const types = (state.schema && state.schema[ENTITY_OF[table]] && state.schema[ENTITY_OF[table]].fields) || {};
  const kind = { datetime: "datetime", int: "number", float: "number", bool: "bool", ip: "ip" };
  return COLS[table].filter((k) => ["id", "source", "fetched_at"].includes(k) || rows.some((r) => r[k] !== null && r[k] !== undefined && r[k] !== ""))
    .map((k) => ({ key: k, label: k === "id" ? "ID" : k === "fetched_at" ? "Fetched" : k === "mfa_enabled" ? "MFA" : k === "src_ip" ? "Source IP" : k === "ip" || k === "os" ? k.toUpperCase() : k.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase()),
      type: k === "fetched_at" ? "datetime" : k === "data" ? "str" : kind[types[k]] || "str" }));
}

async function renderRecords(table) {
  const f = state.filters[table] || {};
  const sources = Object.keys((state.overview && state.overview.by_source[table]) || {});
  const qs = new URLSearchParams({ limit: 200, ...(f.source ? { source: f.source } : {}), ...(f.q ? { q: f.q } : {}) });
  state.schema = state.schema || await api("/api/schema");
  const rows = await api(`/api/records/${table}?${qs}`);
  if (table === "records") rows.forEach((r) => {
    try { r.data = Object.entries(JSON.parse(r.data || "{}")).map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : v}`).join(", "); } catch (_) { /* leave as is */ }
  });
  const cols = columnsFor(table, rows);
  const total = state.overview ? state.overview.tables[table] : rows.length;
  $("#view").innerHTML = `
    <div class="page-head"><h1>${TITLES[table]} <span class="muted small">${n(total)} total</span></h1>
      <a href="/api/records/${table}.jsonl">Export JSONL</a></div>
    <div class="toolbar">
      <select id="f-source"><option value="">All sources</option>${sources.map((s) => `<option ${s === f.source ? "selected" : ""}>${esc(s)}</option>`).join("")}</select>
      <input type="text" id="f-q" placeholder="Search" value="${esc(f.q || "")}">
      <span class="muted small">Showing up to 200 rows</span>
    </div>
    ${dataTable(cols, rows, "No rows")}`;
  $("#f-source").onchange = (e) => { state.filters[table] = { ...f, source: e.target.value }; renderRecords(table); };
  $("#f-q").onchange = (e) => { state.filters[table] = { ...f, q: e.target.value }; renderRecords(table); };
}

async function renderQuarantine() {
  const rows = await api("/api/quarantine?limit=150");
  $("#view").innerHTML = `
    <div class="page-head"><h1>Quarantine</h1><span class="muted">Records that could not be mapped. The rest of the run continues.</span></div>
    <div class="table-wrap"><table><tr><th>When</th><th>Connector</th><th>Reason</th><th>Record</th></tr>
    ${rows.map((r) => `<tr><td>${esc(ago(r.at))}</td><td class="mono">${esc(r.connector)}</td><td class="wrap">${esc(r.reason)}</td><td class="raw">${esc(r.record.slice(0, 400))}</td></tr>`).join("")
      || '<tr><td colspan="4" class="empty">Nothing quarantined</td></tr>'}</table></div>`;
}

const RULES = [
  ["failing", "Connection failing", "3 failed runs in a row. Followed by a message when it recovers."],
  ["recovered", "Connection recovered", "The first good run after a failing notice."],
  ["auth_failed", "Credential rejected", "The source answered 401/403: a key was revoked, expired or lacks permission."],
  ["data_quality", "Bad data spike", "More than 20% of a run's records were rejected; the source may have changed format."],
  ["critical_data", "New critical findings", "New events at or above the severity below. A connection's first run is not reported."],
  ["rotation_due", "Key due for rotation", "A secret is older than 90 days. Checked once a day."],
];

async function renderAlerts() {
  const [cfg, rows] = await Promise.all([api("/api/notifications"), api("/api/alerts?limit=100")]);
  const s = cfg.settings;
  const chk = (id, on, label) => `<label class="check"><input type="checkbox" id="${id}" ${on ? "checked" : ""}> ${label}</label>`;
  const status = (ok, name) => ok ? `<span class="pill good">secret ${esc(name)} is set</span>`
    : `<span class="pill bad">secret ${esc(name)} not set</span> <a href="#secrets" data-goto="secrets">set it on the Secrets tab</a>`;
  $("#view").innerHTML = `
    <div class="page-head"><h1>Notifications</h1>
      <div class="actions"><button class="btn" id="n-test">Send test message</button><button class="btn primary" id="n-save">Save</button></div></div>
    <div class="cards">
      <fieldset><legend>Slack</legend>
        ${chk("n-slack", s.slack.enabled, "Send to Slack")}
        <div class="form-grid" style="margin-top:8px">${fi('id="n-slack-secret"', "Webhook URL is stored as secret", s.slack.webhook_secret)}</div>
        <div class="small" style="margin-top:6px">${status(cfg.secrets.slack_webhook, s.slack.webhook_secret)}</div>
        <div class="muted small" style="margin-top:6px">Slack: api.slack.com/apps, Create app, Incoming Webhooks, Add to channel, copy the URL.
          Teams and Mattermost incoming webhooks work too.${cfg.env_override.slack ? " CF_ALERT_WEBHOOK is set and takes priority." : ""}</div>
      </fieldset>
      <fieldset><legend>Email</legend>
        ${chk("n-email", s.email.enabled, "Send email")}${cfg.env_override.email ? ' <span class="muted small">(set by CF_SMTP_HOST)</span>' : ""}
        <div class="form-grid" style="margin-top:8px">
          ${fi('id="n-host"', "SMTP server", s.email.smtp_host, 'placeholder="smtp.gmail.com"')}
          ${fi('id="n-port"', "Port", s.email.smtp_port, 'placeholder="587"')}
          ${se('id="n-sec"', "Security", [["starttls", "STARTTLS (587)"], ["ssl", "SSL/TLS (465)"], ["none", "None (local relay only)"]], s.email.security)}
          ${fi('id="n-user"', "Username", s.email.username, 'placeholder="alerts@yourcompany.com"')}
          ${fi('id="n-pass"', "Password is stored as secret", s.email.password_secret)}
          ${fi('id="n-from"', "From", s.email.from, 'placeholder="ConnectForge <alerts@yourcompany.com>"')}
          ${fi('id="n-to"', "Also send to (comma separated, optional)", (s.email.to || []).join(", "), 'placeholder="soc@yourcompany.com"')}
        </div>
        <div style="margin-top:8px">${chk("n-to-reg", s.email.to_registered !== false,
          `Send to every registered account (${cfg.registered.length}): <span class="mono">${esc(cfg.registered.join(", ") || "nobody yet")}</span>`)}</div>
        <div class="small" style="margin-top:6px">${s.email.username ? status(cfg.secrets.smtp_password, s.email.password_secret) : ""}</div>
        <div class="muted small" style="margin-top:6px">Gmail: turn on 2-step verification, create an app password, use smtp.gmail.com port 587.</div>
      </fieldset>
    </div>
    <fieldset style="margin-top:12px"><legend>When to notify</legend>
      <div class="rules">${RULES.map(([k, label, help]) => `<div>${chk(`n-r-${k}`, s.rules[k], `<b>${esc(label)}</b>`)}<div class="muted small">${esc(help)}</div></div>`).join("")}</div>
      <div class="form-grid" style="margin-top:10px">
        ${se('id="n-sev"', "New findings at or above", [["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"]], s.min_severity)}
        ${fi('id="n-cool"', "Repeat the same notice at most every (minutes)", s.cooldown_minutes)}
      </div>
    </fieldset>
    <div id="n-out"></div>
    <h2 style="margin:18px 0 8px">Sent</h2>
    <div class="table-wrap"><table><tr><th>When</th><th>About</th><th>Type</th><th>Message</th><th>Delivery</th></tr>
    ${rows.map((r) => `<tr><td class="nowrap">${esc(ago(r.at))}</td><td class="mono">${esc(r.connector)}</td><td>${esc(cfg.kinds[r.kind] || r.kind)}</td>
      <td class="wrap">${esc(r.message)}</td><td class="${/failed|HTTP [45]/.test(r.delivered) ? "err-text" : /logged only|held back|switched off/.test(r.delivered) ? "muted" : ""}">${esc(r.delivered)}</td></tr>`).join("")
      || '<tr><td colspan="5" class="empty">Nothing sent yet</td></tr>'}</table></div>`;
}

function collectNotifications() {
  const v = (id) => $(id).value.trim();
  return {
    slack: { enabled: $("#n-slack").checked, webhook_secret: v("#n-slack-secret") || "slack_webhook" },
    email: { enabled: $("#n-email").checked, smtp_host: v("#n-host"), smtp_port: Number(v("#n-port")) || 587, security: v("#n-sec"),
      username: v("#n-user"), password_secret: v("#n-pass") || "smtp_password", from: v("#n-from"), to: v("#n-to"),
      to_registered: $("#n-to-reg").checked },
    rules: Object.fromEntries(RULES.map(([k]) => [k, $(`#n-r-${k}`).checked])),
    min_severity: v("#n-sev"), cooldown_minutes: Number(v("#n-cool")) || 0,
  };
}

async function renderSecrets() {
  const [rows, be] = await Promise.all([api("/api/secrets"), api("/api/secrets/backend")]);
  const editable = be.writable;
  $("#view").innerHTML = `
    <div class="page-head"><h1>Secrets</h1>
      <span class="muted">Backend: ${esc(be.backend)}. ${editable ? "Values are stored encrypted and can be replaced but never viewed."
        : "Values are managed and rotated in the secret manager, not here."}</span></div>
    <div class="table-wrap"><table><tr><th>Name</th><th>Status</th><th>Used by</th>${editable ? "<th>Age</th>" : ""}<th>Last used</th><th>${editable ? "Set value" : ""}</th></tr>
    ${rows.map((s) => `<tr>
      <td class="mono">${esc(s.name)}</td>
      <td>${s.set ? "Set" : `<span class="warn-text">${esc(s.problem || "Not set")}</span>`}</td>
      <td class="mono">${esc(s.used_by.join(", "))}</td>
      ${editable ? `<td>${s.age_days == null ? "" : esc(s.age_days + "d")}${s.rotation_due ? ' <span class="warn-text">rotate</span>' : ""}</td>` : ""}
      <td>${s.last_used_at ? esc(ago(s.last_used_at)) + (s.last_used_by ? ` by <span class="mono">${esc(s.last_used_by)}</span>` : "") : ""}</td>
      ${editable ? `<td><div class="actions"><input type="password" data-secret-input="${esc(s.name)}" autocomplete="new-password" data-lpignore="true" data-1p-ignore>
        <button class="btn" data-secret-save="${esc(s.name)}">Save</button></div></td>`
        : `<td><button class="btn" data-secret-refresh="${esc(s.name)}" title="Use the value just rotated in the manager">Reload</button></td>`}</tr>`).join("")}</table></div>`;
}

async function renderAudit() {
  const rows = await api("/api/audit?limit=150");
  $("#view").innerHTML = `
    <div class="page-head"><h1>Audit log</h1></div>
    <div class="table-wrap"><table><tr><th>When</th><th>Actor</th><th>Action</th><th>Detail</th></tr>
    ${rows.map((r) => `<tr><td>${esc(ago(r.at))}</td><td class="mono">${esc(r.actor)}</td>
      <td class="${/blocked|denied|alert/.test(r.action) ? "err-text" : ""}">${esc(r.action)}</td><td class="mono wrap">${esc(r.detail)}</td></tr>`).join("")}</table></div>`;
}

// ---------------------------------------------------------------- connection details

async function openDetail(id, tab = "data") {
  state.drawer = { id, tab, q: state.drawer && state.drawer.id === id ? state.drawer.q : "" };
  const d = await api(`/api/connectors/${encodeURIComponent(id)}`);
  const h = d.health;
  const lr = h.last_run || {};
  $("#drawer-title").textContent = h.name;
  $("#drawer-sub").innerHTML = (h.endpoint ? `${esc(h.integration_name)} / ` : "") +
    `<span class="mono">${esc(h.id)}</span>, writes to ${esc(h.entity)}s, source <span class="mono">${esc(h.source)}</span>`;
  $("#drawer-actions").innerHTML = `
    <button class="btn" data-run="${esc(id)}">Run now</button>
    <button class="btn" data-test="${esc(id)}">Test connection</button>
    <button class="btn" data-toggle="${esc(id)}" data-paused="${h.paused}">${h.paused ? "Resume" : "Pause"}</button>
    <button class="btn" data-edit="${esc(id)}">Edit YAML</button>
    <button class="btn danger" data-remove="${esc(id)}">Remove</button>`;
  const tabs = [["data", "Data"], ["overview", "Overview"], ["runs", "Runs"], ["bad", "Quarantine"], ["config", "Config"], ["preview", "Preview"]];
  $("#drawer-tabs").innerHTML = tabs.map(([k, l]) => `<a data-dtab="${k}" class="${k === tab ? "on" : ""}">${l}</a>`).join("");

  let html = "";
  if (tab === "data") {
    const q = state.drawer.q || "";
    const dv = await api(`/api/connectors/${encodeURIComponent(id)}/data?limit=200${q ? `&q=${encodeURIComponent(q)}` : ""}`);
    html = `<div class="toolbar"><input type="text" id="data-q" placeholder="Search this endpoint" value="${esc(q)}">
        <span class="muted small">${n(dv.total)} stored in ${esc(dv.table)}${dv.rows.length < dv.total ? `, showing ${n(dv.rows.length)}` : ""}. Click a row for the full record.</span></div>
      ${dataTable(dv.columns, dv.rows, emptyReason(dv.last_run, q))}`;
  } else if (tab === "overview") {
    html = `<dl class="facts">
      <dt>Status</dt><dd><span class="st ${esc(h.status)}">${esc(h.status)}</span>${h.reasons.length ? ` <span class="muted">(${esc(h.reasons.join("; "))})</span>` : ""}</dd>
      <dt>Auth</dt><dd>${esc(h.auth.replace(/_/g, " "))}</dd>
      <dt>Pagination</dt><dd>${esc(h.kind === "file" ? "file tail" : h.pagination.replace(/_/g, " "))}</dd>
      <dt>Allowed hosts</dt><dd class="mono">${esc(h.hosts.join(", ") || "local file")}</dd>
      <dt>Secrets</dt><dd class="mono">${esc(h.secrets.join(", ") || "none")}</dd>
      <dt>Schedule</dt><dd>every ${esc(every(h.every_seconds))}${h.paused ? ", paused" : `, next in ${esc(dur(h.next_run_in_s))}`}</dd>
      <dt>Last run</dt><dd>${esc(ago(lr.finished_at))}${lr.status ? `, ${esc(lr.status)}` : ""}${lr.duration_ms != null ? `, ${n(lr.duration_ms)} ms` : ""}</dd>
      <dt>Last success</dt><dd>${esc(ago(h.last_success_at))}</dd>
      <dt>Last run counts</dt><dd>${lr.finished_at ? `${n(lr.pages)} pages, ${n(lr.fetched)} pulled, ${n(lr.new)} new, ${n(lr.updated)} updated, ${n(lr.unchanged)} unchanged, ${n(lr.rejected)} rejected, ${n(lr.retries)} retries` : ""}</dd>
      <dt>Stored records</dt><dd>${n(h.records_stored)}</dd>
      <dt>Checkpoint</dt><dd class="mono">${esc(h.cursor || "")}</dd>
      <dt>Failures in a row</dt><dd>${n(h.consecutive_failures)}</dd>
    </dl>
    ${lr.error ? `<div class="notice bad">${esc(lr.error)}</div>` : ""}
    ${h.notes.length ? `<div class="notes">${h.notes.map(esc).join("<br>")}</div>` : ""}`;
  } else if (tab === "runs") {
    html = `<div class="table-wrap"><table><tr><th>#</th><th>Started</th><th>Trigger</th><th>Status</th><th>Pages</th><th>Pulled</th><th>New</th><th>Updated</th><th>Rejected</th><th>Retries</th><th>Error</th></tr>
      ${d.runs.map((r) => `<tr><td>${esc(r.id)}</td><td>${esc(ago(r.started_at))}</td><td>${esc(r.trigger)}</td><td>${esc(r.status)}</td>
        <td class="num">${n(r.pages)}</td><td class="num">${n(r.fetched)}</td><td class="num">${n(r.new)}</td><td class="num">${n(r.updated)}</td>
        <td class="num">${n(r.rejected)}</td><td class="num">${n(r.retries)}</td><td class="wrap err-text">${esc(r.error || "")}</td></tr>`).join("")}</table></div>`;
  } else if (tab === "bad") {
    html = `<div class="table-wrap"><table><tr><th>When</th><th>Reason</th><th>Record</th></tr>
      ${d.quarantined.map((r) => `<tr><td>${esc(ago(r.at))}</td><td class="wrap">${esc(r.reason)}</td><td class="raw">${esc(r.record)}</td></tr>`).join("")
        || '<tr><td colspan="3" class="empty">Nothing quarantined</td></tr>'}</table></div>`;
  } else if (tab === "config") {
    html = `<pre>${esc(JSON.stringify(d.spec, null, 2))}</pre>`;
  } else {
    html = '<div id="pv" class="muted">Fetching one page</div>';
  }
  $("#drawer-body").innerHTML = html;
  $("#drawer").classList.toggle("wide", tab === "data");
  $("#drawer").classList.remove("hidden");
  if (tab === "data") $("#data-q").onchange = (e) => { state.drawer.q = e.target.value; openDetail(id, "data"); };
  if (tab === "preview") {
    try { $("#pv").outerHTML = renderPreview(await api("/api/preview", { method: "POST", body: JSON.stringify({ yaml: id }) })); }
    catch (e) { $("#pv").outerHTML = `<div class="notice bad">${esc(e.message)}</div>`; }
  }
}

function renderPreview(p) {
  const notes = p.notes.length ? `<div class="notes">${p.notes.map(esc).join("<br>")}</div>` : "";
  const learned = p.learned_mapping ? `<div class="label">Mapping found automatically. Paste it into the config to pin or adjust it.</div>
    <pre>${esc(p.learned_mapping)}</pre>` : "";
  const items = p.samples.map((s) => `<div class="pair">
      <div><div class="label">Source record</div><pre>${esc(JSON.stringify(s.raw, null, 2).slice(0, 3000))}</pre></div>
      <div><div class="label">${s.error ? "Rejected" : `Stored as ${esc(p.entity)}`}</div>${s.error ? `<div class="notice bad">${esc(s.error)}</div>` : `<pre>${esc(JSON.stringify(s.record, null, 2))}</pre>`}</div>
    </div>`).join("");
  return notes + learned + (items || '<div class="muted">The source returned no records.</div>');
}

// ---------------------------------------------------------------- add / edit connector

function field(id, label, value = "", attrs = "") {
  return `<label>${label}<input type="text" id="${id}" value="${esc(value)}" ${attrs}></label>`;
}
function select(id, label, options, value) {
  return `<label>${label}<select id="${id}">${options.map((o) => `<option ${o === value ? "selected" : ""}>${o}</option>`).join("")}</select></label>`;
}

// The form builds an integration: connection settings once, then any number of endpoints.
// Inputs carry data-g (connection setting), or data-ep + data-k (endpoint setting), so the form can be read
// back into state.form before every re-render and nothing typed is lost.
const PAGING = ["none", "link_header", "next_url", "page_number", "offset", "next_token"];
const newEndpoint = (i = 0) => ({ name: i ? `endpoint${i + 1}` : "users", title: i ? "" : "Users", entity: i ? "event" : "user",
  method: "GET", path: i ? "" : "/api/v1/users", params: "", records: "", every: "", paging: "shared",
  psizeParam: "", psize: "", pparam: "", ppath: "", mapMode: "auto", map: [] });
const newForm = () => ({
  id: "my-integration", name: "My integration", base: "https://api.example.com", headers: "Accept: application/json", every: "1h",
  auth: "api_key", secret: "my_api_key", header: "X-API-Key", user: "", tokenUrl: "", clientId: "", clientAuth: "basic",
  paging: "link_header", psizeParam: "limit", psize: "100", pparam: "", ppath: "",
  endpoints: [newEndpoint(0)],
});

function fi(attrs, label, value, extra = "") {
  return `<label>${label}<input type="text" ${attrs} value="${esc(value)}" ${extra}></label>`;
}
function se(attrs, label, options, value) {
  return `<label>${label}<select ${attrs}>${options.map((o) => {
    const [val, text] = Array.isArray(o) ? o : [o, o];
    return `<option value="${esc(val)}" ${val === value ? "selected" : ""}>${esc(text)}</option>`;
  }).join("")}</select></label>`;
}
function pagingFields(o, attr) {
  if (o.paging === "none" || o.paging === "shared") return "";
  const param = { link_header: "", next_url: "", page_number: "Page parameter", offset: "Offset parameter", next_token: "Token parameter" }[o.paging];
  const path = { next_url: "Next-link path (e.g. _links.next)", offset: "Total path (optional)", next_token: "Token path in response" }[o.paging];
  return fi(`${attr("psizeParam")}`, "Page size parameter", o.psizeParam, 'placeholder="limit, per_page, maxResults"') +
    fi(`${attr("psize")}`, "Page size", o.psize, 'placeholder="100"') +
    (param ? fi(`${attr("pparam")}`, param, o.pparam) : "") + (path ? fi(`${attr("ppath")}`, path, o.ppath) : "");
}

function renderForm() {
  const f = state.form = state.form || newForm();
  const g = (k) => `data-g="${k}"`;
  const authFields = {
    none: "",
    api_key: fi(g("header"), "Header name", f.header, 'placeholder="X-API-Key"') + fi(g("secret"), "Secret name", f.secret),
    bearer: fi(g("secret"), "Secret name", f.secret) + fi(g("header"), "Scheme (optional)", f.header === "X-API-Key" ? "" : f.header, 'placeholder="Bearer, SSWS, ApiKey"'),
    basic: fi(g("user"), "Username or email", f.user) + fi(g("secret"), "Secret name (password or token)", f.secret),
    oauth2_client_credentials: fi(g("tokenUrl"), "Token URL", f.tokenUrl, 'placeholder="https://auth.example.com/oauth/token"') +
      fi(g("clientId"), "Client ID", f.clientId) + fi(g("secret"), "Secret name (client secret)", f.secret) +
      se(g("clientAuth"), "Send credentials in", [["basic", "Authorization header"], ["body", "Request body"]], f.clientAuth),
  }[f.auth];
  const endpoints = f.endpoints.map((e, i) => {
    const a = (k) => `data-ep="${i}" data-k="${k}"`;
    const targets = e.entity === "record" ? null : Object.keys(state.schema[e.entity].fields);
    const required = e.entity === "record" ? [] : state.schema[e.entity].required;
    const rows = e.map.map((r, j) => `<div class="maprow">
        ${targets ? `<select data-ep="${i}" data-m="${j}" data-mk="target">${targets.map((t) => `<option ${t === r.target ? "selected" : ""}>${t}</option>`).join("")}</select>`
          : `<input type="text" data-ep="${i}" data-m="${j}" data-mk="target" value="${esc(r.target)}" placeholder="column name">`}
        <input type="text" data-ep="${i}" data-m="${j}" data-mk="from" value="${esc(r.from)}" placeholder="path in the record (a.b, a[0].c), or =fixed value">
        <button class="btn" data-map-del="${i}:${j}">Remove</button></div>`).join("");
    return `<fieldset class="endpoint"><legend>Endpoint ${i + 1}${e.title ? `: ${esc(e.title)}` : ""}</legend>
      <div class="form-grid">
        ${fi(a("name"), "Name (used in the id)", e.name, 'placeholder="lowercase, e.g. alerts"')}${fi(a("title"), "Title", e.title, 'placeholder="shown in the dashboard"')}
        ${se(`${a("entity")} data-rerender`, "Writes to", [["user", "Users"], ["device", "Devices"], ["event", "Events / alerts"], ["record", "Other records (keep every field)"]], e.entity)}
        ${se(a("method"), "Method", ["GET", "POST"], e.method)}
        ${fi(a("path"), "Path", e.path, 'placeholder="/api/v1/alerts"')}
        ${fi(a("params"), "Query parameters", e.params, 'placeholder="status=open&limit=100"')}
        ${fi(a("records"), "Records path (optional)", e.records, 'placeholder="found automatically, e.g. data.items"')}
        ${fi(a("every"), "Schedule (optional)", e.every, `placeholder="default: ${esc(f.every)}"`)}
        ${se(`${a("paging")} data-rerender`, "Pagination", [["shared", "Same as default"], ...PAGING.map((p) => [p, p.replace(/_/g, " ")])], e.paging)}
        ${pagingFields(e, a)}
      </div>
      <div class="form-grid" style="margin-top:8px">
        ${se(`${a("mapMode")} data-rerender`, "Field mapping", [["auto", "Automatic (learned from real data)"], ["manual", "Manual"]], e.mapMode)}
      </div>
      ${e.mapMode === "manual" ? `<div style="margin-top:8px">${required.length ? `<div class="muted small">Required: ${required.join(", ")}</div>` : ""}${rows}
        <button class="btn" data-map-add="${i}">Add field</button></div>` : ""}
      <div class="actions" style="margin-top:8px">${f.endpoints.length > 1 ? `<button class="btn danger" data-ep-del="${i}">Remove endpoint</button>` : ""}</div>
    </fieldset>`;
  }).join("");
  $("#mode-form").innerHTML = `<div class="form-stack">
    <fieldset><legend>Connection</legend><div class="form-grid">
      ${fi(g("id"), "ID", f.id, 'placeholder="lowercase-with-dashes"')}${fi(g("name"), "Name", f.name)}
      ${fi(g("base"), "Base URL", f.base)}${fi(g("headers"), "Shared headers (optional)", f.headers, 'placeholder="Accept: application/json; X-Org: 1"')}
      ${fi(g("every"), "Default schedule", f.every, 'placeholder="30s, 15m, 2h, 1d"')}</div></fieldset>
    <fieldset><legend>Authentication</legend><div class="form-grid">
      ${se(`${g("auth")} data-rerender`, "Type", [["none", "None"], ["api_key", "API key"], ["bearer", "Bearer token"], ["basic", "Basic (user + password/token)"],
        ["oauth2_client_credentials", "OAuth2 client credentials"]], f.auth)}${authFields}</div>
      ${f.auth === "none" ? "" : '<div class="muted small" style="margin-top:6px">Only the secret\'s name goes in the file. Save its value on the Secrets tab.</div>'}</fieldset>
    <fieldset><legend>Default pagination</legend><div class="form-grid">
      ${se(`${g("paging")} data-rerender`, "Style", PAGING.map((p) => [p, p.replace(/_/g, " ")]), f.paging)}${pagingFields(f, g)}</div></fieldset>
    <div class="section-head"><h2>Endpoints</h2><button class="btn" id="ep-add">Add endpoint</button></div>
    ${endpoints}
    <div class="actions"><button class="btn" id="btn-gen">Generate YAML</button></div></div>`;
}

function collectForm() {
  const f = state.form;
  if (!f || !$("#mode-form [data-g]")) return f;
  document.querySelectorAll("#mode-form [data-g]").forEach((el) => { f[el.dataset.g] = el.value.trim(); });
  document.querySelectorAll("#mode-form [data-ep][data-k]").forEach((el) => { f.endpoints[el.dataset.ep][el.dataset.k] = el.value.trim(); });
  document.querySelectorAll("#mode-form [data-ep][data-m]").forEach((el) => { f.endpoints[el.dataset.ep].map[el.dataset.m][el.dataset.mk] = el.value.trim(); });
  return f;
}

function yamlScalar(v) {
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return /^[A-Za-z0-9_./-]+$/.test(v) && !/^(true|false|null|yes|no|on|off|y|n|~)$/i.test(v) && !/^[\d.]/.test(v) ? v : JSON.stringify(v);
}
const present = (v) => v !== undefined && v !== "" && !(v && typeof v === "object" && !Array.isArray(v) && !Object.keys(v).length);
function toYaml(obj, indent = "") {
  return Object.entries(obj).filter(([, v]) => present(v)).map(([k, v]) => {
    if (Array.isArray(v) && v.length && typeof v[0] === "object") {
      return `${indent}${k}:\n` + v.map((item) => {
        const body = toYaml(item, indent + "    ");
        return `${indent}  - ` + body.slice(indent.length + 4);
      }).join("\n");
    }
    if (Array.isArray(v)) return `${indent}${k}: [${v.map(yamlScalar).join(", ")}]`;
    if (v && typeof v === "object") return `${indent}${k}:\n${toYaml(v, indent + "  ")}`;
    return `${indent}${k}: ${yamlScalar(v)}`;
  }).join("\n");
}
function pagingSpec(o) {
  if (o.paging === "shared") return undefined;
  const pg = { type: o.paging };
  if (o.paging === "none") return pg;
  if (o.psizeParam) { pg.page_size_param = o.psizeParam; pg.page_size = Number(o.psize) || 100; }
  if (o.paging === "page_number" && o.pparam) pg.page_param = o.pparam;
  if (o.paging === "offset") { if (o.pparam) pg.offset_param = o.pparam; if (o.ppath) pg.total_path = o.ppath; }
  if (o.paging === "next_token") { pg.token_path = o.ppath || o.pparam; pg.token_param = o.pparam || o.ppath; }
  if (o.paging === "next_url" && o.ppath) pg.token_path = o.ppath;
  return pg;
}
const kv = (text, sep, eq) => Object.fromEntries(String(text || "").split(sep).map((x) => x.trim()).filter(Boolean)
  .map((x) => { const at = x.indexOf(eq); return at < 0 ? [x, ""] : [x.slice(0, at).trim(), x.slice(at + 1).trim()]; }));

function generateYaml() {
  const f = collectForm();
  const auth = { type: f.auth };
  if (f.auth === "api_key") Object.assign(auth, { header: f.header || "X-API-Key", secret: f.secret });
  if (f.auth === "bearer") Object.assign(auth, { secret: f.secret, ...(f.header && f.header !== "X-API-Key" ? { scheme: f.header } : {}) });
  if (f.auth === "basic") Object.assign(auth, { username: f.user, secret: f.secret });
  if (f.auth === "oauth2_client_credentials") Object.assign(auth, { token_url: f.tokenUrl, client_id: f.clientId, secret: f.secret, client_auth: f.clientAuth });
  const endpoints = f.endpoints.map((e) => {
    const mapping = {};
    if (e.mapMode === "manual") e.map.filter((r) => r.target && r.from).forEach((r) => { mapping[r.target] = r.from.startsWith("=") ? { const: r.from.slice(1) } : r.from; });
    return {
      name: e.name, title: e.title, entity: e.entity, path: e.path, ...(e.method === "POST" ? { method: "POST" } : {}),
      params: kv(e.params, "&", "="), records: e.records, ...(e.every ? { schedule: { every: e.every } } : {}),
      pagination: pagingSpec(e), mapping,
    };
  });
  const spec = {
    id: f.id, name: f.name, auth, request: { base_url: f.base, headers: kv(f.headers, /[;\n]/, ":") },
    schedule: { every: f.every || "1h" }, pagination: pagingSpec(f), endpoints,
  };
  $("#yaml").value = "# Made with the Add connector form. Leaving out `mapping` means fields are matched automatically.\n" + toYaml(spec) + "\n";
  setMode("yaml");
}

function setMode(mode) {
  state.mode = mode;
  document.querySelectorAll("[data-mode]").forEach((b) => b.classList.toggle("on", b.dataset.mode === mode));
  $("#mode-form").classList.toggle("hidden", mode !== "form");
  $("#mode-yaml").classList.toggle("hidden", mode !== "yaml");
}

async function openAdd(title = "Add connector") {
  state.schema = state.schema || await api("/api/schema");
  state.examples = await api("/api/examples");
  $("#add-title").textContent = title;
  $("#example-pick").innerHTML = '<option value="">Start from a template</option>' +
    Object.keys(state.examples).map((k) => `<option>${esc(k)}</option>`).join("");
  state.form = null;
  renderForm();
  setMode("form");
  $("#yaml").value = "";
  $("#add-out").innerHTML = "";
  $("#add").classList.remove("hidden");
}

async function validateYaml() {
  if (state.mode === "form") generateYaml();
  const r = await api("/api/connectors/validate", { method: "POST", body: JSON.stringify({ yaml: $("#yaml").value }) });
  if (!r.valid) {
    $("#add-out").innerHTML = `<div class="notice bad">Not valid:<ul>${r.errors.map((e) => `<li>${esc(e)}</li>`).join("")}</ul></div>`;
    return false;
  }
  const s = r.summary;
  const eps = r.endpoints;
  state.corrected = r.corrected;
  const fixes = r.fixes && r.fixes.length ? `<div class="notice">
      <b>Read with ${r.fixes.length} automatic fix${r.fixes.length > 1 ? "es" : ""}.</b> Check that this is what you meant:
      <ul>${r.fixes.map((f) => `<li>${esc(f)}</li>`).join("")}</ul>
      <button class="btn" id="btn-use-corrected">Use the corrected YAML</button>
      <span class="muted small">Replaces the text above with the clean version, which is what gets saved.</span></div>` : "";
  $("#add-out").innerHTML = fixes + `<div class="notice good">Valid. <span class="mono">${esc(r.id)}</span>, auth ${esc(s.auth.replace(/_/g, " "))},
      secrets: ${esc(s.secrets.join(", ") || "none")}, allowed hosts: ${esc(s.hosts.join(", ") || "local file")}.
      ${eps.length > 1 ? `${eps.length} endpoints share this login.` : ""}</div>
    <div class="table-wrap"><table><tr><th>Endpoint</th><th>Path</th><th>Writes to</th><th>Paging</th><th>Every</th><th>Fields</th></tr>
      ${eps.map((x) => `<tr><td>${esc(x.name)}<div class="muted mono">${esc(x.id)}</div></td><td class="mono">${esc(x.path)}</td><td>${esc(x.table)}</td>
        <td>${esc(x.pagination.replace(/_/g, " "))}</td><td>${esc(every(x.every_seconds))}</td><td class="wrap">${esc(x.fields.join(", "))}</td></tr>`).join("")}
    </table></div>
    ${eps.length > 1 ? `<label class="small muted">Test and Preview use endpoint <select id="ep-pick">${eps.map((x) =>
      `<option value="${esc(x.endpoint)}" ${x.endpoint === state.pickedEp ? "selected" : ""}>${esc(x.name)}</option>`).join("")}</select></label>` : ""}`;
  const pick = $("#ep-pick");
  if (pick) pick.onchange = (e) => { state.pickedEp = e.target.value; };
  return true;
}

function pickedEndpoint() {
  const p = $("#ep-pick");
  return p ? p.value : null;
}

// ---------------------------------------------------------------- events

document.addEventListener("click", async (e) => {
  const go = e.target.closest("[data-goto]");
  if (go) { e.preventDefault(); setView(go.dataset.goto); return; }
  const navLink = e.target.closest("#nav a[data-view]");
  if (navLink) { setView(navLink.dataset.view); return; }
  const dtab = e.target.closest("[data-dtab]");
  if (dtab) { openDetail(state.drawer.id, dtab.dataset.dtab); return; }
  const exp = e.target.closest("tr[data-expand]");
  if (exp && !e.target.closest("a")) { exp.nextElementSibling.classList.toggle("hidden"); return; }
  const row = e.target.closest("tr[data-open]");
  if (row && !e.target.closest("button")) { openDetail(row.dataset.open); return; }

  const t = e.target.closest("button, [data-close]");
  if (!t) { if (e.target.classList && e.target.classList.contains("modal")) e.target.classList.add("hidden"); return; }
  try {
    if (t.dataset.close !== undefined) {
      t.closest(".modal, .drawer").classList.add("hidden");
      if (t.closest(".drawer")) state.drawer = null;
    } else if (t.dataset.run) {
      t.disabled = true;
      const r = await api(`/api/connectors/${t.dataset.run}/run`, { method: "POST" });
      toast(r.skipped || (r.status === "ok"
        ? `${t.dataset.run}: ${n(r.fetched)} pulled, ${n(r.new)} new, ${n(r.updated)} updated, ${n(r.rejected)} rejected`
        : `${t.dataset.run} failed: ${r.error}`), r.status === "error");
      await refresh();
      if (state.drawer) openDetail(state.drawer.id, state.drawer.tab);
    } else if (t.dataset.test) {
      t.disabled = true;
      const r = await api("/api/test", { method: "POST", body: JSON.stringify({ yaml: t.dataset.test }) });
      toast(`${r.ok ? "Connection OK" : "Connection failed"}: ${r.detail} (${r.latency_ms} ms)`, !r.ok);
    } else if (t.dataset.toggle) {
      await api(`/api/connectors/${t.dataset.toggle}/${t.dataset.paused === "true" ? "resume" : "pause"}`, { method: "POST" });
      await refresh();
      openDetail(t.dataset.toggle, "overview");
    } else if (t.dataset.remove) {
      const sib = state.overview.connectors.filter((c) => c.endpoint && c.integration === (state.overview.connectors.find((x) => x.id === t.dataset.remove) || {}).integration);
      if (!confirm(sib.length > 1
        ? `Remove the whole integration (${sib.length} endpoints: ${sib.map((c) => c.endpoint).join(", ")})? They share one file. It is moved to data/removed and stored records are kept.`
        : `Remove ${t.dataset.remove}? It will stop running. Its file is moved to data/removed and stored records are kept.`)) return;
      const r = await api(`/api/connectors/${encodeURIComponent(t.dataset.remove)}`, { method: "DELETE" });
      $("#drawer").classList.add("hidden");
      state.drawer = null;
      toast(`Removed ${r.removed}`);
      refresh();
    } else if (t.dataset.edit) {
      await openAdd("Edit connector");
      const res = await fetch(`/api/connectors/${encodeURIComponent(t.dataset.edit)}/yaml`);
      $("#yaml").value = await res.text();
      setMode("yaml");
      $("#add-out").innerHTML = `<div class="notice">Keep the same id to update <span class="mono">${esc(t.dataset.edit)}</span>. A different id creates a new connector.</div>`;
    } else if (t.id === "btn-reload") {
      const r = await api("/api/reload", { method: "POST" });
      const errs = Object.keys(r.errors);
      toast(`Reloaded. Changed: ${r.changed.join(", ") || "none"}. Added: ${r.added.join(", ") || "none"}.` +
        (errs.length ? ` Not loaded: ${errs.join(", ")}.` : ""), errs.length > 0);
      refresh();
    } else if (t.dataset.mode) {
      if (t.dataset.mode === "yaml" && state.mode === "form" && !$("#yaml").value) generateYaml();
      else setMode(t.dataset.mode);
    } else if (t.dataset.mapDel !== undefined) {
      const [i, j] = t.dataset.mapDel.split(":").map(Number);
      collectForm().endpoints[i].map.splice(j, 1);
      renderForm();
    } else if (t.dataset.mapAdd !== undefined) {
      const ep = collectForm().endpoints[Number(t.dataset.mapAdd)];
      const req = ep.entity === "record" ? ["id"] : state.schema[ep.entity].required;
      ep.map.push({ target: req.find((r) => !ep.map.some((m) => m.target === r)) || (ep.entity === "record" ? "" : "id"), from: "" });
      renderForm();
    } else if (t.id === "ep-add") {
      const f = collectForm();
      f.endpoints.push(newEndpoint(f.endpoints.length));
      renderForm();
    } else if (t.dataset.epDel !== undefined) {
      collectForm().endpoints.splice(Number(t.dataset.epDel), 1);
      renderForm();
    } else if (t.dataset.secretSave) {
      const inp = $(`[data-secret-input="${t.dataset.secretSave}"]`);
      const val = inp.value.trim();
      if (!val) return toast("Enter a value first", true);
      if (/^https?:\/\/(127\.0\.0\.1|localhost)/.test(val)) return toast("That is the address of this page, not a token.", true);
      await api(`/api/secrets/${encodeURIComponent(t.dataset.secretSave)}`, { method: "PUT", body: JSON.stringify({ value: val }) });
      inp.value = "";
      toast(`Saved ${t.dataset.secretSave}`);
      renderSecrets();
    } else if (t.dataset.secretRefresh) {
      const r = await api(`/api/secrets/${encodeURIComponent(t.dataset.secretRefresh)}/refresh`, { method: "POST" });
      toast(`Reloaded ${t.dataset.secretRefresh}` + (r.refreshed.length ? ` for ${r.refreshed.join(", ")}` : ""));
      renderSecrets();
    } else if (t.id === "btn-add") {
      openAdd();
    } else if (t.id === "btn-gen") {
      generateYaml();
    } else if (t.id === "n-save") {
      await api("/api/notifications", { method: "PUT", body: JSON.stringify(collectNotifications()) });
      toast("Notification settings saved");
      renderAlerts();
    } else if (t.id === "n-test") {
      await api("/api/notifications", { method: "PUT", body: JSON.stringify(collectNotifications()) });
      t.disabled = true;
      const r = await api("/api/notifications/test", { method: "POST" });
      t.disabled = false;
      toast(`Test message: ${r.delivered}`, /failed|HTTP [45]|logged only/.test(r.delivered));
      renderAlerts();
    } else if (t.id === "btn-use-corrected") {
      $("#yaml").value = state.corrected;
      setMode("yaml");
      validateYaml();
    } else if (t.id === "btn-validate") {
      validateYaml();
    } else if (t.id === "btn-test") {
      if (!(await validateYaml())) return;
      const r = await api("/api/test", { method: "POST", body: JSON.stringify({ yaml: $("#yaml").value, endpoint: pickedEndpoint() }) });
      $("#add-out").insertAdjacentHTML("beforeend",
        `<div class="notice ${r.ok ? "good" : "bad"}">${r.ok ? "Connection OK" : "Connection failed"}: ${esc(r.detail)} (${esc(r.latency_ms)} ms)</div>`);
    } else if (t.id === "btn-preview") {
      if (!(await validateYaml())) return;
      $("#add-out").insertAdjacentHTML("beforeend", '<div id="pv2" class="muted">Fetching one page</div>');
      try { $("#pv2").outerHTML = renderPreview(await api("/api/preview", { method: "POST", body: JSON.stringify({ yaml: $("#yaml").value, endpoint: pickedEndpoint() }) })); }
      catch (err) { $("#pv2").outerHTML = `<div class="notice bad">${esc(err.message)}</div>`; }
    } else if (t.id === "btn-save") {
      if (!(await validateYaml())) return;
      const h = await api("/api/connectors", { method: "POST", body: JSON.stringify({ yaml: $("#yaml").value }) });
      $("#add").classList.add("hidden");
      toast(`Saved ${h.ids.join(", ")}. First run starting.`);
      refresh();
    }
  } catch (err) {
    toast(err.message, true);
  } finally {
    if (t.dataset && (t.dataset.run || t.dataset.test)) t.disabled = false;
  }
});

// selects that change which fields are shown: keep what was typed, then redraw
$("#mode-form").addEventListener("change", (e) => {
  if (!e.target.matches("[data-rerender]")) return;
  const f = collectForm();
  const ep = e.target.dataset.ep;
  if (ep !== undefined && e.target.dataset.k === "mapMode" && f.endpoints[ep].mapMode === "manual" && !f.endpoints[ep].map.length) {
    const ent = f.endpoints[ep].entity;
    f.endpoints[ep].map = (ent === "record" ? ["id", "title"] : state.schema[ent].required).map((t) => ({ target: t, from: "" }));
  }
  if (ep !== undefined && e.target.dataset.k === "entity") f.endpoints[ep].map = [];
  renderForm();
});

$("#yaml-file").onchange = async (e) => {
  const f = e.target.files[0];
  e.target.value = "";
  if (!f) return;
  if (f.size > 200000) return toast("File is too large for a connector config", true);
  $("#yaml").value = await f.text();
  setMode("yaml");
  validateYaml().catch((err) => toast(err.message, true));
};
$("#example-pick").onchange = (e) => {
  if (e.target.value) { $("#yaml").value = state.examples[e.target.value]; setMode("yaml"); }
};
document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  $("#add").classList.add("hidden");
  $("#drawer").classList.add("hidden");
  state.drawer = null;
});

const initial = location.hash.slice(1);
if (["users", "devices", "events", "records", "quarantine", "alerts", "secrets", "audit"].includes(initial)) state.view = initial;
document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("on", a.dataset.view === state.view));
// ---------------------------------------------------------------- sign in / sign up

function showAuth(mode) {
  state.user = null;
  document.body.classList.add("signed-out");
  api("/api/auth/status").then((st) => {
    const signup = mode ? mode === "signup" : !st.has_accounts;
    $("#auth").innerHTML = `<div class="auth-box">
      <div class="auth-brand">ConnectForge</div>
      <h1>${signup ? "Create your account" : "Sign in"}</h1>
      <p class="muted small">${signup ? "Notifications are emailed to the address you register."
        : "Use the email and password you registered with."}</p>
      <form id="auth-form" autocomplete="on">
        ${signup ? `<label>Name<input type="text" id="a-name" autocomplete="name" placeholder="Your name"></label>` : ""}
        <label>Email<input type="email" id="a-email" required autocomplete="username" placeholder="you@company.com"></label>
        <label>Password<input type="password" id="a-pass" required minlength="${signup ? 8 : 1}"
          autocomplete="${signup ? "new-password" : "current-password"}" placeholder="${signup ? "At least 8 characters" : ""}"></label>
        <div id="a-err" class="err-text small"></div>
        <button class="btn primary" type="submit">${signup ? "Create account" : "Sign in"}</button>
      </form>
      ${signup ? (st.has_accounts ? '<p class="small">Already registered? <a href="#" data-auth="login">Sign in</a></p>' : "")
        : st.signup_open ? '<p class="small">New here? <a href="#" data-auth="signup">Create an account</a></p>' : ""}
    </div>`;
    $("#auth").classList.remove("hidden");
    $("#a-email").focus();
    $("#auth-form").onsubmit = async (e) => {
      e.preventDefault();
      const body = { email: $("#a-email").value.trim(), password: $("#a-pass").value, name: signup ? $("#a-name").value.trim() : "" };
      try {
        await api(`/api/auth/${signup ? "signup" : "login"}`, { method: "POST", body: JSON.stringify(body) });
        $("#auth").classList.add("hidden");
        boot();
      } catch (err) {
        $("#a-err").textContent = err.message;
      }
    };
  });
}

let timers = [];
async function boot() {
  try {
    state.user = await api("/api/auth/me");
  } catch (_) {
    return showAuth();
  }
  document.body.classList.remove("signed-out");
  $("#whoami").innerHTML = `<span class="muted small">${esc(state.user.email)}</span> <button class="btn" id="btn-logout">Log out</button>`;
  await refresh();
  await render();
  if (initial.startsWith("open=")) openDetail(decodeURIComponent(initial.slice(5))).catch((e) => toast(e.message, true));
  if (initial === "add") openAdd();
  timers.forEach(clearInterval);
  timers = [setInterval(() => state.user && refresh(), 4000), setInterval(autoRender, 10000)];
}

document.addEventListener("click", async (e) => {
  const a = e.target.closest("[data-auth]");
  if (a) { e.preventDefault(); showAuth(a.dataset.auth); }
  if (e.target.id === "btn-logout") {
    await api("/api/auth/logout", { method: "POST" });
    timers.forEach(clearInterval);
    showAuth("login");
  }
});

boot();
function autoRender() {
  if (["users", "devices", "events", "records", "quarantine", "audit"].includes(state.view) && !document.activeElement.matches("input, select")
    && !document.querySelector("tr.detail:not(.hidden)")) render();
}
