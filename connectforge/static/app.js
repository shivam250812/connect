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
  if (["users", "devices", "events"].includes(v)) return renderRecords(v);
  if (v === "quarantine") return renderQuarantine();
  if (v === "alerts") return renderAlerts();
  if (v === "secrets") return renderSecrets();
  return renderAudit();
}

function renderConnections() {
  const o = state.overview;
  if (!o) { $("#view").innerHTML = '<div class="empty">Loading</div>'; return; }
  const t = o.totals;
  const rows = o.connectors.map((c) => {
    const lr = c.last_run || {};
    const status = c.running ? "running" : c.status;
    const err = lr.error || (c.reasons[0] || "");
    return `<tr class="click" data-open="${esc(c.id)}">
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
      <div><span>${n(t.quarantined)}</span>Quarantined</div>
    </div>
    <div class="table-wrap"><table>
      <tr><th>Name</th><th>Status</th><th>Writes to</th><th>Auth</th><th>Schedule</th><th>Last run</th>
        <th style="text-align:right">Pulled</th><th style="text-align:right">Stored</th><th style="text-align:right">Rejected</th><th>Next run</th><th>Last error</th></tr>
      ${rows || '<tr><td colspan="11" class="empty">No connectors yet. Use Add connector to create one.</td></tr>'}
    </table></div>`;
}

const COLS = {
  users: ["id", "name", "email", "status", "last_login", "source", "fetched_at"],
  devices: ["id", "hostname", "ip", "os", "owner", "last_seen", "source", "fetched_at"],
  events: ["id", "type", "severity", "timestamp", "description", "source", "fetched_at"],
};
const TITLES = { users: "Users", devices: "Devices", events: "Events" };

async function renderRecords(table) {
  const f = state.filters[table] || {};
  const sources = Object.keys((state.overview && state.overview.by_source[table]) || {});
  const qs = new URLSearchParams({ limit: 200, ...(f.source ? { source: f.source } : {}), ...(f.q ? { q: f.q } : {}) });
  const rows = await api(`/api/records/${table}?${qs}`);
  const cols = COLS[table];
  const total = state.overview ? state.overview.tables[table] : rows.length;
  $("#view").innerHTML = `
    <div class="page-head"><h1>${TITLES[table]} <span class="muted small">${n(total)} total</span></h1>
      <a href="/api/records/${table}.jsonl">Export JSONL</a></div>
    <div class="toolbar">
      <select id="f-source"><option value="">All sources</option>${sources.map((s) => `<option ${s === f.source ? "selected" : ""}>${esc(s)}</option>`).join("")}</select>
      <input type="text" id="f-q" placeholder="Search" value="${esc(f.q || "")}">
      <span class="muted small">Showing up to 200 rows</span>
    </div>
    <div class="table-wrap"><table>
      <tr>${cols.map((c) => `<th>${c}</th>`).join("")}</tr>
      ${rows.map((r) => `<tr>${cols.map((c) => {
        const v = /(_at|last_login|last_seen|timestamp)$/.test(c) ? shortTime(r[c]) : r[c];
        const cls = c === "severity" ? `sev-${esc(r[c])}` : c === "description" ? "wrap" : c === "id" ? "mono" : "";
        return `<td class="${cls}">${esc(c === "description" ? String(v || "").slice(0, 160) : v)}</td>`;
      }).join("")}</tr>`).join("") || `<tr><td colspan="${cols.length}" class="empty">No rows</td></tr>`}
    </table></div>`;
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

async function renderAlerts() {
  const rows = await api("/api/alerts");
  $("#view").innerHTML = `
    <div class="page-head"><h1>Alerts</h1><span class="muted">Sent after 3 failed runs in a row, and again on recovery. Webhook: secret <span class="mono">alert_webhook</span>.</span></div>
    <div class="table-wrap"><table><tr><th>When</th><th>Connector</th><th>Type</th><th>Message</th><th>Delivery</th></tr>
    ${rows.map((r) => `<tr><td>${esc(ago(r.at))}</td><td class="mono">${esc(r.connector)}</td><td>${esc(r.kind)}</td><td class="wrap">${esc(r.message)}</td><td>${esc(r.delivered)}</td></tr>`).join("")
      || '<tr><td colspan="5" class="empty">No alerts</td></tr>'}</table></div>`;
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

async function openDetail(id, tab = "overview") {
  state.drawer = { id, tab };
  const d = await api(`/api/connectors/${encodeURIComponent(id)}`);
  const h = d.health;
  const lr = h.last_run || {};
  $("#drawer-title").textContent = h.name;
  $("#drawer-sub").innerHTML = `<span class="mono">${esc(h.id)}</span>, writes to ${esc(h.entity)}s, source <span class="mono">${esc(h.source)}</span>`;
  $("#drawer-actions").innerHTML = `
    <button class="btn" data-run="${esc(id)}">Run now</button>
    <button class="btn" data-test="${esc(id)}">Test connection</button>
    <button class="btn" data-toggle="${esc(id)}" data-paused="${h.paused}">${h.paused ? "Resume" : "Pause"}</button>
    <button class="btn" data-edit="${esc(id)}">Edit YAML</button>
    <button class="btn danger" data-remove="${esc(id)}">Remove</button>`;
  const tabs = [["overview", "Overview"], ["runs", "Runs"], ["bad", "Quarantine"], ["config", "Config"], ["preview", "Preview"]];
  $("#drawer-tabs").innerHTML = tabs.map(([k, l]) => `<a data-dtab="${k}" class="${k === tab ? "on" : ""}">${l}</a>`).join("");

  let html = "";
  if (tab === "overview") {
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
  $("#drawer").classList.remove("hidden");
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

function renderForm() {
  const ent = ($("#f-entity") && $("#f-entity").value) || "user";
  const fields = Object.keys(state.schema[ent].fields);
  const required = state.schema[ent].required;
  const rows = state.formRows || required.map((t) => ({ target: t, from: "" }));
  $("#mode-form").innerHTML = `<div class="form-stack">
    <fieldset><legend>General</legend><div class="form-grid">
      ${field("f-id", "ID", "my-source", 'placeholder="lowercase-with-dashes"')}${field("f-name", "Name", "My source")}
      ${select("f-entity", "Writes to", ["user", "device", "event"], ent)}${field("f-every", "Schedule", "15m", 'placeholder="30s, 15m, 2h"')}</div></fieldset>
    <fieldset><legend>Request</legend><div class="form-grid">
      ${field("f-base", "Base URL", "https://api.example.com")}${field("f-path", "Path", "/api/v1/users")}
      ${select("f-method", "Method", ["GET", "POST"], "GET")}${field("f-records", "Records path", "", 'placeholder="for example data.items"')}</div></fieldset>
    <fieldset><legend>Authentication</legend><div class="form-grid">
      ${select("f-auth", "Type", ["none", "api_key", "bearer", "basic"], "api_key")}${field("f-secret", "Secret name", "my_api_key")}
      ${field("f-header", "Header name or scheme", "X-API-Key")}${field("f-user", "Username (basic)", "")}</div></fieldset>
    <fieldset><legend>Pagination</legend><div class="form-grid">
      ${select("f-page", "Style", ["none", "link_header", "page_number", "offset", "next_token"], "link_header")}
      ${field("f-psize-param", "Page size parameter", "limit")}${field("f-psize", "Page size", "100", 'type="number"')}
      ${field("f-pparam", "Page, offset or token parameter", "")}</div></fieldset>
    <fieldset><legend>Field mapping (required: ${required.join(", ")})</legend>
      ${rows.map((r, i) => `<div class="maprow"><select data-map-target="${i}">${fields.map((f) => `<option ${f === r.target ? "selected" : ""}>${f}</option>`).join("")}</select>
        <input type="text" data-map-from="${i}" value="${esc(r.from)}" placeholder="path in the source record, or =fixed value"><button class="btn" data-map-del="${i}">Remove</button></div>`).join("")}
      <button class="btn" id="map-add">Add field</button></fieldset>
    <div class="actions"><button class="btn" id="btn-gen">Generate YAML</button></div></div>`;
  $("#f-entity").onchange = () => { state.formRows = null; renderForm(); };
}

function collectRows() {
  return [...document.querySelectorAll("[data-map-target]")].map((s) =>
    ({ target: s.value, from: $(`[data-map-from="${s.dataset.mapTarget}"]`).value }));
}
function yamlScalar(v) {
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return /^[A-Za-z0-9_./-]+$/.test(v) && !/^(true|false|null|yes|no|\d)/i.test(v) ? v : JSON.stringify(v);
}
function toYaml(obj, indent = "") {
  return Object.entries(obj).filter(([, v]) => v !== undefined && v !== "").map(([k, v]) =>
    (v && typeof v === "object") ? `${indent}${k}:\n${toYaml(v, indent + "  ")}` : `${indent}${k}: ${yamlScalar(v)}`).join("\n");
}
function generateYaml() {
  const v = (id) => $(id).value.trim();
  const auth = { type: v("#f-auth") };
  if (auth.type !== "none") auth.secret = v("#f-secret");
  if (auth.type === "api_key") auth.header = v("#f-header") || "X-API-Key";
  if (auth.type === "bearer" && v("#f-header") && v("#f-header") !== "X-API-Key") auth.scheme = v("#f-header");
  if (auth.type === "basic") auth.username = v("#f-user");
  const pg = { type: v("#f-page") };
  if (pg.type !== "none") {
    if (v("#f-psize-param")) { pg.page_size_param = v("#f-psize-param"); pg.page_size = Number(v("#f-psize")) || 100; }
    if (pg.type === "page_number" && v("#f-pparam")) pg.page_param = v("#f-pparam");
    if (pg.type === "offset" && v("#f-pparam")) pg.offset_param = v("#f-pparam");
    if (pg.type === "next_token") { pg.token_path = v("#f-pparam"); pg.token_param = v("#f-pparam"); }
  }
  const mapping = {};
  collectRows().filter((r) => r.from).forEach((r) => { mapping[r.target] = r.from.startsWith("=") ? { const: r.from.slice(1) } : r.from; });
  const spec = {
    id: v("#f-id"), name: v("#f-name"), entity: $("#f-entity").value, schedule: { every: v("#f-every") }, auth,
    request: { base_url: v("#f-base"), path: v("#f-path"), ...(v("#f-method") === "POST" ? { method: "POST" } : {}) },
    pagination: pg, records: v("#f-records") || undefined, mapping,
  };
  $("#yaml").value = toYaml(spec) + "\n";
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
  state.formRows = null;
  renderForm();
  setMode("form");
  $("#yaml").value = "";
  $("#add-out").innerHTML = "";
  $("#add").classList.remove("hidden");
}

async function validateYaml() {
  if (state.mode === "form") generateYaml();
  const r = await api("/api/connectors/validate", { method: "POST", body: JSON.stringify({ yaml: $("#yaml").value }) });
  const s = r.summary;
  $("#add-out").innerHTML = r.valid
    ? `<div class="notice good">Valid. <span class="mono">${esc(r.id)}</span> writes to ${esc(s.table)}, auth ${esc(s.auth.replace(/_/g, " "))},
        pagination ${esc(s.pagination.replace(/_/g, " "))}, every ${esc(every(s.every_seconds))}. Fields: ${esc(s.fields.join(", "))}.
        Secrets: ${esc(s.secrets.join(", ") || "none")}. Allowed hosts: ${esc(s.hosts.join(", ") || "local file")}.</div>`
    : `<div class="notice bad">Not valid:<ul>${r.errors.map((e) => `<li>${esc(e)}</li>`).join("")}</ul></div>`;
  return r.valid;
}

// ---------------------------------------------------------------- events

document.addEventListener("click", async (e) => {
  const navLink = e.target.closest("#nav a[data-view]");
  if (navLink) { setView(navLink.dataset.view); return; }
  const dtab = e.target.closest("[data-dtab]");
  if (dtab) { openDetail(state.drawer.id, dtab.dataset.dtab); return; }
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
      if (!confirm(`Remove ${t.dataset.remove}? It will stop running. Its file is moved to data/removed and stored records are kept.`)) return;
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
      state.formRows = collectRows().filter((_, i) => i !== Number(t.dataset.mapDel));
      renderForm();
    } else if (t.id === "map-add") {
      state.formRows = [...collectRows(), { target: "id", from: "" }];
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
    } else if (t.id === "btn-validate") {
      validateYaml();
    } else if (t.id === "btn-test") {
      if (!(await validateYaml())) return;
      const r = await api("/api/test", { method: "POST", body: JSON.stringify({ yaml: $("#yaml").value }) });
      $("#add-out").insertAdjacentHTML("beforeend",
        `<div class="notice ${r.ok ? "good" : "bad"}">${r.ok ? "Connection OK" : "Connection failed"}: ${esc(r.detail)} (${esc(r.latency_ms)} ms)</div>`);
    } else if (t.id === "btn-preview") {
      if (!(await validateYaml())) return;
      $("#add-out").insertAdjacentHTML("beforeend", '<div id="pv2" class="muted">Fetching one page</div>');
      try { $("#pv2").outerHTML = renderPreview(await api("/api/preview", { method: "POST", body: JSON.stringify({ yaml: $("#yaml").value }) })); }
      catch (err) { $("#pv2").outerHTML = `<div class="notice bad">${esc(err.message)}</div>`; }
    } else if (t.id === "btn-save") {
      if (!(await validateYaml())) return;
      const h = await api("/api/connectors", { method: "POST", body: JSON.stringify({ yaml: $("#yaml").value }) });
      $("#add").classList.add("hidden");
      toast(`Saved ${h.id}. First run starting.`);
      refresh();
    }
  } catch (err) {
    toast(err.message, true);
  } finally {
    if (t.dataset && (t.dataset.run || t.dataset.test)) t.disabled = false;
  }
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
if (["users", "devices", "events", "quarantine", "alerts", "secrets", "audit"].includes(initial)) state.view = initial;
document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("on", a.dataset.view === state.view));
refresh().then(render);
setInterval(refresh, 4000);
setInterval(() => {
  if (["users", "devices", "events", "quarantine", "alerts", "audit"].includes(state.view) && !document.activeElement.matches("input, select")) render();
}, 10000);
