"use strict";
// Every value from a source is untrusted: always render through esc().
const $ = (s, r = document) => r.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const state = { tab: "users", overview: null, schema: null, mode: "form", filters: {} };
let adminToken = null;
try { adminToken = localStorage.getItem("cfAdminToken"); } catch (_) { /* storage unavailable */ }

async function api(path, opts = {}) {
  opts.headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
  if (adminToken) opts.headers["X-Admin-Token"] = adminToken;
  const res = await fetch(path, opts);
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch (_) { data = text; }
  if (!res.ok) {
    const d = data && data.detail;
    throw new Error(d && d.errors ? d.errors.join("; ") : (typeof d === "string" ? d : res.statusText));
  }
  return data;
}
function toast(msg, bad = false) {
  const t = $("#toast"); t.textContent = msg; t.className = "toast" + (bad ? " err" : "");
  clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.add("hidden"), bad ? 8000 : 4000);
}
function ago(iso) {
  if (!iso) return "never";
  const s = Math.max(0, (Date.now() - new Date(iso)) / 1000);
  return s < 60 ? `${Math.round(s)}s ago` : s < 3600 ? `${Math.round(s / 60)} min ago` : `${Math.round(s / 3600)} h ago`;
}
const every = (s) => (s % 3600 === 0 ? `${s / 3600} h` : s % 60 === 0 ? `${s / 60} min` : `${s} s`);

// ---------- overview ----------
async function refresh() {
  try {
    state.overview = await api("/api/overview");
    renderSummary(); renderGrid();
    $("#updated").textContent = "live · " + new Date().toLocaleTimeString();
  } catch (e) { $("#updated").textContent = "API unreachable"; }
}

function renderSummary() {
  const o = state.overview, t = o.totals;
  $("#summary").innerHTML = [
    [t.connectors, "connections (config files)"], [t.healthy, "healthy"], [t.attention, "need attention", t.attention ? "warn" : ""],
    [o.tables.users.toLocaleString(), "users"], [o.tables.devices.toLocaleString(), "devices"], [o.tables.events.toLocaleString(), "events / alerts"],
    [t.quarantined.toLocaleString(), "bad records quarantined"], [t.alerts, "failure alerts sent"],
  ].map(([v, k, c]) => `<div class="stat ${c || ""}"><div class="v">${esc(v)}</div><div class="k">${esc(k)}</div></div>`).join("");
  $("#load-errors").innerHTML = Object.entries(o.load_errors).map(([f, errs]) =>
    `<div class="panel" style="padding-bottom:0"><div class="err"><b>${esc(f)}</b> not loaded: ${errs.map(esc).join("; ")}</div></div>`).join("");
}

function renderGrid() {
  $("#grid").innerHTML = state.overview.connectors.map((c) => {
    const lr = c.last_run || {};
    const lab = c.id.startsWith("lab-");
    const m = (v, k, cls = "") => `<div class="metric ${cls}"><div class="v">${esc(v ?? "—")}</div><div class="k">${esc(k)}</div></div>`;
    return `<article class="card ${esc(c.status)}">
      <div class="card-head"><div><h3>${esc(c.name)}</h3><div class="muted mono">${esc(c.id)} → ${esc(c.entity)}s · source "${esc(c.source)}"</div></div>
        <span class="pill ${esc(c.status)}">${c.running ? "running" : esc(c.status)}</span></div>
      <div class="chips"><span class="chip ${lab ? "badge-lab" : "badge-real"}">${lab ? "lab mock" : "real API"}</span>
        <span class="chip">login: ${esc(c.auth)}</span>${c.kind === "http" ? `<span class="chip">paging: ${esc(c.pagination)}</span>` : `<span class="chip">file tail</span>`}
        <span class="chip">every ${esc(every(c.every_seconds))}</span>${c.hosts.map((h) => `<span class="chip" title="credentials only ever go to this host">→ ${esc(h)}</span>`).join("")}</div>
      ${c.reasons.map((r) => `<div class="reason">⚠ ${esc(r)}</div>`).join("")}
      <div class="metrics">${m(lr.fetched, "pulled")}${m(lr.new, "new")}${m(lr.updated, "updated")}${m(lr.unchanged, "unchanged")}
        ${m(lr.rejected, "quarantined", lr.rejected ? "bad" : "")}${m(lr.retries, "retries", lr.retries ? "warn" : "")}
        ${m(lr.pages, "pages")}${m(lr.duration_ms != null ? lr.duration_ms + " ms" : null, "duration")}</div>
      <dl class="kv"><dt>Last run</dt><dd>${esc(ago(lr.finished_at))}${lr.status ? " · " + esc(lr.status) : ""}</dd>
        <dt>Last success</dt><dd>${esc(ago(c.last_success_at))}</dd>
        <dt>Next run</dt><dd>${c.next_run_in_s == null ? "—" : `in ${esc(c.next_run_in_s < 120 ? c.next_run_in_s + " s" : c.next_run_in_s < 7200 ? Math.round(c.next_run_in_s / 60) + " min" : (c.next_run_in_s / 3600).toFixed(1) + " h")}`}</dd>
        <dt>Stored</dt><dd>${esc(c.records_stored.toLocaleString())} ${esc(c.entity)}s</dd>
        <dt>Checkpoint</dt><dd class="mono">${esc(c.cursor || "—")}</dd></dl>
      ${lr.error ? `<div class="err">${esc(lr.error)}</div>` : ""}
      ${c.notes.length ? `<div class="notes">${c.notes.map(esc).join("<br>")}</div>` : ""}
      <div class="row"><button class="btn small" data-run="${esc(c.id)}">Run now</button>
        <button class="btn small" data-test="${esc(c.id)}">Test connection</button>
        <button class="btn small" data-toggle="${esc(c.id)}" data-paused="${c.paused}">${c.paused ? "Resume" : "Pause"}</button>
        <button class="btn small" data-detail="${esc(c.id)}">Details</button>
        <button class="btn small danger" data-remove="${esc(c.id)}">Remove</button></div>
    </article>`;
  }).join("") || `<div class="panel muted">No connections yet — click "+ Add source".</div>`;
}

// ---------- tables ----------
const COLS = {
  users: ["id", "name", "email", "status", "last_login", "source", "fetched_at"],
  devices: ["id", "hostname", "ip", "os", "owner", "last_seen", "source", "fetched_at"],
  events: ["id", "type", "severity", "timestamp", "description", "source", "fetched_at"],
};
const fmtCell = (c, v) => (/(_at|last_login|last_seen|timestamp)$/.test(c) && v ? String(v).replace("T", " ").slice(0, 19) : v);

async function renderTab() {
  document.querySelectorAll("#tabs .tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === state.tab));
  const body = $("#tab-body");
  if (COLS[state.tab]) {
    const f = state.filters[state.tab] || {};
    const sources = Object.keys((state.overview && state.overview.by_source[state.tab]) || {});
    const qs = new URLSearchParams({ limit: 100, ...(f.source ? { source: f.source } : {}), ...(f.q ? { q: f.q } : {}) });
    const rows = await api(`/api/records/${state.tab}?${qs}`);
    const cols = COLS[state.tab];
    body.innerHTML = `<div class="toolbar"><select id="f-source"><option value="">all sources</option>${sources.map((s) => `<option ${s === f.source ? "selected" : ""}>${esc(s)}</option>`).join("")}</select>
      <input type="text" id="f-q" placeholder="search…" value="${esc(f.q || "")}"><span class="muted">One <b>${state.tab}</b> table for every source · every row keeps <code>source</code> and <code>fetched_at</code> · <a href="/api/records/${state.tab}.jsonl" style="color:var(--accent)">export JSONL</a></span></div>
      <div class="scroll"><table><tr>${cols.map((c) => `<th>${c}</th>`).join("")}</tr>${rows.map((r) => `<tr>${cols.map((c) =>
        `<td class="${c === "severity" ? "sev-" + esc(r[c]) : ""} ${c === "description" ? "" : "mono"}">${esc(c === "description" ? String(r[c] || "").slice(0, 140) : fmtCell(c, r[c]))}</td>`).join("")}</tr>`).join("")}</table></div>
      ${rows.length ? "" : '<p class="muted">No rows yet.</p>'}`;
    $("#f-source").onchange = (e) => { state.filters[state.tab] = { ...f, source: e.target.value }; renderTab(); };
    $("#f-q").onchange = (e) => { state.filters[state.tab] = { ...f, q: e.target.value }; renderTab(); };
  } else if (state.tab === "quarantine") {
    const rows = await api("/api/quarantine?limit=80");
    body.innerHTML = `<p class="muted">Records that failed mapping are skipped and kept here with the exact reason — the run never crashes (FR-9).</p>
      <div class="scroll"><table><tr><th>When</th><th>Connection</th><th>Reason</th><th>Record</th></tr>${rows.map((r) =>
        `<tr><td class="mono">${esc(ago(r.at))}</td><td>${esc(r.connector)}</td><td>${esc(r.reason)}</td><td class="raw">${esc(r.record.slice(0, 400))}</td></tr>`).join("")}</table></div>`;
  } else if (state.tab === "alerts") {
    const rows = await api("/api/alerts");
    body.innerHTML = `<p class="muted">A connection that fails 3 runs in a row sends an alert (and another when it recovers). Set the <code>alert_webhook</code> secret to a Slack / Teams incoming-webhook URL.</p>
      <div class="scroll"><table><tr><th>When</th><th>Connection</th><th>Kind</th><th>Message</th><th>Delivery</th></tr>${rows.map((r) =>
        `<tr><td class="mono">${esc(ago(r.at))}</td><td>${esc(r.connector)}</td><td>${esc(r.kind)}</td><td>${esc(r.message)}</td><td>${esc(r.delivered)}</td></tr>`).join("")}</table></div>`;
  } else if (state.tab === "secrets") {
    const rows = await api("/api/secrets");
    body.innerHTML = `<p class="muted">Encrypted at rest · write-only (never shown, never in configs or logs) · a connection can read only the secrets its own config names · every read is audited. <code>\${env:NAME}</code> also works.</p>
      <div class="scroll"><table><tr><th>Secret</th><th>Status</th><th>Used by</th><th>Age</th><th>Last used</th><th>Set / rotate</th></tr>${rows.map((s) =>
        `<tr><td class="mono">${esc(s.name)}</td><td>${s.set ? "🔒 stored" : '<span class="tag-due">not set</span>'}</td><td>${esc(s.used_by.join(", ") || "—")}</td>
        <td>${s.age_days == null ? "—" : esc(s.age_days + " d")}${s.rotation_due ? ' <span class="tag-due">rotate</span>' : ""}</td>
        <td>${esc(ago(s.last_used_at))}${s.last_used_by ? " by " + esc(s.last_used_by) : ""}</td>
        <td class="row"><input type="password" placeholder="paste the token here" data-secret-input="${esc(s.name)}" autocomplete="new-password" data-lpignore="true" data-1p-ignore><button class="btn small" data-secret-save="${esc(s.name)}">Save</button></td></tr>`).join("")}</table></div>`;
  } else {
    const rows = await api("/api/audit?limit=80");
    body.innerHTML = `<div class="scroll"><table><tr><th>When</th><th>Actor</th><th>Action</th><th>Detail</th></tr>${rows.map((r) =>
      `<tr><td class="mono">${esc(ago(r.at))}</td><td>${esc(r.actor)}</td><td class="${/blocked|denied|alert/.test(r.action) ? "tag-due" : ""}">${esc(r.action)}</td><td class="mono">${esc(r.detail)}</td></tr>`).join("")}</table></div>`;
  }
}

// ---------- details ----------
async function openDetail(id, sub = "runs") {
  const d = await api(`/api/connectors/${encodeURIComponent(id)}`);
  $("#drawer-title").textContent = `${d.health.name} — ${d.health.status}`;
  const tabs = [["runs", "Run history"], ["bad", "Quarantined"], ["config", "Config"], ["preview", "Mapping preview"]];
  let html = `<div class="subtabs">${tabs.map(([k, l]) => `<button class="btn small ${k === sub ? "active" : ""}" data-sub="${k}" data-id="${esc(id)}">${l}</button>`).join("")}</div>`;
  if (sub === "runs") {
    html += `<div class="scroll"><table><tr><th>#</th><th>Started</th><th>Trigger</th><th>Status</th><th>Pages</th><th>Pulled</th><th>New</th><th>Updated</th><th>Unchanged</th><th>Quarantined</th><th>Retries</th><th>Error</th></tr>${d.runs.map((r) =>
      `<tr><td>${esc(r.id)}</td><td class="mono">${esc(ago(r.started_at))}</td><td>${esc(r.trigger)}</td><td>${esc(r.status)}</td><td>${esc(r.pages)}</td><td>${esc(r.fetched)}</td><td>${esc(r.new)}</td><td>${esc(r.updated)}</td><td>${esc(r.unchanged)}</td><td>${esc(r.rejected)}</td><td>${esc(r.retries)}</td><td>${esc(r.error || "")}</td></tr>`).join("")}</table></div>`;
  } else if (sub === "bad") {
    html += `<div class="scroll"><table><tr><th>When</th><th>Reason</th><th>Record</th></tr>${d.quarantined.map((r) =>
      `<tr><td class="mono">${esc(ago(r.at))}</td><td>${esc(r.reason)}</td><td class="raw">${esc(r.record)}</td></tr>`).join("")}</table></div>`;
  } else if (sub === "config") {
    html += `<p class="muted">Secrets appear only by name — the values live in the encrypted vault.</p><pre>${esc(JSON.stringify(d.spec, null, 2))}</pre>`;
  } else {
    html += `<div id="pv">Fetching one page…</div>`;
  }
  $("#drawer-body").innerHTML = html;
  $("#drawer").classList.remove("hidden");
  if (sub === "preview") {
    try { $("#pv").innerHTML = renderPreview(await api("/api/preview", { method: "POST", body: JSON.stringify({ yaml: id }) })); }
    catch (e) { $("#pv").innerHTML = `<div class="err">${esc(e.message)}</div>`; }
  }
}
function renderPreview(p) {
  return (p.notes.length ? `<div class="notes">${p.notes.map(esc).join("<br>")}</div>` : "") + p.samples.map((s) => `<div class="pair">
    <div><div class="label">Raw record from the source</div><pre>${esc(JSON.stringify(s.raw, null, 2).slice(0, 3000))}</pre></div>
    <div><div class="label">${s.error ? "Would be quarantined" : `Common schema → ${esc(p.entity)}s table`}</div>${s.error ? `<div class="err">${esc(s.error)}</div>` : `<pre>${esc(JSON.stringify(s.record, null, 2))}</pre>`}</div></div>`).join("")
    || `<div class="muted">The source returned no records.</div>`;
}

// ---------- add source: web form (B-5) -> YAML ----------
function field(id, label, value = "", attrs = "") { return `<label>${label}<input id="${id}" value="${esc(value)}" ${attrs}></label>`; }
function select(id, label, options, value) {
  return `<label>${label}<select id="${id}">${options.map((o) => `<option ${o === value ? "selected" : ""}>${o}</option>`).join("")}</select></label>`;
}
function renderForm() {
  const ent = ($("#f-entity") && $("#f-entity").value) || "user";
  const fields = Object.keys(state.schema[ent].fields);
  const required = state.schema[ent].required;
  const rows = state.formRows || required.map((t) => ({ target: t, from: "" }));
  $("#mode-form").innerHTML = `
    <fieldset><legend>Source</legend><div class="form-grid">
      ${field("f-id", "Connection id", "my-source", 'placeholder="lowercase-id"')}${field("f-name", "Display name", "My source")}
      ${select("f-entity", "Lands in table", ["user", "device", "event"], ent)}${field("f-every", "Run every", "15m", 'placeholder="30s, 15m, 2h"')}</div></fieldset>
    <fieldset><legend>Endpoint (FR-2)</legend><div class="form-grid">
      ${field("f-base", "Base URL", "https://api.example.com")}${field("f-path", "Path", "/api/v1/users")}
      ${select("f-method", "Method", ["GET", "POST"], "GET")}${field("f-records", "Records path in response", "", 'placeholder="(empty = whole body) e.g. data.items"')}</div></fieldset>
    <fieldset><legend>Login (FR-1)</legend><div class="form-grid">
      ${select("f-auth", "Type", ["none", "api_key", "bearer", "basic"], "api_key")}${field("f-secret", "Secret name (stored in vault)", "my_api_key")}
      ${field("f-header", "Header (api_key) / scheme (bearer)", "X-API-Key")}${field("f-user", "Username / email (basic)", "")}</div></fieldset>
    <fieldset><legend>Pagination (FR-3)</legend><div class="form-grid">
      ${select("f-page", "Style", ["none", "link_header", "page_number", "offset", "next_token"], "link_header")}
      ${field("f-psize-param", "Page-size parameter", "limit")}${field("f-psize", "Page size", "100", 'type="number"')}
      ${field("f-pparam", "Page / offset / token parameter", "")}</div></fieldset>
    <fieldset><legend>Mapping to the ${ent} schema (FR-5) — <span class="req">required: ${required.join(", ")}</span></legend>
      <div id="maprows">${rows.map((r, i) => `<div class="maprow"><select data-map-target="${i}">${fields.map((f) => `<option ${f === r.target ? "selected" : ""}>${f}</option>`).join("")}</select>
        <input data-map-from="${i}" value="${esc(r.from)}" placeholder="source path, e.g. profile.login  (or =constant)"><button class="btn small" data-map-del="${i}">✕</button></div>`).join("")}</div>
      <button class="btn small" id="map-add">+ field</button></fieldset>
    <div class="row"><button class="btn" id="btn-gen">Generate config ↓</button><span class="muted">The form writes the YAML for you — review it on the YAML tab, then Validate / Test / Save.</span></div>`;
  $("#f-entity").onchange = () => { state.formRows = null; renderForm(); };
}
function collectRows() {
  return [...document.querySelectorAll("[data-map-target]")].map((s) => ({ target: s.value, from: $(`[data-map-from="${s.dataset.mapTarget}"]`).value }));
}
function yamlScalar(v) {
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return /^[A-Za-z0-9_./-]+$/.test(v) && !/^(true|false|null|yes|no|\d)/i.test(v) ? v : JSON.stringify(v);
}
function toYaml(obj, indent = "") {
  return Object.entries(obj).filter(([, v]) => v !== undefined && v !== "").map(([k, v]) => {
    if (v && typeof v === "object") return `${indent}${k}:\n${toYaml(v, indent + "  ")}`;
    return `${indent}${k}: ${yamlScalar(v)}`;
  }).join("\n");
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
  const spec = { id: v("#f-id"), name: v("#f-name"), entity: $("#f-entity").value, schedule: { every: v("#f-every") },
    auth, request: { base_url: v("#f-base"), path: v("#f-path"), ...(v("#f-method") === "POST" ? { method: "POST" } : {}) },
    pagination: pg, records: v("#f-records") || undefined, mapping };
  $("#yaml").value = "# generated by the ConnectForge web form\n" + toYaml(spec) + "\n";
  setMode("yaml");
}
function setMode(mode) {
  state.mode = mode;
  document.querySelectorAll("[data-mode]").forEach((b) => b.classList.toggle("active", b.dataset.mode === mode));
  $("#mode-form").classList.toggle("hidden", mode !== "form");
  $("#mode-yaml").classList.toggle("hidden", mode !== "yaml");
}
async function openAdd() {
  state.schema = state.schema || await api("/api/schema");
  state.examples = await api("/api/examples");
  $("#example-pick").innerHTML = `<option value="">Load example…</option>` + Object.keys(state.examples).map((k) => `<option>${esc(k)}</option>`).join("");
  state.formRows = null; renderForm(); setMode("form");
  $("#add-out").innerHTML = "";
  $("#add").classList.remove("hidden");
}
async function validateYaml() {
  if (state.mode === "form") generateYaml();
  const r = await api("/api/connectors/validate", { method: "POST", body: JSON.stringify({ yaml: $("#yaml").value }) });
  const s = r.summary;
  $("#add-out").innerHTML = r.valid
    ? `<div class="ok-box">✓ Valid: <b>${esc(r.id)}</b> → <b>${esc(s.table)}</b> table · login ${esc(s.auth)} · paging ${esc(s.pagination)} · every ${esc(every(s.every_seconds))} · maps ${esc(s.fields.join(", "))} · secrets: ${esc(s.secrets.join(", ") || "none")} · credentials only sent to ${esc(s.hosts.join(", ") || "local file")}</div>`
    : `<div class="err"><b>Fix before it can run:</b><ul>${r.errors.map((e) => `<li>${esc(e)}</li>`).join("")}</ul></div>`;
  return r.valid;
}

// ---------- events ----------
document.addEventListener("click", async (e) => {
  const t = e.target.closest("button, [data-close]");
  if (!t) { if (e.target.classList && e.target.classList.contains("overlay")) e.target.classList.add("hidden"); return; }
  try {
    if (t.dataset.close !== undefined) t.closest(".overlay").classList.add("hidden");
    else if (t.dataset.run) { t.disabled = true; const r = await api(`/api/connectors/${t.dataset.run}/run`, { method: "POST" });
      toast(r.skipped || `${t.dataset.run}: ${r.status} — pulled ${r.fetched}, new ${r.new}, updated ${r.updated}, quarantined ${r.rejected}${r.error ? " — " + r.error : ""}`, r.status === "error"); refresh(); renderTab(); }
    else if (t.dataset.test) { t.disabled = true; const r = await api("/api/test", { method: "POST", body: JSON.stringify({ yaml: t.dataset.test }) });
      toast(`${r.ok ? "✓" : "✗"} ${t.dataset.test}: ${r.detail} (${r.latency_ms} ms)`, !r.ok); }
    else if (t.dataset.toggle) { await api(`/api/connectors/${t.dataset.toggle}/${t.dataset.paused === "true" ? "resume" : "pause"}`, { method: "POST" }); refresh(); }
    else if (t.dataset.remove) {
      if (!confirm(`Remove connection "${t.dataset.remove}"? It stops running; its YAML is archived to data/removed/ and already-stored records are kept.`)) return;
      const r = await api(`/api/connectors/${encodeURIComponent(t.dataset.remove)}`, { method: "DELETE" });
      toast(`${r.removed} removed${r.archived_to ? " — config archived to " + r.archived_to : ""}`); refresh(); }
    else if (t.dataset.detail) openDetail(t.dataset.detail);
    else if (t.dataset.sub) openDetail(t.dataset.id, t.dataset.sub);
    else if (t.dataset.tab) { state.tab = t.dataset.tab; renderTab(); }
    else if (t.dataset.goto) { state.tab = t.dataset.goto; await renderTab(); $("#tabs").scrollIntoView({ behavior: "smooth" }); }
    else if (t.dataset.mode) { if (t.dataset.mode === "yaml" && state.mode === "form" && !$("#yaml").value) generateYaml(); else setMode(t.dataset.mode); }
    else if (t.dataset.mapDel !== undefined) { state.formRows = collectRows().filter((_, i) => i !== Number(t.dataset.mapDel)); renderForm(); }
    else if (t.id === "map-add") { state.formRows = [...collectRows(), { target: "id", from: "" }]; renderForm(); }
    else if (t.dataset.secretSave) { const inp = $(`[data-secret-input="${t.dataset.secretSave}"]`);
      const val = inp.value.trim();
      if (!val) return toast("enter a value", true);
      if (/^https?:\/\/(127\.0\.0\.1|localhost)/.test(val)) return toast("That is this page's address, not a token — copy the token from the provider and paste it again.", true);
      await api(`/api/secrets/${encodeURIComponent(t.dataset.secretSave)}`, { method: "PUT", body: JSON.stringify({ value: val }) });
      inp.value = ""; toast(`${t.dataset.secretSave} stored (encrypted)`); renderTab(); }
    else if (t.id === "btn-add") openAdd();
    else if (t.id === "btn-gen") generateYaml();
    else if (t.id === "btn-validate") validateYaml();
    else if (t.id === "btn-test") { if (!(await validateYaml())) return;
      const r = await api("/api/test", { method: "POST", body: JSON.stringify({ yaml: $("#yaml").value }) });
      $("#add-out").innerHTML += `<div class="${r.ok ? "ok-box" : "err"}" style="margin-top:8px">${r.ok ? "✓ Connection OK" : "✗ Connection failed"}: ${esc(r.detail)} (${esc(r.latency_ms)} ms)</div>`; }
    else if (t.id === "btn-preview") { if (!(await validateYaml())) return;
      $("#add-out").innerHTML += `<div id="pv2" class="muted">Fetching one page…</div>`;
      try { $("#pv2").outerHTML = renderPreview(await api("/api/preview", { method: "POST", body: JSON.stringify({ yaml: $("#yaml").value }) })); }
      catch (err) { $("#pv2").outerHTML = `<div class="err">${esc(err.message)}</div>`; } }
    else if (t.id === "btn-save") { if (!(await validateYaml())) return;
      const h = await api("/api/connectors", { method: "POST", body: JSON.stringify({ yaml: $("#yaml").value }) });
      $("#add").classList.add("hidden"); toast(`${h.name} added — first run starting (no code, no restart)`); refresh(); }
  } catch (err) { toast(err.message, true); }
  finally { if (t.dataset && (t.dataset.run || t.dataset.test)) t.disabled = false; }
});
$("#yaml-file").onchange = async (e) => {
  const f = e.target.files[0]; e.target.value = "";
  if (!f) return;
  if (f.size > 200000) return toast("That file is too large for a connector config", true);
  $("#yaml").value = await f.text(); setMode("yaml");
  toast(`Loaded ${f.name} — validating…`); validateYaml().catch((err) => toast(err.message, true));
};
$("#example-pick").onchange = (e) => { if (e.target.value) { $("#yaml").value = state.examples[e.target.value]; setMode("yaml"); } };
document.addEventListener("keydown", (e) => { if (e.key === "Escape") document.querySelectorAll(".overlay").forEach((o) => o.classList.add("hidden")); });

refresh().then(renderTab);
setInterval(refresh, 3000);
setInterval(() => { if (["users", "devices", "events", "quarantine", "alerts"].includes(state.tab) && !document.activeElement.matches("input")) renderTab(); }, 8000);
