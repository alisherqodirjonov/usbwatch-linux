"use strict";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const main = $("#main");
const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const MODES = {
  off: ["Allow all", "Every USB drive works. All activity is logged."],
  blacklist: ["Block listed", "Drives you block are switched off the moment they are plugged in."],
  whitelist: ["Allow listed only", "Only drives you allow work. Any other USB drive is switched off when plugged in."],
};
const SHOW = {
  "": ["All activity", {}],
  to: ["Written to USB", { direction: "to USB" }],
  from: ["Read from USB", { direction: "from USB" }],
  deleted: ["Deleted", null],
  drives: ["Plugged in / removed", { category: "device" }],
};
let gen = 0, timer = null;

// --- helpers ---
async function api(path, opts = {}) {
  const r = await fetch(path, {
    method: opts.method || "GET", credentials: "same-origin",
    headers: { "X-Requested-With": "usbwatch", ...(opts.body ? { "Content-Type": "application/json" } : {}) },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (r.status === 401 && !opts.login) { showLogin(); throw new Error("Not signed in"); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
  return data;
}
function toast(msg, bad = false) {
  const t = $("#toast");
  t.textContent = msg; t.className = "toast" + (bad ? " bad" : "");
  clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.add("hidden"), 4500);
}
const fail = e => toast(e.message || String(e), true);
function confirmBox(text, okLabel = "OK", danger = false) {
  return new Promise(resolve => {
    $("#modal-body").innerHTML = `<p>${esc(text)}</p>`;
    const yes = $("#modal-yes"), no = $("#modal-no");
    yes.textContent = okLabel; yes.className = "btn" + (danger ? " danger" : "");
    const done = v => { $("#modal").classList.add("hidden"); yes.onclick = no.onclick = null; resolve(v); };
    yes.onclick = () => done(true); no.onclick = () => done(false);
    $("#modal").classList.remove("hidden"); yes.focus();
  });
}
function fmtSize(n) {
  if (n === null || n === undefined || n === "") return "";
  n = Number(n);
  if (!isFinite(n) || n < 0) return "";
  for (const u of ["B", "KB", "MB", "GB", "TB"]) {
    if (n < 1024 || u === "TB") return u === "B" ? `${n.toFixed(0)} B` : `${n.toFixed(1)} ${u}`;
    n /= 1024;
  }
}
const when = sec => sec ? new Date(sec * 1000).toLocaleString() : "";
const actCell = a => `<span class="a-${String(a).replace(/[^A-Za-z]/g, "")}">${esc(a)}</span>`;
const devLink = r => r.serial ? `<a href="#/activity?serial=${encodeURIComponent(r.serial)}">${esc(r.device || r.name || r.serial)}</a>` : "";
const who = r => r.user ? esc(r.user) + (r.login && r.login !== r.user ? ` <span class="muted">(${esc(r.login)})</span>` : "") : "";
const proc = r => r.process ? `<span title="${esc(r.cmdline)}">${esc(r.process)}</span>` : "";
const listPill = k => k === "allow" ? `<span class="pill allow">Allowed</span>` : k === "block" ? `<span class="pill block">Blocked</span>` : "";
function query() {
  const i = location.hash.indexOf("?");
  return new URLSearchParams(i < 0 ? "" : location.hash.slice(i + 1));
}
const head = (title, tools = "") => `<div class="head"><h1>${esc(title)}</h1><div class="tools">${tools}</div></div>`;

/** Render a table into `el`. cols: [{h, f(row) -> html, cls}] */
function table(el, cols, rows, opts = {}) {
  if (!rows.length) { el.innerHTML = `<div class="empty">${esc(opts.empty || "Nothing here yet.")}</div>`; return; }
  el.innerHTML = `<table><thead><tr>${cols.map(c => `<th>${esc(c.h)}</th>`).join("")}</tr></thead>
    <tbody>${rows.map((r, i) => `<tr data-i="${i}" class="${opts.onClick ? "click" : ""}">${cols.map(c => `<td class="${c.cls || ""}">${c.f(r) ?? ""}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
  if (opts.onClick) el.querySelector("tbody").addEventListener("click", e => {
    if (e.target.closest("a,button,input")) return;
    const tr = e.target.closest("tr"); if (tr) opts.onClick(rows[tr.dataset.i]);
  });
}
function autoRefresh(fn, my, ms = 5000) {
  clearInterval(timer);
  timer = setInterval(() => {
    if (my !== gen || document.hidden || document.activeElement?.matches("input,select,textarea")) return;
    fn(true).catch(() => {});
  }, ms);
}

const EVENT_COLS = [
  { h: "Time", f: r => esc(r.ts), cls: "nowrap" },
  { h: "What", f: r => actCell(r.action), cls: "nowrap" },
  { h: "File", f: r => esc(r.path) + (r.dest ? `<br><span class="muted">→ ${esc(r.dest)}</span>` : ""), cls: "path" },
  { h: "Size", f: r => fmtSize(r.size), cls: "nowrap" },
  { h: "User", f: who, cls: "nowrap" },
  { h: "Program", f: proc, cls: "nowrap" },
  { h: "Drive", f: devLink },
];

function driveCard(d) {
  const status = d.blocked ? `<span class="pill block">Blocked</span>` : listPill(d.list);
  let body;
  if (d.blocked) body = `<p class="muted small">Switched off by the access policy.</p>`;
  else if (!d.mount) body = `<p class="muted small">Plugged in, not mounted${d.size ? ` · ${fmtSize(d.size)}` : ""}</p>`;
  else {
    const used = (d.total || 0) - (d.free || 0), pct = d.total ? (used / d.total * 100).toFixed(1) : 0;
    body = `<p class="muted small">${esc(d.mount)}${d.fs ? ` · ${esc(d.fs)}` : ""}</p>
      <div class="bar"><i class="${pct > 90 ? "full" : ""}" data-w="${pct}"></i></div>
      <p class="muted small">${fmtSize(used)} used of ${fmtSize(d.total)}${d.files != null ? ` · ${esc(d.files)} files` : ""}</p>`;
  }
  return `<a class="drive" href="#/activity?serial=${encodeURIComponent(d.serial)}">
    <div class="drive-head"><b>${esc(d.label || d.name || "USB drive")}</b>${status}</div>
    ${d.label && d.name ? `<p class="small">${esc(d.name)}</p>` : ""}${body}</a>`;
}

// --- pages ---
const pages = {
  async overview(quiet) {
    const my = gen, d = await api("/api/summary");
    if (my !== gen) return;
    const dm = d.daemon || {};
    const warn = !dm.running ? `<div class="badbox"><b>The monitoring service is not running.</b> Nothing is being logged.
        Start it with <span class="mono">sudo systemctl start usbwatch</span>.</div>`
      : !dm.root ? `<div class="warnbox">The service is not running as root, so drives cannot be blocked.</div>` : "";
    main.innerHTML = head("Overview", `<span class="muted">Policy: <a href="#/drives"><b>${esc(MODES[d.mode]?.[0] || d.mode)}</b></a></span>`) + warn +
      `<h2 class="section">Connected USB drives</h2>
       ${d.drives.length ? `<div class="drives">${d.drives.map(driveCard).join("")}</div>` : `<div class="panel empty">No USB drive is plugged in.</div>`}
       <p class="muted stats">Last 24 hours: <b>${d.to_usb_24h}</b> files written to USB · <b>${d.from_usb_24h}</b> read from USB · <b>${d.deleted_24h}</b> deleted</p>
       <h2 class="section">Latest file activity <a class="small" href="#/activity">See all</a></h2>
       <div class="tbl-wrap" id="ov-recent"></div>`;
    $$("[data-w]").forEach(i => i.style.width = i.dataset.w + "%");
    table($("#ov-recent"), EVENT_COLS, d.recent, { empty: "No file activity yet. Plug in a USB drive and copy a file to see it here." });
    if (!quiet) autoRefresh(pages.overview, my);
  },

  async drives(quiet) {
    const my = gen;
    const [rows, st] = await Promise.all([api("/api/devices"), api("/api/settings")]);
    if (my !== gen) return;
    const search = quiet ? $("#dv-q")?.value || "" : "";
    main.innerHTML = head("USB drives", `<div class="seg" id="dv-mode">${Object.entries(MODES).map(([k, [label]]) =>
        `<button data-m="${k}" class="${st.mode === k ? "on" : ""}">${label}</button>`).join("")}</div>`) +
      `<p class="muted">${esc(MODES[st.mode]?.[1] || "")}</p>
       <div class="row"><input id="dv-q" class="w240" placeholder="Search drives…" aria-label="search" value="${esc(search)}"></div>
       <div class="tbl-wrap" id="dv"></div>`;
    const draw = () => {
      const q = $("#dv-q").value.toLowerCase();
      table($("#dv"), [
        { h: "Drive", f: r => `<b>${esc(r.label || r.name || "(unknown)")}</b>${r.label && r.name ? `<br><span class="muted small">${esc(r.name)}</span>` : ""}` },
        { h: "Status", f: r => r.blocked ? `<span class="pill block">Blocked</span>` : r.connected ? `<span class="pill on">Plugged in</span>` : `<span class="muted">Not connected</span>` },
        { h: "Serial", f: r => `<span class="mono">${esc(r.serial)}</span>` },
        { h: "Size", f: r => fmtSize(r.total), cls: "nowrap" },
        { h: "Last seen", f: r => esc(r.last), cls: "nowrap" },
        { h: "List", f: r => listPill(r.list) },
        { h: "", cls: "nowrap", f: r => (r.list !== "allow" ? `<button class="btn small" data-k="allow" data-s="${esc(r.serial)}">Allow</button> ` : "") +
            (r.list !== "block" ? `<button class="btn danger small" data-k="block" data-s="${esc(r.serial)}">Block</button> ` : "") +
            (r.list ? `<button class="btn ghost small" data-k="" data-s="${esc(r.serial)}">Remove from list</button>` : "") },
      ], rows.filter(r => !q || `${r.name} ${r.label} ${r.serial}`.toLowerCase().includes(q)),
      { onClick: r => location.hash = `#/activity?serial=${encodeURIComponent(r.serial)}`, empty: "No USB drives seen yet. Plug one in." });
    };
    $("#dv-q").oninput = draw; draw();
    $("#dv").addEventListener("click", async e => {
      const b = e.target.closest("button[data-s]"); if (!b) return;
      const r = rows.find(x => x.serial === b.dataset.s);
      try {
        await api("/api/policy", { method: "POST", body: { serials: [r.serial], names: { [r.serial]: r.name }, kind: b.dataset.k || null } });
        toast("Saved."); pages.drives(true);
      } catch (err) { fail(err); }
    });
    $$("#dv-mode button").forEach(b => b.onclick = async () => {
      const m = b.dataset.m;
      if (m === st.mode) return;
      if (m === "whitelist" && !await confirmBox("Only allowed drives will work. Any other USB drive is switched off, including drives plugged in right now.\n\nAllow the drives people need first.", "Allow listed only", true)) return;
      api("/api/settings", { method: "PUT", body: { mode: m } }).then(() => { toast(`Policy: ${MODES[m][0]}.`); pages.drives(true); }).catch(fail);
    });
    if (!quiet) autoRefresh(pages.drives, my, 10000);
  },

  async activity() {
    const my = gen, p = query(), serial = p.get("serial") || "";
    const show = SHOW[p.get("show")] ? p.get("show") : "";
    main.innerHTML = head("Activity", `
        <input id="ac-q" class="w240" placeholder="Search file, user, program…" aria-label="search">
        <select id="ac-show" aria-label="show">${Object.entries(SHOW).map(([k, [label]]) => `<option value="${k}" ${k === show ? "selected" : ""}>${label}</option>`).join("")}</select>
        <button class="btn ghost" id="ac-csv">Export CSV</button>`) +
      (serial ? `<div class="row">Drive <b class="mono">${esc(serial)}</b> <a href="#/activity${show ? "?show=" + show : ""}">show all drives</a></div>` : "") +
      `<div class="tbl-wrap" id="ac"></div><div class="more"><button class="btn ghost hidden" id="ac-more">Load more</button></div>`;
    let rows = [];
    const params = before => {
      const u = new URLSearchParams({ q: $("#ac-q").value, serial, ...(SHOW[$("#ac-show").value][1] || {}) });
      if (before) u.set("before", before);
      return u;
    };
    const load = async more => {
      if ($("#ac-show").value === "deleted") return loadDeleted();
      const d = await api("/api/events?" + params(more && rows.length ? rows[rows.length - 1].id : 0));
      if (my !== gen) return;
      rows = more ? rows.concat(d.rows) : d.rows;
      table($("#ac"), EVENT_COLS, rows, { empty: "Nothing matches." });
      $("#ac-more").classList.toggle("hidden", !d.more);
    };
    const loadDeleted = async () => {
      const d = (await api("/api/deleted?" + new URLSearchParams({ q: $("#ac-q").value }))).filter(r => !serial || r.serial === serial);
      if (my !== gen) return;
      table($("#ac"), [...EVENT_COLS.slice(0, 4), EVENT_COLS[6],
        { h: "", f: r => r.vid ? `<button class="btn small" data-vid="${r.vid}">Restore</button>` : "" }],
        d, { empty: "No deleted files recorded." });
      $("#ac-more").classList.add("hidden");
    };
    let t;
    $("#ac-q").oninput = () => { clearTimeout(t); t = setTimeout(() => load().catch(fail), 300); };
    $("#ac-show").onchange = () => {
      const u = new URLSearchParams(); if (serial) u.set("serial", serial); if ($("#ac-show").value) u.set("show", $("#ac-show").value);
      history.replaceState(null, "", "#/activity" + (u.toString() ? "?" + u : ""));
      load().catch(fail);
    };
    $("#ac-more").onclick = () => load(true).catch(fail);
    $("#ac-csv").onclick = () => location.href = "/api/events.csv?" + params();
    $("#ac").addEventListener("click", async e => {
      const b = e.target.closest("button[data-vid]"); if (!b) return;
      try {
        const { id } = await api("/api/commands", { method: "POST", body: { cmd: "restore", args: { vid: +b.dataset.vid } } });
        toast("Restoring…");
        for (let i = 0; i < 20; i++) {
          await new Promise(r => setTimeout(r, 700));
          const c = (await api("/api/commands")).find(x => x.id === id);
          if (c && c.done) return toast(c.result, !c.ok);
        }
        toast("Restore is taking long. Is the service running?", true);
      } catch (err) { fail(err); }
    });
    await load();
    autoRefresh(async () => { if (rows.length <= 200 && !$("#ac-q").value && $("#ac-show").value !== "deleted") await load(); }, my, 5000);
  },

  async settings() {
    const my = gen, st = await api("/api/settings");
    if (my !== gen) return;
    const w = st.web;
    main.innerHTML = head("Settings") +
      `<div class="panel"><h2>Monitoring</h2>
        <label class="sw"><input type="checkbox" id="s-reads" ${st.log_reads ? "checked" : ""}> Log files read or copied from USB drives</label>
        <label class="sw"><input type="checkbox" id="s-exec" ${st.log_exec ? "checked" : ""}> Log programs run from USB drives</label>
        <div class="row"><label>Keep activity for <input id="s-ret" type="number" min="1" max="3650" class="w100" value="${st.retention_days}"> days</label></div>
        <details><summary>Advanced</summary>
          <div class="row"><label>Report the same file read by the same program at most every <input id="s-dedup" type="number" min="0" class="w80" value="${st.read_dedup_s}"> seconds</label></div>
          <div class="row"><label>Store a SHA-256 hash of files written to USB, up to <input id="s-hash" type="number" min="0" class="w100" value="${st.hash_max_mb}"> MB (0 = off)</label></div>
          <label class="muted small" for="s-ign">Ignore reads by these programs (file indexers, thumbnailers), comma separated</label>
          <textarea id="s-ign">${esc(st.ignore_processes)}</textarea>
        </details>
        <div class="row"><button class="btn" id="s-save">Save</button></div></div>

       <div class="panel"><h2>Recovery copies</h2>
        <p class="muted">Keep a private copy of files written to USB drives, so deleted files can be restored. Only root can read the copies.</p>
        <label class="sw"><input type="checkbox" id="v-on" ${st.vault_on ? "checked" : ""}> Keep recovery copies</label>
        <div class="row"><label>Largest file <input id="v-max" type="number" min="1" class="w100" value="${st.vault_max_mb}"> MB</label>
          <label>Total space <input id="v-cap" type="number" min="1" class="w80" value="${st.vault_cap_gb}"> GB</label>
          <span class="muted small">In use: ${st.vault.n} files, ${fmtSize(st.vault.size) || "0 B"}</span></div>
        <button class="btn" id="v-save">Save</button></div>

       <div class="panel"><h2>Change your password</h2>
        <div class="row"><input id="pw-old" type="password" placeholder="Current password" autocomplete="current-password" aria-label="current password">
          <input id="pw-new" type="password" placeholder="New (10+ characters)" autocomplete="new-password" aria-label="new password">
          <input id="pw-new2" type="password" placeholder="Repeat new" autocomplete="new-password" aria-label="repeat new password">
          <button class="btn" id="pw-save">Change</button></div></div>

       <details class="panel" id="au-box"><summary>Audit log</summary>
        <p class="muted small">Every sign-in and every change made in the console or on the command line.</p>
        <div class="tbl-wrap maxh" id="au"></div></details>

       <p class="muted small">Version ${esc(st.version)} · console on ${w.bind.map(esc).join(", ")}:${esc(w.port)} (${w.tls ? "HTTPS" : "HTTP"}) ·
        network access is set in <span class="mono">${esc(st.conf_file)}</span></p>`;
    $("#s-save").onclick = () => api("/api/settings", { method: "PUT", body: {
        log_reads: $("#s-reads").checked, log_exec: $("#s-exec").checked, read_dedup_s: +$("#s-dedup").value,
        hash_max_mb: +$("#s-hash").value, retention_days: +$("#s-ret").value, ignore_processes: $("#s-ign").value } })
      .then(() => toast("Saved.")).catch(fail);
    $("#v-save").onclick = async () => {
      if ($("#v-on").checked && !st.vault_on && !await confirmBox("Copies of files written to USB drives will be kept on this computer. Turn this on only where you are allowed to keep that data.", "Turn on")) return;
      api("/api/settings", { method: "PUT", body: { vault_on: $("#v-on").checked, vault_max_mb: +$("#v-max").value, vault_cap_gb: +$("#v-cap").value } })
        .then(() => toast("Saved.")).catch(fail);
    };
    $("#pw-save").onclick = () => {
      if ($("#pw-new").value !== $("#pw-new2").value) return toast("The new passwords do not match.", true);
      api("/api/password", { method: "POST", body: { old: $("#pw-old").value, new: $("#pw-new").value } })
        .then(() => { toast("Password changed. Please sign in again."); setTimeout(showLogin, 1200); }).catch(fail);
    };
    $("#au-box").addEventListener("toggle", async e => {
      if (!e.target.open) return;
      try {
        table($("#au"), [{ h: "Time", f: r => esc(when(r.ts)), cls: "nowrap" }, { h: "By", f: r => esc(r.who) },
          { h: "From", f: r => esc(r.ip) }, { h: "Action", f: r => esc(r.action) }, { h: "Detail", f: r => esc(r.detail), cls: "path" }],
          await api("/api/audit"));
      } catch (err) { fail(err); }
    });
  },
};

// --- router / auth ---
async function render() {
  const my = ++gen;
  clearInterval(timer);
  const [path] = location.hash.replace(/^#\/?/, "").split("?");
  const name = pages[path] ? path : "overview";
  $$("#nav a").forEach(a => a.classList.toggle("active", a.dataset.page === name));
  main.innerHTML = `<div class="empty">Loading…</div>`;
  try {
    await pages[name](false);
  } catch (e) {
    if (my === gen && e.message !== "Not signed in") main.innerHTML = `<div class="empty err">${esc(e.message)}</div>`;
  }
}
function showLogin() {
  clearInterval(timer);
  $("#shell").classList.add("hidden");
  $("#login").classList.remove("hidden");
  $("#login-pw").value = "";
  $("#login-pw").focus();
}
function showApp(me) {
  $("#login").classList.add("hidden");
  $("#shell").classList.remove("hidden");
  $("#side-status").textContent = `Signed in as ${me.user}`;
  if (me.initial_pw) toast("You are using the generated first password. Please change it under Settings.", true);
  render();
}
$("#login-form").onsubmit = async e => {
  e.preventDefault();
  $("#login-msg").textContent = "";
  try {
    await api("/api/login", { method: "POST", body: { user: $("#login-user").value, password: $("#login-pw").value }, login: true });
    showApp(await api("/api/me"));
  } catch (err) { $("#login-msg").textContent = err.message; }
};
$("#logout").onclick = () => api("/api/logout", { method: "POST" }).finally(showLogin);
document.addEventListener("keydown", e => { if (e.key === "Escape" && !$("#modal").classList.contains("hidden")) $("#modal-no").click(); });
window.addEventListener("hashchange", () => { if (!$("#shell").classList.contains("hidden")) render(); });
api("/api/me", { login: true }).then(showApp).catch(showLogin);
