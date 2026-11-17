"use strict";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const main = $("#main");
const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const ACTIONS = ["Connected", "Disconnected", "Mounted", "Unmounted", "Created", "Modified", "Read", "Executed", "Deleted",
  "Renamed/Moved", "Deleted (offline)", "Restored", "Blocked", "Block failed", "Unblocked", "Unblock failed",
  "Policy applied", "Watch limit", "Event overflow", "Service started", "Service stopped"];
const CATEGORIES = { device: "Devices", volume: "Mounts", file: "Files", policy: "Policy", system: "System" };
const MODES = { off: "Off (log only)", blacklist: "Blacklist", whitelist: "Whitelist only" };
const SCOPES = { storage: "USB mass storage", "storage+mtp": "Mass storage + phones/cameras (MTP/PTP)", all: "All USB devices (except hubs)" };
let gen = 0, timer = null;

// ---------- helpers ----------
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
const dirCell = d => d === "to USB" ? `<span class="pill to">→ to USB</span>` : d === "from USB" ? `<span class="pill from">← from USB</span>` : "";
const listPill = k => k ? `<span class="pill ${esc(k)}">${k === "allow" ? "Whitelist" : "Blacklist"}</span>` : "—";
const devLink = r => r.serial ? `<a href="#/activity?serial=${encodeURIComponent(r.serial)}">${esc(r.device || r.name || r.serial)}</a>` : "";
const who = r => r.user ? esc(r.user) + (r.login ? ` <span class="muted">(${esc(r.login)})</span>` : "") : "";
const proc = r => r.process ? `<span title="${esc(r.cmdline)}">${esc(r.process)}<span class="muted">[${esc(r.pid)}]</span></span>` : "";
function query() {
  const i = location.hash.indexOf("?");
  return new URLSearchParams(i < 0 ? "" : location.hash.slice(i + 1));
}
const head = (title, tools = "") => `<div class="head"><h1>${esc(title)}</h1><div class="tools">${tools}</div></div>`;
const cards = items => `<div class="cards">${items.map(([v, l]) => `<div class="card"><div class="v">${esc(v)}</div><div class="l">${esc(l)}</div></div>`).join("")}</div>`;
function driveCards(mounts) {
  if (!mounts.length) return `<p class="muted">No USB drive mounted right now.</p>`;
  return `<div class="drives">${mounts.map(d => {
    const used = (d.total || 0) - (d.free || 0), ratio = d.total ? used / d.total : 0;
    const watch = d.watched < 0 ? ` · <span class="a-Watchlimit">partly watched (${-d.watched} folders)</span>` : ` · ${d.watched || 0} folders watched`;
    return `<div class="drive"><b>${esc(d.mount)} · ${esc(d.label || d.name || "USB drive")} · ${esc(d.fs)}</b>
      <div class="bar"><i class="${ratio > .9 ? "full" : ""}" data-w="${(ratio * 100).toFixed(1)}"></i></div>
      <span class="muted small">${fmtSize(used)} used · ${fmtSize(d.free)} free · ${fmtSize(d.total)} total · ${d.files ?? "?"} files${watch}<br>
      <span class="mono">${esc(d.serial)}</span> · ${esc(d.source)}</span>
      <div class="row"><button class="btn dark small" data-rescan="${esc(d.mount)}">Re-index</button></div></div>`;
  }).join("")}</div>`;
}
function applyBars(root = main) { $$("[data-w]", root).forEach(i => i.style.width = i.dataset.w + "%"); }

/** Render a table into `el`. cols: [{h, f(row) -> html, cls}] */
function table(el, cols, rows, opts = {}) {
  if (!rows.length) { el.innerHTML = `<div class="empty">${esc(opts.empty || "Nothing here yet.")}</div>`; return; }
  const sel = opts.select;
  el.innerHTML = `<table><thead><tr>${sel ? `<th><input type="checkbox" data-all aria-label="select all"></th>` : ""}${cols.map(c => `<th>${esc(c.h)}</th>`).join("")}</tr></thead>
    <tbody>${rows.map((r, i) => `<tr data-i="${i}" class="${opts.onClick ? "click" : ""}">${sel ? `<td><input type="checkbox" data-i="${i}"></td>` : ""}${cols.map(c => `<td class="${c.cls || ""}">${c.f(r) ?? ""}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
  if (opts.onClick) el.querySelector("tbody").addEventListener("click", e => {
    if (e.target.closest("a,button,input")) return;
    const tr = e.target.closest("tr"); if (tr) opts.onClick(rows[tr.dataset.i]);
  });
  if (sel) {
    el.querySelector("[data-all]").addEventListener("change", e => $$("tbody input[type=checkbox]", el).forEach(c => c.checked = e.target.checked));
    el.selected = () => $$("tbody input[type=checkbox]:checked", el).map(c => rows[c.dataset.i]);
  }
}
function autoRefresh(fn, my, ms = 5000) {
  clearInterval(timer);
  timer = setInterval(() => {
    if (my !== gen || document.hidden || document.activeElement?.matches("input,select,textarea")) return;
    fn(true).catch(() => {});
  }, ms);
}
function rescanHandler(root) {
  root.addEventListener("click", e => {
    const b = e.target.closest("[data-rescan]"); if (!b) return;
    api("/api/commands", { method: "POST", body: { cmd: "rescan", args: { mount: b.dataset.rescan } } })
      .then(() => toast("Re-index requested.")).catch(fail);
  });
}

const EVENT_COLS = [
  { h: "Time", f: r => esc(r.ts), cls: "nowrap" },
  { h: "Action", f: r => actCell(r.action), cls: "nowrap" },
  { h: "Direction", f: r => dirCell(r.direction), cls: "nowrap" },
  { h: "Path / device", f: r => esc(r.path) + (r.dest ? `<br><span class="muted">→ ${esc(r.dest)}</span>` : "") + (r.detail ? `<br><span class="muted small">${esc(r.detail)}</span>` : ""), cls: "path" },
  { h: "Size", f: r => fmtSize(r.size), cls: "nowrap" },
  { h: "User", f: who, cls: "nowrap" },
  { h: "Process", f: proc, cls: "nowrap" },
  { h: "USB device", f: devLink },
  { h: "SHA-256", f: r => r.sha256 ? `<span class="mono" title="${esc(r.sha256)}">${esc(r.sha256.slice(0, 12))}…</span>` : "" },
];

// ---------- pages ----------
const pages = {
  async overview(quiet) {
    const my = gen, d = await api("/api/summary");
    if (my !== gen) return;
    const dm = d.daemon || {};
    const warn = !dm.running ? `<div class="badbox"><b>The monitoring service is not running.</b> Nothing is being logged or enforced.
        Start it with <span class="mono">sudo systemctl start usbwatch</span> (or your init system's equivalent).</div>`
      : (!dm.root ? `<div class="warnbox">The service is not running as root: devices cannot be blocked.</div>` : "")
        + (dm.fanotify && dm.fanotify !== "ok" ? `<div class="warnbox">Process attribution is unavailable (${esc(dm.fanotify)}). File events will not name the user/process and reads are not logged.</div>` : "");
    main.innerHTML = head("Overview", `<span class="muted">Policy: <b>${esc(MODES[d.mode])}</b> · ${esc(SCOPES[d.scope])}</span>`) + warn +
      cards([[d.attached.length, "USB devices connected"], [d.mounts.length, "USB drives mounted"], [d.devices, `USB devices known (${d.storage_devices} storage)`],
             [d.to_usb_24h, "Files written to USB (24 h)"], [d.from_usb_24h, "Files read from USB (24 h)"],
             [d.deleted_24h, "Files deleted (24 h)"], [d.blocked, "Devices blocked now"]]) +
      `<div class="panel"><h2>Mounted USB drives</h2>${driveCards(d.mounts)}</div>
       <div class="panel"><h2>Connected USB devices</h2><div id="ov-att"></div></div>
       <div class="panel"><h2>Alerts</h2><div id="ov-alerts"></div></div>
       <div class="panel"><h2>Latest file activity <a class="small" href="#/activity">view all</a></h2><div class="tbl-wrap" id="ov-recent"></div></div>
       <p class="muted small">Service ${dm.running ? `<span class="dot on"></span>running since ${esc(when(dm.started))}` : `<span class="dot off"></span>stopped`}
        · kernel ${esc(dm.kernel)} · ${esc(dm.arch)} · Python ${esc(dm.python)} · fanotify ${esc(dm.fanotify)}${dm.exec_events ? " (+exec)" : ""} · netlink ${esc(dm.netlink)} · inotify watches ${esc(dm.watches)} / ${esc(dm.inotify_limit)}</p>`;
    applyBars();
    rescanHandler($(".drives") || main);
    table($("#ov-att"), [
      { h: "Device", f: r => `<b>${esc(r.name || "(unknown)")}</b>${r.blocked ? ` <span class="pill block">blocked</span>` : ""}` },
      { h: "Serial", f: r => `<a class="mono" href="#/activity?serial=${encodeURIComponent(r.serial)}">${esc(r.serial)}</a>` },
      { h: "VID:PID", f: r => `<span class="mono">${esc(r.vid)}:${esc(r.pid)}</span>` },
      { h: "Classes", f: r => esc(r.classes) + (r.storage ? ` <span class="pill">storage</span>` : "") },
      { h: "List", f: r => listPill(r.list) },
      { h: "Connected since", f: r => esc(r.ts), cls: "nowrap" },
    ], d.attached, { empty: "No USB devices connected." });
    table($("#ov-alerts"), [{ h: "Time", f: r => esc(r.ts), cls: "nowrap" }, { h: "Action", f: r => actCell(r.action) },
      { h: "Device", f: devLink }, { h: "Detail", f: r => esc(r.detail || r.path), cls: "path" }],
      d.alerts, { empty: "No alerts." });
    table($("#ov-recent"), EVENT_COLS, d.recent, { empty: "No file activity yet. Plug in a USB drive to get started." });
    if (!quiet) autoRefresh(pages.overview, my);
  },

  async devices() {
    const my = gen, rows = await api("/api/devices");
    if (my !== gen) return;
    main.innerHTML = head("USB Devices", `
        <input id="dv-q" class="w240" placeholder="Search name / serial / VID / PID…" aria-label="search">
        <label class="sw"><input type="checkbox" id="dv-st"> storage only</label>`) +
      `<div class="row"><span class="muted">Selected:</span>
        <button class="btn small" data-k="allow">Allow (whitelist)</button>
        <button class="btn danger small" data-k="block">Block (blacklist)</button>
        <button class="btn dark small" data-k="">Remove from list</button>
        <button class="btn dark small" id="dv-hist">Re-read kernel history</button></div>
       <div class="tbl-wrap" id="dv"></div>`;
    const draw = () => {
      const q = $("#dv-q").value.toLowerCase(), st = $("#dv-st").checked;
      table($("#dv"), [
        { h: "Name", f: r => `<b>${esc(r.name || "(unknown)")}</b>${r.connected ? ` <span class="pill allow">connected</span>` : ""}${r.blocked ? ` <span class="pill block">blocked</span>` : ""}` },
        { h: "Serial (unique ID)", f: r => `<span class="mono">${esc(r.serial)}</span>` },
        { h: "VID:PID", f: r => `<span class="mono">${esc(r.vid)}:${esc(r.pid)}</span>` },
        { h: "Vendor", f: r => esc(r.vendor) }, { h: "Product", f: r => esc(r.product) },
        { h: "Type", f: r => r.storage ? "Mass storage" : esc(r.classes) },
        { h: "Capacity", f: r => fmtSize(r.total), cls: "nowrap" },
        { h: "First seen", f: r => esc(r.first), cls: "nowrap" }, { h: "Last seen", f: r => esc(r.last), cls: "nowrap" },
        { h: "Last removed", f: r => esc(r.removed), cls: "nowrap" }, { h: "Times", f: r => esc(r.times) },
        { h: "File events", f: r => esc(r.file_events) }, { h: "List", f: r => listPill(r.list) },
      ], rows.filter(r => (!st || r.storage) && (!q || `${r.name} ${r.serial} ${r.vid} ${r.pid} ${r.vendor} ${r.product}`.toLowerCase().includes(q))),
      { select: true, onClick: r => location.hash = `#/activity?serial=${encodeURIComponent(r.serial)}`, empty: "No USB devices recorded yet." });
    };
    $("#dv-q").oninput = draw; $("#dv-st").onchange = draw; draw();
    $("#dv-hist").onclick = () => api("/api/commands", { method: "POST", body: { cmd: "refresh_history" } }).then(() => toast("Reading the kernel log…")).catch(fail);
    $$("[data-k]").forEach(b => b.onclick = async () => {
      const sel = $("#dv").selected?.() || [];
      if (!sel.length) return toast("Tick one or more devices first.", true);
      const names = Object.fromEntries(sel.map(r => [r.serial, r.name]));
      try {
        await api("/api/policy", { method: "POST", body: { serials: Object.keys(names), names, kind: b.dataset.k || null } });
        toast("Saved. Applied within a second."); render();
      } catch (e) { fail(e); }
    });
  },

  async activity(_q, preset = {}) {
    const my = gen, p = query();
    for (const [k, v] of Object.entries(preset)) if (!p.has(k)) p.set(k, v);
    const title = preset.direction ? "Transfers" : "File Activity";
    main.innerHTML = head(title, `
        <input id="ac-q" class="w240" placeholder="Search path, process, user…" value="${esc(p.get("q") || "")}" aria-label="search">
        <select id="ac-cat"><option value="">All categories</option>${Object.entries(CATEGORIES).map(([k, v]) => `<option value="${k}" ${p.get("category") === k ? "selected" : ""}>${v}</option>`).join("")}</select>
        <select id="ac-act"><option value="">All actions</option>${ACTIONS.map(a => `<option ${p.get("action") === a ? "selected" : ""}>${esc(a)}</option>`).join("")}</select>
        <select id="ac-dir"><option value="">Any direction</option><option value="both" ${p.get("direction") === "both" ? "selected" : ""}>⇄ transfers only</option><option value="to USB" ${p.get("direction") === "to USB" ? "selected" : ""}>→ written to USB</option><option value="from USB" ${p.get("direction") === "from USB" ? "selected" : ""}>← read from USB</option></select>
        <input id="ac-user" class="w100" placeholder="user" value="${esc(p.get("user") || "")}" aria-label="user">
        <label class="muted">from <input id="ac-since" type="date" value="${esc(p.get("since") || "")}"></label>
        <label class="muted">to <input id="ac-until" type="date" value="${esc(p.get("until") || "")}"></label>
        <button class="btn dark" id="ac-csv">Export CSV</button>`) +
      (preset.direction ? `<p class="muted">Files copied/saved <b>to</b> USB drives (Created, Modified, Restored) and files opened/copied <b>from</b> them (Read, Executed), with the user and process responsible.</p>` : "") +
      (p.get("serial") ? `<div class="row">USB device <b class="mono">${esc(p.get("serial"))}</b> <a href="#/${preset.direction ? "transfers" : "activity"}">clear filter</a></div>` : "") +
      `<div class="tbl-wrap" id="ac"></div><div class="more"><button class="btn dark hidden" id="ac-more">Load more</button></div>`;
    let rows = [];
    const params = before => {
      const u = new URLSearchParams({ q: $("#ac-q").value, category: $("#ac-cat").value, action: $("#ac-act").value,
        direction: $("#ac-dir").value, user: $("#ac-user").value, since: $("#ac-since").value, until: $("#ac-until").value,
        serial: p.get("serial") || "" });
      if (before) u.set("before", before);
      return u;
    };
    const load = async more => {
      const d = await api("/api/events?" + params(more && rows.length ? rows[rows.length - 1].id : 0));
      if (my !== gen) return;
      rows = more ? rows.concat(d.rows) : d.rows;
      table($("#ac"), EVENT_COLS, rows, { empty: "No matching events." });
      $("#ac-more").classList.toggle("hidden", !d.more);
    };
    let t;
    $("#ac-q").oninput = $("#ac-user").oninput = () => { clearTimeout(t); t = setTimeout(() => load().catch(fail), 300); };
    ["#ac-cat", "#ac-act", "#ac-dir", "#ac-since", "#ac-until"].forEach(s => $(s).onchange = () => load().catch(fail));
    $("#ac-more").onclick = () => load(true).catch(fail);
    $("#ac-csv").onclick = () => location.href = "/api/events.csv?" + params();
    await load();
    autoRefresh(async () => { if (rows.length <= 200 && !$("#ac-q").value) await load(); }, my, 5000);
  },

  transfers(q) { return pages.activity(q, { direction: "both" }); },

  async deleted() {
    const my = gen, rows = await api("/api/deleted");
    if (my !== gen) return;
    main.innerHTML = head("Deleted Files", `<input id="dl-q" class="w240" placeholder="Search…" aria-label="search">`) +
      `<p class="muted">Files deleted from USB drives. "Deleted (offline)" = missing since the drive was last seen on this computer.
       A file can be restored when the recovery vault holds a copy (Settings → Recovery vault) and the drive is plugged in.</p><div class="tbl-wrap" id="dl"></div>`;
    const draw = () => {
      const q = $("#dl-q").value.toLowerCase();
      table($("#dl"), [
        { h: "Time", f: r => esc(r.ts), cls: "nowrap" }, { h: "Action", f: r => actCell(r.action), cls: "nowrap" },
        { h: "USB device", f: devLink }, { h: "Path", f: r => esc(r.path), cls: "path" },
        { h: "Size", f: r => fmtSize(r.size), cls: "nowrap" },
        { h: "Recoverable", f: r => r.vid ? `<button class="btn small" data-vid="${r.vid}">Restore</button>` : `<span class="muted">No</span>` },
      ], rows.filter(r => !q || `${r.path} ${r.device} ${r.serial}`.toLowerCase().includes(q)), { empty: "No deleted files recorded." });
    };
    $("#dl-q").oninput = draw; draw();
    $("#dl").addEventListener("click", async e => {
      const b = e.target.closest("button[data-vid]"); if (!b) return;
      try {
        const { id } = await api("/api/commands", { method: "POST", body: { cmd: "restore", args: { vid: +b.dataset.vid } } });
        toast("Restoring…");
        for (let i = 0; i < 20; i++) {
          await new Promise(r => setTimeout(r, 700));
          const c = (await api("/api/commands")).find(x => x.id === id);
          if (c && c.done) return toast(c.result, !c.ok);
        }
        toast("Restore is taking long; is the service running?", true);
      } catch (err) { fail(err); }
    });
  },

  async access() {
    const my = gen;
    const [st, pol] = await Promise.all([api("/api/settings"), api("/api/policy")]);
    if (my !== gen) return;
    main.innerHTML = head("Access Control", `<div class="seg" id="ac-mode">${Object.entries(MODES).map(([k, v]) =>
      `<button data-m="${k}" class="${st.mode === k ? "on" : ""}">${v}</button>`).join("")}</div>`) +
      `<p class="muted"><b>Off</b>: log only. <b>Blacklist</b>: listed devices are disabled the moment they are plugged in.
       <b>Whitelist only</b>: every device in scope that is NOT whitelisted is disabled. Blocking deauthorizes the device in the kernel
       before it can be mounted; it is re-checked on every replug. Keyboards/mice are never blocked unless the scope is "All USB devices".</p>
       <div class="panel"><h2>Policy applies to</h2><div class="row"><select id="ac-scope">${Object.entries(SCOPES).map(([k, v]) =>
        `<option value="${k}" ${st.policy_scope === k ? "selected" : ""}>${v}</option>`).join("")}</select></div></div>
       <div class="panel"><h2>Add a device by serial</h2><div class="row">
        <input id="ac-serial" class="grow" placeholder="Serial (as shown in USB Devices)">
        <input id="ac-name" class="grow" placeholder="Name / owner (optional)">
        <select id="ac-kind"><option value="allow">Whitelist</option><option value="block">Blacklist</option></select>
        <button class="btn" id="ac-add">Add</button></div>
        <p class="muted small">Tip: tick devices on <a href="#/devices">USB Devices</a> instead of typing serials.</p></div>
       <div class="tbl-wrap" id="ac-list"></div>`;
    table($("#ac-list"), [
      { h: "Name", f: r => esc(r.name || r.device) || "<span class='muted'>(unnamed)</span>" },
      { h: "Serial", f: r => `<span class="mono">${esc(r.serial)}</span>` + (r.connected ? ` <span class="pill allow">connected</span>` : "") },
      { h: "List", f: r => listPill(r.kind) }, { h: "Last seen", f: r => esc(r.last) },
      { h: "Added", f: r => esc(when(r.ts)), cls: "nowrap" },
      { h: "", f: r => `<button class="btn dark small" data-rm="${esc(r.serial)}">Remove</button>` },
    ], pol, { empty: "The whitelist and blacklist are empty." });
    $("#ac-list").addEventListener("click", e => {
      const b = e.target.closest("[data-rm]"); if (!b) return;
      api("/api/policy", { method: "POST", body: { serials: [b.dataset.rm], kind: null } }).then(render).catch(fail);
    });
    $("#ac-add").onclick = () => {
      const serial = $("#ac-serial").value.trim();
      if (!serial) return toast("Enter a serial.", true);
      api("/api/policy", { method: "POST", body: { serials: [serial], name: $("#ac-name").value, kind: $("#ac-kind").value } }).then(render).catch(fail);
    };
    $("#ac-scope").onchange = async e => {
      if (e.target.value === "all" && st.mode !== "off" && !await confirmBox("Scope 'All USB devices' can disable keyboards, mice and other peripherals that are not whitelisted. Continue?", "Continue", true)) { e.target.value = st.policy_scope; return; }
      api("/api/settings", { method: "PUT", body: { policy_scope: e.target.value } }).then(() => { toast("Scope saved."); render(); }).catch(fail);
    };
    $$("#ac-mode button").forEach(b => b.onclick = async () => {
      const m = b.dataset.m;
      if (m === st.mode) return;
      if (m === "whitelist" && !await confirmBox("Whitelist-only mode disables EVERY device in scope that is not on the whitelist — including ones plugged in right now.\n\nWhitelist the devices people need first.", "Enable whitelist mode", true)) return;
      api("/api/settings", { method: "PUT", body: { mode: m } }).then(() => { toast(`Mode set to ${MODES[m]}.`); render(); }).catch(fail);
    });
  },

  async audit() {
    const my = gen, [rows, cmds] = await Promise.all([api("/api/audit"), api("/api/commands")]);
    if (my !== gen) return;
    main.innerHTML = head("Audit Log") + `<p class="muted">Every sign-in and every change made through the console or the command line.</p>
      <div class="tbl-wrap" id="au"></div><h2 class="mt">Commands sent to the service</h2><div class="tbl-wrap maxh" id="cm"></div>`;
    table($("#au"), [{ h: "Time", f: r => esc(when(r.ts)), cls: "nowrap" }, { h: "By", f: r => esc(r.who) }, { h: "From", f: r => esc(r.ip) },
      { h: "Action", f: r => esc(r.action) }, { h: "Detail", f: r => esc(r.detail), cls: "path" }], rows);
    table($("#cm"), [{ h: "Created", f: r => esc(when(r.created)), cls: "nowrap" }, { h: "By", f: r => esc(r.user) },
      { h: "Command", f: r => esc(r.cmd) + " " + esc(r.args === "{}" ? "" : r.args) },
      { h: "State", f: r => r.done ? (r.ok ? "<span class='a-Created'>done</span>" : "<span class='a-Deleted'>failed</span>") : "queued" },
      { h: "Result", f: r => esc(r.result) }], cmds, { empty: "No commands yet." });
  },

  async settings() {
    const my = gen, st = await api("/api/settings");
    if (my !== gen) return;
    const w = st.web;
    main.innerHTML = head("Settings") +
      `<div class="grid2"><div class="panel"><h2>Monitoring</h2>
        <label class="sw"><input type="checkbox" id="s-reads" ${st.log_reads ? "checked" : ""}> Log files read / copied <b>from</b> USB drives</label>
        <label class="sw"><input type="checkbox" id="s-exec" ${st.log_exec ? "checked" : ""}> Log programs executed from USB drives (kernel 5.0+)</label>
        <div class="row"><label>Report the same file read by the same process at most every <input id="s-dedup" type="number" min="0" class="w80" value="${st.read_dedup_s}"> s</label></div>
        <div class="row"><label>SHA-256 of files written to USB up to <input id="s-hash" type="number" min="0" class="w100" value="${st.hash_max_mb}"> MB (0 = off)</label></div>
        <div class="row"><label>Keep events for <input id="s-ret" type="number" min="1" max="3650" class="w100" value="${st.retention_days}"> days</label></div>
        <label class="muted small" for="s-ign">Ignore reads by these processes (indexers, thumbnailers), comma separated</label>
        <textarea id="s-ign">${esc(st.ignore_processes)}</textarea>
        <div class="row"><button class="btn" id="s-save">Save</button></div></div>

       <div class="panel"><h2>Recovery vault</h2>
        <p class="muted">Keeps a private local copy of files written to USB drives so deleted files can be restored.
        Copies are readable by root only. Enable only where you are allowed to keep that data.</p>
        <label class="sw"><input type="checkbox" id="v-on" ${st.vault_on ? "checked" : ""}> Keep recovery copies</label>
        <div class="row"><label>Max file size <input id="v-max" type="number" min="1" class="w100" value="${st.vault_max_mb}"> MB</label>
          <label>Total limit <input id="v-cap" type="number" min="1" class="w80" value="${st.vault_cap_gb}"> GB</label></div>
        <p class="muted small">In use: ${st.vault.n} file(s), ${fmtSize(st.vault.size) || "0 B"}</p>
        <button class="btn" id="v-save">Save</button></div></div>

       <div class="grid2"><div class="panel"><h2>Change your password</h2>
        <div class="row"><input id="pw-old" type="password" placeholder="Current" autocomplete="current-password" aria-label="current password"></div>
        <div class="row"><input id="pw-new" type="password" placeholder="New (10+ chars)" autocomplete="new-password" aria-label="new password">
          <input id="pw-new2" type="password" placeholder="Repeat" autocomplete="new-password" aria-label="repeat new password">
          <button class="btn" id="pw-save">Change</button></div>
        <h2 class="mt">Console users</h2>
        <dl class="kv">${st.users.map(u => `<dt>${esc(u.name)}</dt><dd>last sign-in ${esc(when(u.last_login) || "never")}</dd>`).join("")}</dl>
        <p class="muted small">Add / remove users as root: <span class="mono">sudo usbwatch passwd NAME</span>, <span class="mono">sudo usbwatch userdel NAME</span></p></div>

       <div class="panel"><h2>Console access <span class="muted small">(read-only here)</span></h2>
        <dl class="kv"><dt>Listening on</dt><dd class="mono">${w.bind.map(esc).join(", ")} port ${esc(w.port)} (${w.tls ? "HTTPS" : "HTTP"})</dd>
        <dt>Allowed clients</dt><dd class="mono">${w.allow.map(esc).join(", ") || "loopback only"}</dd>
        <dt>Extra host names</dt><dd class="mono">${w.allowed_hosts.map(esc).join(", ") || "—"}</dd>
        <dt>Session timeout</dt><dd>${esc(w.session_hours)} h of inactivity</dd>
        <dt>Event log file</dt><dd class="mono">${esc(st.events_file || "off")}${st.syslog ? " + syslog" : ""}</dd>
        <dt>Config file</dt><dd class="mono">${esc(st.conf_file)}</dd><dt>Data</dt><dd class="mono">${esc(st.data_dir)}</dd>
        <dt>Version</dt><dd>${esc(st.version)}</dd></dl>
        <p class="muted small">To let other computers open this console, edit <span class="mono">[web] bind / allow</span> in the config file as root
        (TLS recommended) and restart <span class="mono">usbwatch-web</span>. The console cannot change its own exposure.</p></div></div>`;
    $("#s-save").onclick = () => api("/api/settings", { method: "PUT", body: {
        log_reads: $("#s-reads").checked, log_exec: $("#s-exec").checked, read_dedup_s: +$("#s-dedup").value,
        hash_max_mb: +$("#s-hash").value, retention_days: +$("#s-ret").value, ignore_processes: $("#s-ign").value } })
      .then(() => toast("Saved.")).catch(fail);
    $("#v-save").onclick = async () => {
      if ($("#v-on").checked && !st.vault_on && !await confirmBox("A private copy of files written to USB drives will be kept on this computer (within the limits). Enable only on computers you own or are authorized to monitor, and only for data you are allowed to keep.", "Enable vault")) return;
      api("/api/settings", { method: "PUT", body: { vault_on: $("#v-on").checked, vault_max_mb: +$("#v-max").value, vault_cap_gb: +$("#v-cap").value } })
        .then(() => toast("Saved.")).catch(fail);
    };
    $("#pw-save").onclick = () => {
      if ($("#pw-new").value !== $("#pw-new2").value) return toast("New passwords do not match.", true);
      api("/api/password", { method: "POST", body: { old: $("#pw-old").value, new: $("#pw-new").value } })
        .then(() => { toast("Password changed. Sign in again."); setTimeout(showLogin, 1200); }).catch(fail);
    };
  },
};

// ---------- router / auth ----------
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
  $("#side-status").textContent = `${me.user} · v${me.version}`;
  if (me.initial_pw) toast("You are using the generated initial password — change it under Settings.", true);
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
