// Dependency-free UI. All server data is inserted with textContent / value only
// (never innerHTML), so stored values cannot inject markup or script.
const API = "/api";
let token = null;           // kept in memory only; a reload requires logging in again
let me = null;
const root = document.getElementById("app");

function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else if (k === "style") el.style.cssText = v;  // CSSOM write: allowed under a strict CSP
    else if (v !== null && v !== undefined && v !== false) el.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat()) if (k !== null && k !== undefined) el.append(k);
  return el;
}

async function api(path, { method = "GET", body, raw } = {}) {
  const headers = {};
  if (token) headers.Authorization = "Bearer " + token;
  let payload;
  if (raw) payload = raw;
  else if (body) { headers["Content-Type"] = "application/json"; payload = JSON.stringify(body); }
  const r = await fetch(API + path, { method, headers, body: payload });
  if (r.status === 401 && token) { token = null; me = null; render(); throw new Error("Session expired"); }
  if (r.status === 204) return null;
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    const d = data.detail;
    throw new Error(typeof d === "string" ? d : Array.isArray(d) ? d.map(e => e.msg).join("; ") : "Request failed");
  }
  return data;
}

function errBox() { return h("div", { class: "err" }); }
const guard = (box, fn) => async (...a) => { box.textContent = ""; try { await fn(...a); } catch (e) { box.textContent = e.message; } };

// ---- login / forgot / reset (split screen: carousel left, form right) ----
const SLIDES = [
  ["Every address, one source of truth", "Sections, subnets, VLANs and VRFs for IPv4 and IPv6, with free space always visible."],
  ["Discover what is really in use", "Scan subnets, spot stale and conflicting addresses, and reserve the next free IP in a click."],
  ["Secure and audit-ready", "Directory sign-in, per-section permissions and a full change log for every action."],
];
let authView = "login";      // login | forgot | reset
let resetToken = null;
let notice = "";
let carouselTimer = null;

function carousel() {
  let idx = 0;
  const slides = SLIDES.map(([t, d], n) => h("div", { class: "slide" + (n === 0 ? " on" : ""), "aria-hidden": n === 0 ? "false" : "true" },
    h("h2", {}, t), h("p", {}, d)));
  const dots = SLIDES.map((_, n) => h("button", { class: "dot" + (n === 0 ? " on" : ""), type: "button", "aria-label": `Slide ${n + 1}`,
    onclick: () => show(n) }));
  function show(n) {
    idx = n;
    slides.forEach((s, k) => { s.classList.toggle("on", k === n); s.setAttribute("aria-hidden", k === n ? "false" : "true"); });
    dots.forEach((d, k) => d.classList.toggle("on", k === n));
  }
  clearInterval(carouselTimer);
  if (!matchMedia("(prefers-reduced-motion: reduce)").matches) {
    carouselTimer = setInterval(() => show((idx + 1) % SLIDES.length), 6000);
  }
  return h("section", { class: "hero", "aria-label": "About IPAM" },
    h("div", { class: "brand" }, "IPAM"), h("div", { class: "slides" }, slides), h("div", { class: "dots" }, dots));
}

function field(label, input) { return h("label", { class: "fld" }, h("span", {}, label), input); }

function loginForm() {
  const err = errBox();
  const saved = localStorage.getItem("ipam_user") || "";   // username only, never the password or token
  const u = h("input", { autocomplete: "username", maxlength: 64, required: true, placeholder: "Enter your username", value: saved });
  const p = h("input", { type: "password", autocomplete: "current-password", maxlength: 128, required: true, placeholder: "Enter your password" });
  const rem = h("input", { type: "checkbox", checked: saved ? true : null });
  const note = notice ? h("div", { class: "ok" }, notice) : null; notice = "";
  return h("form", { class: "authform", onsubmit: guard(err, async (e) => {
    e.preventDefault();
    const r = await api("/auth/login", { method: "POST", body: { username: u.value, password: p.value } });
    rem.checked ? localStorage.setItem("ipam_user", u.value) : localStorage.removeItem("ipam_user");
    token = r.access_token; me = await api("/auth/me"); clearInterval(carouselTimer); render();
  }) }, h("h1", {}, "Log in"), note, field("Username", u), field("Password", p),
    h("div", { class: "rowsplit" }, h("label", { class: "chk" }, rem, " Remember me"),
      h("a", { href: "#", onclick: (e) => { e.preventDefault(); authView = "forgot"; render(); } }, "Forgot password?")),
    err, h("button", { class: "pri wide" }, "Log in"));
}

function forgotForm() {
  const err = errBox();
  const em = h("input", { type: "email", maxlength: 254, required: true, placeholder: "you@company.com", autocomplete: "email" });
  const done = h("div", { class: "ok" });
  return h("form", { class: "authform", onsubmit: guard(err, async (e) => {
    e.preventDefault();
    const r = await api("/auth/forgot-password", { method: "POST", body: { email: em.value } });
    done.textContent = r.detail;
  }) }, h("h1", {}, "Reset password"), h("p", { class: "mut" }, "Enter your account e-mail and we will send you a reset link."),
    field("E-mail address", em), err, done, h("button", { class: "pri wide" }, "Send reset link"),
    h("p", { class: "center" }, h("a", { href: "#", onclick: (e) => { e.preventDefault(); authView = "login"; render(); } }, "Back to log in")));
}

function resetForm() {
  const err = errBox();
  const p1 = h("input", { type: "password", autocomplete: "new-password", maxlength: 128, required: true, minlength: 12, placeholder: "At least 12 characters" });
  const p2 = h("input", { type: "password", autocomplete: "new-password", maxlength: 128, required: true, placeholder: "Repeat password" });
  return h("form", { class: "authform", onsubmit: guard(err, async (e) => {
    e.preventDefault();
    if (p1.value !== p2.value) throw new Error("Passwords do not match");
    await api("/auth/reset-password", { method: "POST", body: { token: resetToken, new_password: p1.value } });
    resetToken = null; authView = "login"; notice = "Password updated. Please log in."; render();
  }) }, h("h1", {}, "Choose a new password"), field("New password", p1), field("Repeat password", p2), err,
    h("button", { class: "pri wide" }, "Update password"));
}

function loginView() {
  const forms = { login: loginForm, forgot: forgotForm, reset: resetForm };
  return h("div", { class: "split" }, carousel(), h("section", { class: "formside" }, forms[authView]()));
}

(function readResetLink() {
  const m = location.hash.match(/^#reset=([\w-]{20,100})$/);
  if (m) { resetToken = m[1]; authView = "reset"; history.replaceState(null, "", location.pathname); }
})();

const fmtTime = (v) => new Date(/(Z|[+-]\d\d:?\d\d)$/i.test(v) ? v : v + "Z").toLocaleString();   // server times are UTC

// ---- generic table ----
function table(cols, rows, actions) {
  return h("table", {}, h("thead", {}, h("tr", {}, cols.map(c => h("th", {}, c[0])), actions ? h("th") : null)),
    h("tbody", {}, rows.map(r => h("tr", {}, cols.map(c => h("td", {}, String(c[1](r) ?? ""))), actions ? h("td", {}, actions(r)) : null))));
}
const delBtn = (fn) => h("button", { class: "del", onclick: fn }, "Delete");

// ---- views ----
let sections = [], current = null;

async function subnetsView(el) {
  const err = errBox();
  sections = await api("/sections");
  if (current === null && sections.length) current = sections[0].id;
  const sel = h("select", { onchange: (e) => { current = Number(e.target.value); render(); } },
    sections.map(s => h("option", { value: s.id, selected: s.id === current }, s.name)));
  el.append(h("div", { class: "card" }, h("b", {}, "Section: "), sel, " ",
    me.role === "admin" ? addSectionForm(err) : null, err));
  if (!current) return;
  const [subnets, vrfs, vlans] = await Promise.all([api(`/subnets?section_id=${current}`), api("/vrfs"), api("/vlans")]);
  const nameOf = (list, id, f) => { const x = list.find(i => i.id === id); return x ? f(x) : ""; };
  const cidr = h("input", { placeholder: "10.0.0.0/24", required: true, maxlength: 49 });
  const desc = h("input", { placeholder: "Description", maxlength: 2000 });
  const vrf = h("select", {}, h("option", { value: "" }, "(no VRF)"), vrfs.map(v => h("option", { value: v.id }, v.name)));
  const vlan = h("select", {}, h("option", { value: "" }, "(no VLAN)"), vlans.map(v => h("option", { value: v.id }, `${v.number} ${v.name}`)));
  const file = h("input", { type: "file", accept: ".csv" });
  const add = h("form", { class: "row", onsubmit: guard(err, async (e) => {
    e.preventDefault();
    await api("/subnets", { method: "POST", body: { section_id: current, cidr: cidr.value, description: desc.value || null,
      vrf_id: vrf.value ? Number(vrf.value) : null, vlan_id: vlan.value ? Number(vlan.value) : null } });
    render();
  }) }, cidr, desc, vrf, vlan, h("button", { class: "pri" }, "Add subnet"));
  const imp = h("form", { class: "row", onsubmit: guard(err, async (e) => {
    e.preventDefault(); if (!file.files[0]) return;
    const fd = new FormData(); fd.append("file", file.files[0]);
    const r = await api(`/sections/${current}/import`, { method: "POST", raw: fd });
    alert(`Created ${r.created}; errors: ${r.errors.length}\n` + r.errors.slice(0, 10).map(x => `row ${x.row}: ${x.error}`).join("\n"));
    render();
  }) }, file, h("button", {}, "Import CSV (cidr,description,vrf,vlan)"));
  const bar = (r) => h("span", { class: "bar " + (r.percent_used >= 95 ? "full" : r.percent_used >= 80 ? "warn" : "") },
    h("i", { style: `width:${Math.min(r.percent_used, 100)}%` }));
  const t = h("table", {}, h("thead", {}, h("tr", {}, ["Subnet", "Description", "VRF", "VLAN", "Usage", "Used/Total", "Next free", ""].map(x => h("th", {}, x)))),
    h("tbody", {}, subnets.map(r => h("tr", {},
      h("td", {}, h("a", { href: "#", onclick: (e) => { e.preventDefault(); openSubnet = r; render(); } }, r.cidr)),
      h("td", {}, r.description || ""), h("td", {}, nameOf(vrfs, r.vrf_id, v => v.name)),
      h("td", {}, nameOf(vlans, r.vlan_id, v => v.number)), h("td", {}, bar(r), " ", `${r.percent_used}%`),
      h("td", {}, `${r.used}/${r.total}`), h("td", {}, r.next_free || "-"),
      h("td", {}, delBtn(guard(err, async () => { if (confirm("Delete subnet and its addresses?")) { await api(`/subnets/${r.id}`, { method: "DELETE" }); render(); } })))))));
  el.append(h("div", { class: "card" }, add, imp, t));
  if (openSubnet && subnets.some(s => s.id === openSubnet.id)) await addressesView(el, openSubnet, err);
}
let openSubnet = null;

function addSectionForm(err) {
  const n = h("input", { placeholder: "New section name", required: true, maxlength: 100 });
  return h("form", { class: "row", style: "display:inline-flex;margin:0 0 0 12px", onsubmit: guard(err, async (e) => {
    e.preventDefault(); const s = await api("/sections", { method: "POST", body: { name: n.value } }); current = s.id; render();
  }) }, n, h("button", {}, "Add section"));
}

async function addressesView(el, subnet, err) {
  const addrs = await api(`/subnets/${subnet.id}/addresses`);
  const ip = h("input", { placeholder: "IP", required: true, maxlength: 45 });
  const host = h("input", { placeholder: "Hostname", maxlength: 255 });
  const mac = h("input", { placeholder: "MAC", maxlength: 17 });
  const st = h("select", {}, ["used", "reserved", "online", "offline", "dhcp"].map(s => h("option", {}, s)));
  const form = h("form", { class: "row", onsubmit: guard(err, async (e) => {
    e.preventDefault();
    await api(`/subnets/${subnet.id}/addresses`, { method: "POST", body: { ip: ip.value, hostname: host.value || null, mac: mac.value || null, status: st.value } });
    render();
  }) }, ip, host, mac, st, h("button", { class: "pri" }, "Add address"),
    h("button", { type: "button", onclick: guard(err, async () => {
      const r = await api(`/subnets/${subnet.id}/scan`, { method: "POST" });
      alert(`Scanned ${r.scanned}, alive ${r.alive}, new ${r.new}`); render();
    }) }, "Scan subnet"));
  el.append(h("div", { class: "card" }, h("h3", {}, "Addresses in " + subnet.cidr), form,
    table([["IP", r => r.ip], ["Hostname", r => r.hostname], ["MAC", r => r.mac], ["Status", r => r.status],
      ["Last seen", r => r.last_seen ? fmtTime(r.last_seen) : ""]], addrs,
      (r) => delBtn(guard(err, async () => { await api(`/addresses/${r.id}`, { method: "DELETE" }); render(); })))));
}

function simpleCrud(path, cols, fields) {
  return async (el) => {
    const err = errBox();
    const rows = await api("/" + path);
    const inputs = fields.map(f => h("input", { placeholder: f.label, required: f.req, type: f.num ? "number" : "text", maxlength: 255 }));
    const form = h("form", { class: "row", onsubmit: guard(err, async (e) => {
      e.preventDefault();
      const body = {}; fields.forEach((f, i) => { const v = inputs[i].value; body[f.key] = f.num ? Number(v) : (v || null); });
      await api("/" + path, { method: "POST", body }); render();
    }) }, inputs, h("button", { class: "pri" }, "Add"));
    el.append(h("div", { class: "card" }, form, err,
      table(cols, rows, (r) => delBtn(guard(err, async () => { await api(`/${path}/${r.id}`, { method: "DELETE" }); render(); })))));
  };
}

async function searchView(el) {
  const err = errBox(); const q = h("input", { placeholder: "IP, hostname, MAC or description", minlength: 2, maxlength: 64 });
  const out = h("div");
  el.append(h("div", { class: "card" }, h("form", { class: "row", onsubmit: guard(err, async (e) => {
    e.preventDefault(); const rows = await api("/search?q=" + encodeURIComponent(q.value));
    out.replaceChildren(table([["IP", r => r.ip], ["Hostname", r => r.hostname], ["MAC", r => r.mac], ["Status", r => r.status]], rows));
  }) }, q, h("button", { class: "pri" }, "Search")), err, out));
}

async function auditView(el) {
  const rows = await api("/audit?limit=200");
  el.append(h("div", { class: "card" }, table([["When", r => fmtTime(r.at)], ["User", r => r.actor],
    ["Action", r => r.action], ["Target", r => r.target], ["Detail", r => r.detail], ["From", r => r.client_ip]], rows)));
}

const tabs = {
  Subnets: subnetsView, Search: searchView,
  VLANs: simpleCrud("vlans", [["Number", r => r.number], ["Name", r => r.name], ["Description", r => r.description]],
    [{ key: "number", label: "VLAN id", req: true, num: true }, { key: "name", label: "Name", req: true }, { key: "description", label: "Description" }]),
  VRFs: simpleCrud("vrfs", [["Name", r => r.name], ["RD", r => r.rd], ["Description", r => r.description]],
    [{ key: "name", label: "Name", req: true }, { key: "rd", label: "Route distinguisher" }, { key: "description", label: "Description" }]),
  Devices: simpleCrud("devices", [["Hostname", r => r.hostname], ["Type", r => r.device_type], ["Location", r => r.location]],
    [{ key: "hostname", label: "Hostname", req: true }, { key: "device_type", label: "Type (firewall, lb, vm...)", req: true }, { key: "location", label: "Location" }]),
  Audit: auditView,
};
let tab = "Subnets";

async function render() {
  root.replaceChildren();
  if (!token) { root.append(loginView()); return; }
  const names = Object.keys(tabs).filter(n => n !== "Audit" || me.role === "admin");
  root.append(h("header", {}, h("h1", {}, "IPAM"),
    h("nav", {}, names.map(n => h("button", { class: n === tab ? "on" : "", onclick: () => { tab = n; render(); } }, n))),
    h("span", { class: "sp" }), h("span", {}, `${me.username} (${me.role}) `),
    h("button", { onclick: async () => { try { await api("/auth/logout", { method: "POST" }); } finally { token = null; me = null; render(); } } }, "Sign out")));
  const main = h("main"); root.append(main);
  try { await tabs[tab](main); } catch (e) { main.append(h("div", { class: "err" }, e.message)); }
}
render();
