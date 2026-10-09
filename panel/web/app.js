/* AmneziaWG Panel SPA */
const $ = (s, p) => (p || document).querySelector(s);
const $$ = (s, p) => [...(p || document).querySelectorAll(s)];
let ME = null, KEYS = [], USERS = [];

async function api(path, opts = {}) {
  const o = { headers: { "Content-Type": "application/json" }, credentials: "same-origin", ...opts };
  if (o.body && typeof o.body !== "string") o.body = JSON.stringify(o.body);
  const r = await fetch("/api" + path, o);
  if (r.status === 403) { showLogin(); throw new Error("unauthorized"); }
  const ct = r.headers.get("content-type") || "";
  const d = ct.includes("json") ? await r.json() : await r.text();
  if (!r.ok) throw new Error(d.error || ("HTTP " + r.status));
  return d;
}
function toast(msg, cls = "ok") {
  const t = document.createElement("div");
  t.className = "toast " + cls; t.textContent = msg;
  $("#toastRoot").appendChild(t);
  setTimeout(() => t.remove(), 4200);
}
function esc(s) { return String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function fmtBytes(b) {
  if (!b) return "—";
  const u = ["Б", "КБ", "МБ", "ГБ", "ТБ"]; let i = 0; b = Number(b);
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return b.toFixed(b > 99 ? 0 : 1) + " " + u[i];
}
function fmtDate(ts) { return ts ? new Date(ts * 1000).toLocaleDateString("ru-RU") : "∞"; }
function fmtAgo(ts) {
  if (!ts) return "никогда";
  const s = Math.floor(Date.now() / 1000 - ts);
  if (s < 60) return "только что";
  if (s < 3600) return Math.floor(s / 60) + " мин назад";
  if (s < 86400) return Math.floor(s / 3600) + " ч назад";
  return Math.floor(s / 86400) + " дн назад";
}
async function copy(text) {
  try { await navigator.clipboard.writeText(text); toast("Скопировано в буфер ✔"); }
  catch { toast("Не удалось скопировать", "err"); }
}

/* ---------- modal ---------- */
function modal(title, bodyHTML, onSubmit, submitLabel = "Сохранить") {
  return new Promise(resolve => {
    const back = document.createElement("div");
    back.className = "modal-back";
    back.innerHTML = `<div class="modal"><h3>${title}</h3><form id="mf">${bodyHTML}
      <div class="modal-actions"><button type="button" class="btn ghost" id="mc">Отмена</button>
      <button class="btn primary" type="submit">${submitLabel}</button></div></form></div>`;
    $("#modalRoot").appendChild(back);
    const close = () => { back.remove(); resolve(null); };
    $("#mc", back).onclick = close;
    back.onclick = e => { if (e.target === back) close(); };
    $("#mf", back).onsubmit = async e => {
      e.preventDefault();
      const data = Object.fromEntries(new FormData(e.target).entries());
      try {
        const res = onSubmit ? await onSubmit(data) : data;
        back.remove(); resolve(res);
      } catch (err) { toast(err.message, "err"); }
    };
    const first = $("input,select", back); if (first) first.focus();
  });
}
const sw = (name, label, on) => `<div class="switch-row"><span>${label}</span>
  <label class="switch"><input type="checkbox" name="${name}" ${on ? "checked" : ""}><span class="slider"></span></label></div>`;
const fld = (name, label, val, type = "text", attrs = "") =>
  `<label>${label}<input type="${type}" name="${name}" value="${esc(val ?? "")}" ${attrs}></label>`;
const sel = (name, label, opts, val) =>
  `<label>${label}<select name="${name}">${opts.map(o =>
    `<option value="${o[0]}" ${String(o[0]) === String(val) ? "selected" : ""}>${o[1]}</option>`).join("")}</select></label>`;

/* ---------- login ---------- */
function showLogin() { $("#login").classList.remove("hidden"); $("#app").classList.add("hidden"); }
$("#loginForm").onsubmit = async e => {
  e.preventDefault();
  const d = Object.fromEntries(new FormData(e.target).entries());
  try {
    const r = await api("/login", { method: "POST", body: d });
    ME = r.user; $("#loginErr").textContent = "";
    startApp();
  } catch (err) { $("#loginErr").textContent = err.message; }
};
$("#logoutBtn").onclick = async () => { await api("/logout", { method: "POST" }); location.reload(); };
$("#themeBtn").onclick = () => {
  const h = document.documentElement;
  h.dataset.theme = h.dataset.theme === "dark" ? "light" : "dark";
  localStorage.setItem("awg-theme", h.dataset.theme);
};
if (localStorage.getItem("awg-theme")) document.documentElement.dataset.theme = localStorage.getItem("awg-theme");

/* ---------- navigation ---------- */
const NAV = [
  ["dashboard", "📊", "Дашборд"],
  ["keys", "🔑", "Ключи VPN"],
  ["users", "👥", "Пользователи", "admin"],
  ["settings", "⚙️", "Настройки", "admin"],
];
function renderNav(view) {
  $("#nav").innerHTML = NAV.filter(n => !n[3] || ME.role === n[3]).map(n =>
    `<div class="nav-item ${n[0] === view ? "active" : ""}" data-v="${n[0]}"><span>${n[1]}</span>${n[2]}</div>`).join("");
  $$(".nav-item").forEach(el => el.onclick = () => go(el.dataset.v));
}
function go(v) { renderNav(v); VIEWS[v](); }

/* ---------- views ---------- */
const VIEWS = {
  async dashboard() {
    $("#main").innerHTML = `<h2 class="page">Дашборд <button class="btn sm" onclick="location.reload()">↻ Обновить</button></h2><div id="dash" class="muted">Загрузка…</div>`;
    const st = await api("/stats");
    const isAdmin = ME.role === "admin";
    $("#dash").innerHTML = `
    <div class="grid c4">
      <div class="card stat"><span class="v">${st.keys_online}</span><span class="l">Онлайн сейчас</span></div>
      <div class="card stat"><span class="v">${st.keys_active}/${st.keys_total}</span><span class="l">Активных ключей</span></div>
      ${isAdmin ? `<div class="card stat"><span class="v">${st.users}</span><span class="l">Пользователей</span></div>` : ""}
      <div class="card stat"><span class="v">${fmtBytes(st.traffic_bytes)}</span><span class="l">Трафик всего</span></div>
    </div>
    <div class="grid c2">
      <div class="card"><h3 style="margin-top:0">Сервер</h3>
        <table>
        <tr><td class="muted">Endpoint</td><td class="mono">${esc(st.endpoint)}:${esc(st.port)}</td></tr>
        <tr><td class="muted">Публичный ключ сервера</td><td class="mono" style="word-break:break-all">${esc(st.server_pubkey)}
          <button class="btn sm" onclick="copy('${esc(st.server_pubkey)}')">копировать</button></td></tr>
        <tr><td class="muted">Аптайм</td><td>${Math.floor(st.uptime / 3600)} ч ${Math.floor(st.uptime % 3600 / 60)} мин</td></tr>
        <tr><td class="muted">Load average</td><td>${st.load.map(x => x.toFixed(2)).join(" / ")}</td></tr>
        </table></div>
      <div class="card"><h3 style="margin-top:0">Быстрые действия</h3>
        <div class="row-actions">
          <button class="btn primary" onclick="go('keys');newKey()">＋ Новый ключ</button>
          ${isAdmin ? `<button class="btn" onclick="api('/reload',{method:'POST'}).then(()=>toast('Конфигурация применена'))">⇧ Применить конфиг</button>` : ""}
          <button class="btn" onclick="go('keys')">🔑Manage keys</button>
        </div>
        <p class="muted small.muted" style="margin-top:16px">AmneziaWG 3.0 — WireGuard с шумовыми пакетами (junk packets), устойчивый к DPI-блокировкам.</p>
      </div>
    </div>`;
  },

  async keys() {
    KEYS = await api("/keys");
    const isAdmin = ME.role === "admin";
    $("#main").innerHTML = `
    <h2 class="page">Ключи VPN <button class="btn primary" id="addKey">＋ Создать ключ</button></h2>
    <div class="searchbar"><input id="q" placeholder="Поиск по имени / публичному ключу / заметке…">
      <span class="muted small.muted">${KEYS.length} ключей</span></div>
    <div class="card" style="padding:0;overflow-x:auto"><table id="kt">
      <thead><tr><th>Статус</th><th>Имя</th><th>IP</th><th>Транспорт</th><th>Истекает</th><th>Трафик</th><th>Был онлайн</th>${isAdmin ? "<th>Владелец</th>" : ""}<th></th></tr></thead>
      <tbody></tbody></table><div id="kEmpty" class="empty hidden"><div class="big">🔑</div>Ключей пока нет — создайте первый!</div></div>`;
    $("#addKey").onclick = () => newKey();
    $("#q").oninput = e => drawKeys(e.target.value);
    drawKeys("");
  },

  async users() {
    USERS = await api("/users");
    $("#main").innerHTML = `
    <h2 class="page">Пользователи <button class="btn primary" id="addUser">＋ Добавить</button></h2>
    <div class="card" style="padding:0;overflow-x:auto"><table>
      <thead><tr><th>Логин</th><th>Роль</th><th>Статус</th><th>Ключей</th><th>Последний вход</th><th></th></tr></thead>
      <tbody>${USERS.map(u => `<tr>
        <td class="keyname">${esc(u.username)}</td>
        <td><span class="badge ${u.role === "admin" ? "warn" : "off"}">${u.role}</span></td>
        <td>${u.enabled ? '<span class="badge ok"><i class="dot"></i>активен</span>' : '<span class="badge err"><i class="dot"></i>отключён</span>'}</td>
        <td>${u.keys_count}</td>
        <td class="muted">${fmtAgo(u.last_login)}</td>
        <td><div class="row-actions">
          <button class="btn sm" onclick="editUser(${u.id})">✏️</button>
          <button class="btn sm" onclick="toggleUser(${u.id},${1 - (u.enabled ? 1 : 0)})">${u.enabled ? "⛔" : "✅"}</button>
          ${u.id !== ME.id ? `<button class="btn sm danger" onclick="delUser(${u.id},'${esc(u.username)}')">🗑</button>` : ""}
        </div></td></tr>`).join("")}</tbody></table></div>`;
    $("#addUser").onclick = () => newUsers();
  },

  async settings() {
    const s = await api("/settings");
    $("#main").innerHTML = `
    <h2 class="page">Настройки сервера</h2>
    <form id="sf">
    <div class="grid c2">
      <div class="card"><h3 style="margin-top:0">🌐 Сеть</h3>
        ${fld("endpoint_host", "Домен / IP endpoint (для клиентов)", s.endpoint_host)}
        ${fld("port", "Порт UDP (ListenPort)", s.port, "number")}
        ${fld("subnet", "Подсеть клиентов", s.subnet)}
        ${fld("server_ip", "IP сервера в туннеле", s.server_ip)}
        ${fld("server_ipv6", "IPv6 в туннеле (необязательно)", s.server_ipv6)}
        ${fld("default_dns", "DNS по умолчанию", s.default_dns)}
        ${fld("default_mtu", "MTU по умолчанию", s.default_mtu, "number")}
      </div>
      <div class="card"><h3 style="margin-top:0">🎭 Анти-DPI (AmneziaWG)</h3>
        ${sw("amnezia_enabled", "Включить шумовые пакеты", s.amnezia_enabled == 1 || s.amnezia_enabled === "")}
        ${sw("pfs", "Perfect Forward Secrecy (Noise)", s.pfs != 0)}
        ${fld("jc", "Jc — кол-во мусорных пакетов", s.jc || 3, "number")}
        <div class="grid" style="grid-template-columns:1fr 1fr">
          ${fld("jmin", "Jmin", s.jmin || 50, "number")}
          ${fld("jmax", "Jmax", s.jmax || 90, "number")}
        </div>
        <div class="grid" style="grid-template-columns:1fr 1fr">
          ${fld("s1", "S1 (init junk size)", s.s1 || 857, "number")}
          ${fld("s2", "S2 (resp junk size)", s.s2 || 1271, "number")}
        </div>
        ${fld("user_key_limit", "Лимит ключей для обычных юзеров", localStorage.getItem("_") || "", "number")}
      </div>
    </div>
    <div class="card"><h3 style="margin-top:0">🔐 Смена собственного пароля</h3>
      <div class="grid c2">
        ${fld("old_password", "Текущий пароль", "", "password")}
        ${fld("new_password", "Новый пароль", "", "password", " minlength=6")}
      </div>
    </div>
    <button class="btn primary block" style="max-width:300px">💾 Сохранить и применить</button>
    </form>`;
    $("#sf").onsubmit = async e => {
      e.preventDefault();
      const f = new FormData(e.target);
      const set = {};
      for (const k of ["endpoint_host","port","subnet","server_ip","server_ipv6","default_dns","default_mtu","jc","jmin","jmax","s1","s2","user_key_limit"])
        if (f.has(k)) set[k] = f.get(k);
      set.amnezia_enabled = f.get("amnezia_enabled") ? 1 : 0;
      set.pfs = f.get("pfs") ? 1 : 0;
      try {
        const r = await api("/settings", { method: "PUT", body: set });
        if (r.applied === false) toast("Сохранено, но wg-quick вернул ошибку: " + r.apply_error, "err");
        else toast("Настройки применены ✔");
      } catch (err) { toast(err.message, "err"); }
      if (f.get("new_password")) {
        try {
          await api("/password", { method: "POST", body: { old_password: f.get("old_password"), new_password: f.get("new_password") } });
          toast("Пароль обновлён ✔");
        } catch (err) { toast("Пароль: " + err.message, "err"); }
      }
    };
  },
};

/* ---------- key rendering ---------- */
const TRANSPORT_LABEL = { wg: "WireGuard", "wg-amnezia": "AmneziaWG", shadowsocks: "SS+AmneziaWG" };
function statusBadge(k) {
  if (k.status === "expired") return '<span class="badge err"><i class="dot"></i>истёк</span>';
  if (k.status !== "active") return '<span class="badge off"><i class="dot"></i>выключен</span>';
  return k.online ? '<span class="badge ok"><i class="dot"></i>онлайн</span>'
                  : '<span class="badge warn"><i class="dot"></i>активен</span>';
}
function quotaHTML(k) {
  if (!k.quota_bytes) return '<span class="muted">∞</span>';
  const pct = Math.min(100, (k.used_bytes / k.quota_bytes) * 100);
  return `${fmtBytes(k.used_bytes)} / ${fmtBytes(k.quota_bytes)}
    <div class="progress"><i style="width:${pct}%"></i></div>`;
}
function drawKeys(q) {
  q = (q || "").toLowerCase();
  const rows = KEYS.filter(k => !q || (k.name + k.public_key + (k.note || "")).toLowerCase().includes(q));
  const isAdmin = ME.role === "admin";
  const owners = Object.fromEntries(USERS.map(u => [u.id, u.username]));
  $("#kt tbody").innerHTML = rows.map(k => `<tr>
    <td>${statusBadge(k)}</td>
    <td><span class="keyname">${esc(k.name)}</span>${k.counter ? ` <small class="muted">#${k.counter}</small>` : ""}
      ${k.note ? `<br><small class="muted">${esc(k.note)}</small>` : ""}</td>
    <td class="mono">${esc(k.ip4)}</td>
    <td><span class="badge off">${TRANSPORT_LABEL[k.transport] || k.transport}</span></td>
    <td>${fmtDate(k.expires_at)}</td>
    <td style="min-width:120px">${quotaHTML(k)}</td>
    <td class="muted">${fmtAgo(k.last_seen)}</td>
    ${isAdmin ? `<td class="muted">${esc(owners[k.owner_id] || "—")}</td>` : ""}
    <td><div class="row-actions">
      <button class="btn sm" title="Скачать .conf" onclick="dl(${k.id},'ini')">⬇ conf</button>
      <button class="btn sm" title="Configlink / Amnezia JSON" onclick="dl(${k.id},'json')">⬇ json</button>
      <button class="btn sm" title="QR-код" onclick="showQR(${k.id})">▦ QR</button>
      <button class="btn sm" title="Изменить" onclick="editKey(${k.id})">✏️</button>
      ${isAdmin ? `<button class="btn sm" title="Ротация ключей" onclick="rotateKey(${k.id})">♻️</button>` : ""}
      <button class="btn sm" title="Подробнее" onclick="keyInfo(${k.id})">ℹ️</button>
      <button class="btn sm danger" title="Удалить" onclick="delKey(${k.id},'${esc(k.name)}')">🗑</button>
    </div></td></tr>`).join("");
  $("#kEmpty").classList.toggle("hidden", rows.length > 0);
}
function dl(id, kind) { window.open(`/api/keys/${id}/${kind}`, "_blank"); }
async function showQR(id) {
  const k = KEYS.find(x => x.id === id);
  modal(`QR-код — ${esc(k.name)}`,
    `<div style="text-align:center"><img src="/api/keys/${id}/qr" width="260" height="260" style="border-radius:12px;background:#fff;padding:10px">
     <p class="muted small.muted">Сканируйте приложением AmneziaWG / WireGuard</p></div>`, null, "Закрыть");
}
async function rotateKey(id) {
  if (!confirm("Сгенерировать новые приватный/публичный/PSK ключи? Старый конфиг клиента перестанет работать.")) return;
  await api(`/keys/${id}/rotate`, { method: "POST" });
  toast("Ключи повращены ♻️"); go("keys");
}
async function delKey(id, name) {
  if (!confirm(`Удалить ключ «${name}»? Клиент сразу потеряет доступ.`)) return;
  await api(`/keys/${id}`, { method: "DELETE" });
  toast("Ключ удалён"); go("keys");
}

/* ---------- key forms ---------- */
const keyForm = (k = {}, extra = "") => `
  <div class="grid c2">
    ${fld("name", "Имя ключа", k.name, "text", "required placeholder=\"iPhone Ильи\"")}
    ${sel("transport", "Транспорт", [["wg-amnezia", "AmneziaWG (анти-DPI)"], ["wg", "Чистый WireGuard"], ["shadowsocks", "Shadowsocks + AmneziaWG"]], k.transport || "wg-amnezia")}
    ${fld("expires_days", "Срок действия (дней, 0 = бессрочно)", k.expires_days ?? 30, "number", "min=0")}
    ${fld("quota_mb", "Квота трафика (МБ, пусто = безлимит)", k.quota_mb ?? "", "number", "min=0")}
    ${fld("dns", "DNS", k.dns || "8.8.8.8, 8.8.4.4")}
    ${fld("mtu", "MTU", k.mtu || 1420, "number")}
    ${fld("endpoint_port", "Порт endpoint", k.endpoint_port || 443, "number")}
    ${fld("note", "Заметка", k.note || "")}
  </div>
  ${sw("enable_amnezia", "Шумовые пакеты (junk) — защита от DPI", k.enable_amnezia !== false && k.enable_amnezia !== 0)}
  ${sw("enable_pfs", "Preshared key (PFS)", k.enable_pfs !== false && k.enable_pfs !== 0)}
  <details style="margin-top:14px"><summary class="muted" style="cursor:pointer">Расширенные параметры обфускации</summary>
    <div class="grid" style="grid-template-columns:repeat(3,1fr)">
      ${fld("junk_min_size", "Jmin", k.junk_min_size || 50, "number")}
      ${fld("junk_max_size", "Jmax", k.junk_max_size || 90, "number")}
      ${fld("junk_count", "Jc", k.junk_count || 3, "number")}
      ${fld("init_packet_junk_size", "S1", k.init_packet_junk_size || 857, "number")}
      ${fld("response_packet_junk_size", "S2", k.response_packet_junk_size || 1271, "number")}
      ${fld("tg_port", "Telegram port", k.tg_port || 443, "number")}
    </div>
  </details>${extra}`;

async function newKey() {
  const ownerExtra = ME.role === "admin" && USERS.length ?
    sel("owner_id", "Владелец", [[ME.id, "— (я)"]].concat(USERS.filter(u => u.id !== ME.id).map(u => [u.id, u.username])), "") : "";
  const r = await modal("Новый ключ VPN", keyForm({}, ownerExtra), d => {
    const body = { ...d, enable_amnezia: !!d.enable_amnezia, enable_pfs: !!d.enable_pfs };
    Object.keys(body).forEach(k => body[k] === "" && delete body[k]);
    return api("/keys", { method: "POST", body });
  }, "Создать");
  if (!r) return;
  toast("Ключ создан ✔");
  KEYS = await api("/keys");
  USERS = ME.role === "admin" ? await api("/users") : USERS;
  if ($("#kt")) drawKeys($("#q")?.value || "");
  createdDialog(r);
}
function createdDialog(k) {
  modal(`Ключ «${esc(k.name)}» создан`, `
    <p class="muted small.muted">Скачайте конфиг или передайте клиенту ссылку. Приватный ключ показан один раз:</p>
    <textarea readonly rows="8" class="mono">${esc(k.private_key)}</textarea>
    <div class="row-actions" style="margin-top:14px">
      <button class="btn" type="button" onclick="dl(${k.id},'ini')">⬇ Скачать .conf</button>
      <button class="btn" type="button" onclick="dl(${k.id},'json')">⬇ Configlink JSON</button>
      <button class="btn" type="button" onclick="showQR(${k.id})">▦ QR-код</button>
    </div>`, null, "Готово");
}
async function editKey(id) {
  const k = await api(`/keys/${id}`);
  const days = k.expires_at ? Math.max(1, Math.round((k.expires_at - Date.now() / 1000) / 86400)) : 0;
  const r = await modal("Изменить ключ — " + esc(k.name), keyForm({ ...k, expires_days: days, quota_mb: k.quota_bytes ? Math.round(k.quota_bytes / 1048576) : "" }),
    d => {
      const body = { ...d, enable_amnezia: !!d.enable_amnezia, enable_pfs: !!d.enable_pfs };
      Object.keys(body).forEach(x => body[x] === "" && delete body[x]);
      return api(`/keys/${id}`, { method: "PUT", body });
    });
  if (!r) return;
  toast("Ключ обновлён ✔");
  KEYS = await api("/keys");
  if ($("#kt")) drawKeys($("#q")?.value || "");
}
async function keyInfo(id) {
  const k = await api(`/keys/${id}`);
  modal("Информация — " + esc(k.name), `
    <table>
      <tr><td class="muted">ID</td><td>#${k.id}</td></tr>
      <tr><td class="muted">Публичный ключ</td><td class="mono" style="word-break:break-all">${esc(k.public_key)}
        <button class="btn sm" onclick="copy('${esc(k.public_key)}')">копир.</button></td></tr>
      <tr><td class="muted">Preshared key</td><td class="mono" style="word-break:break-all">${esc(k.preshared_key)}
        <button class="btn sm" onclick="copy('${esc(k.preshared_key)}')">копир.</button></td></tr>
      <tr><td class="muted">IP в туннеле</td><td class="mono">${esc(k.ip4)}</td></tr>
      <tr><td class="muted">Endpoint</td><td class="mono">${esc(k.endpoint_ip)}:${k.endpoint_port}</td></tr>
      <tr><td class="muted">AllowedIPs</td><td class="mono">${esc(k.allowed_ips)}</td></tr>
      <tr><td class="muted">Создан</td><td>${new Date(k.created_at * 1000).toLocaleString("ru-RU")}</td></tr>
      <tr><td class="muted">Последняя активность</td><td>${fmtAgo(k.last_seen)}</td></tr>
      <tr><td class="muted">Трафик</td><td>${fmtBytes(k.used_bytes)}</td></tr>
    </table>`, null, "Закрыть");
}

/* ---------- user actions ---------- */
async function newUsers() {
  await modal("Новый пользователь", `
    ${fld("username", "Логин", "", "text", "required pattern=\"[A-Za-z0-9_.@-]{3,32}\"")}
    ${fld("password", "Пароль (мин. 6 символов)", "", "password", "required minlength=6")}
    ${sel("role", "Роль", [["user", "Пользователь"], ["admin", "Администратор"]], "user")}`,
    d => api("/users", { method: "POST", body: d }), "Добавить");
  toast("Пользователь добавлен ✔"); go("users");
}
async function editUser(id) {
  const u = USERS.find(x => x.id === id);
  await modal("Изменить " + esc(u.username), `
    ${fld("password", "Новый пароль (пусто — не менять)", "", "password", "minlength=6")}
    ${sel("role", "Роль", [["user", "Пользователь"], ["admin", "Администратор"]], u.role)}
    ${sw("enabled", "Аккаунт активен", !!u.enabled)}`,
    d => api(`/users/${id}`, { method: "PUT", body: { password: d.password || undefined, role: d.role, enabled: !!d.enabled } }));
  toast("Обновлено ✔"); go("users");
}
async function toggleUser(id, en) {
  await api(`/users/${id}`, { method: "PUT", body: { enabled: !!en } });
  go("users");
}
async function delUser(id, name) {
  if (!confirm(`Удалить пользователя «${name}»? Его ключи останутся без владельца.`)) return;
  await api(`/users/${id}`, { method: "DELETE" });
  toast("Удалён"); go("users");
}

/* ---------- boot ---------- */
async function startApp() {
  $("#login").classList.add("hidden");
  $("#app").classList.remove("hidden");
  $("#whoami").textContent = `${ME.username} (${ME.role})`;
  if (ME.role === "admin") { try { USERS = await api("/users"); } catch {} }
  go("dashboard");
}
(async () => {
  try { ME = (await api("/me")).user; startApp(); }
  catch { showLogin(); }
})();
