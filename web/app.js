/* NodeWatch — веб-панель. Чистый JS без библиотек: опрос API раз в 3 с,
   графики на canvas, карточки инцидентов, правка порогов на лету. */
"use strict";

// ------------------------------------------------------------------ утилиты
const $ = (sel, root = document) => root.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const POLL_MS = 3000;

const fmt = {
  num(v, d = 1) { return v == null || isNaN(v) ? "–" : Number(v).toLocaleString("ru-RU", { maximumFractionDigits: d, minimumFractionDigits: 0 }); },
  rate(v) {
    if (v == null) return "–";
    const units = ["Б/с", "КБ/с", "МБ/с", "ГБ/с"]; let i = 0; v = Number(v);
    while (Math.abs(v) >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return fmt.num(v, v < 10 ? 1 : 0) + " " + units[i];
  },
  mb(v) { if (v == null) return "–"; return Math.abs(v) >= 1024 ? fmt.num(v / 1024, 2) + " ГБ" : fmt.num(v, 0) + " МБ"; },
  mbs(v) { if (v == null) return "–"; return (v > 0 ? "+" : "") + fmt.mb(v); },
  pct(v) { return v == null ? "–" : fmt.num(v, 1) + " %"; },
  ps(v) { return v == null ? "–" : fmt.num(v, 1) + "/с"; },
  plain(v) { return fmt.num(v, 1); },
  time(ts) { return ts ? new Date(ts * 1000).toLocaleTimeString("ru-RU") : "–"; },
  datetime(ts) { return ts ? new Date(ts * 1000).toLocaleString("ru-RU") : "–"; },
  ago(s) {
    if (s == null) return "нет данных";
    if (s < 60) return Math.round(s) + " с назад";
    if (s < 3600) return Math.round(s / 60) + " мин назад";
    return Math.round(s / 3600) + " ч назад";
  },
};

// метрики для графиков и сводки
const METRICS = {
  cpu_user: { label: "CPU пользователя", f: fmt.pct, color: "#62c6f2" },
  net_total: { label: "Сеть, вход + выход", f: fmt.rate, color: "#49d08a" },
  mem_used: { label: "Занятая память", f: fmt.mb, color: "#f0b54a" },
  mem_delta: { label: "Изменение памяти за интервал", f: fmt.mbs, color: "#f0b54a", signed: true },
  proc_new_ps: { label: "Новые процессы", f: fmt.ps, color: "#ff8f6b" },
  thr_new_ps: { label: "Новые потоки", f: fmt.ps, color: "#ff8f6b" },
  disk_total: { label: "Диск, чтение + запись", f: fmt.rate, color: "#c49bf2" },
  cpu_total: { label: "CPU всего", f: fmt.pct, color: "#62c6f2" },
};
const SUMMARY_LABELS = {
  cpu_total: ["CPU всего", fmt.pct], cpu_user: ["CPU пользователя", fmt.pct], cpu_max_core: ["Самое загруженное ядро", fmt.pct],
  disk_read: ["Диск: чтение", fmt.rate], disk_write: ["Диск: запись", fmt.rate], disk_total: ["Диск: всего", fmt.rate],
  disk_iops: ["Диск: операций/с (IOPS)", fmt.plain], net_in: ["Сеть: входящий", fmt.rate], net_out: ["Сеть: исходящий", fmt.rate],
  net_total: ["Сеть: всего", fmt.rate], proc_new_ps: ["Новые процессы", fmt.ps], thr_new_ps: ["Новые потоки", fmt.ps],
  proc_count: ["Процессов", fmt.plain], thr_count: ["Потоков", fmt.plain], handles: ["Дескрипторов (Windows)", fmt.plain],
  mem_used: ["Занятая память", fmt.mb], mem_pct: ["Занятая память, %", fmt.pct], mem_delta: ["mem_delta", fmt.mbs], swap_pct: ["Подкачка (swap)", fmt.pct],
};
const STATUS_RU = { online: "онлайн", silent: "молчит", offline: "офлайн", paused: "пауза" };
const SEV_RU = { critical: "критично", high: "высокая", medium: "средняя", low: "низкая" };
const RULE_DESC = {
  "Общие": "База для z-оценок, профиль порогов и адаптивный режим.",
  NET_LOW_CPU: "Долгий высокий трафик, когда пользователь почти не нагружает процессор, — похоже на фоновую выгрузку данных.",
  PROC_BURST: "Всплеск запуска процессов или потоков: сканеры, майнеры, массовый запуск скриптов.",
  DISK_NET_COMBO: "Много читается или пишется на диск и одновременно идёт трафик — копирование и отправка данных.",
  MEM_JUMP: "Резкий рост занятой памяти за несколько замеров.",
  AGENT_SILENT: "Агент перестал присылать метрики: остановлен, заблокирован или узел недоступен.",
};
const EVIDENCE_RU = {
  net_total_kBps: "Сетевой трафик, КБ/с", cpu_user_pct: "CPU пользователя, %", points_in_row: "Точек подряд",
  duration_s: "Длительность, с", z: "z-score", threshold_z: "Порог z-score", floor_kBps: "Абсолютный порог, КБ/с",
  low_cpu_user_pct: "Порог CPU пользователя, %", baseline: "Норма узла", proc_new_ps: "Новых процессов в секунду",
  thr_new_ps: "Новых потоков в секунду", z_proc: "z-score процессов", z_thr: "z-score потоков",
  hard_limit_ps: "Жёсткий порог, процессов/с", trigger: "Сработало по", baseline_proc: "Норма: процессы",
  baseline_thr: "Норма: потоки", disk_total_kBps: "Диск, КБ/с", disk_iops: "Операций диска/с",
  z_disk: "z-score диска", z_net: "z-score сети", baseline_disk: "Норма: диск", baseline_net: "Норма: сеть",
  mem_used_mb: "Занято памяти, МБ", mem_total_mb: "Всего памяти, МБ", jump_mb: "Скачок, МБ", jump_pct: "Скачок, % от RAM",
  window_points: "Окно, точек", mem_delta_mb: "mem_delta, МБ", threshold_pct: "Порог скачка, %",
  silent_s: "Без метрик, с", threshold_s: "Порог молчания, с", paused: "Пауза по команде", profile: "Профиль порогов",
  manual: "Создан вручную", requested_by: "Кем создан", note: "Примечание",
};

// ------------------------------------------------------------------ состояние
const state = {
  token: "", tab: "agents", agents: [], reportNode: null, lastEvent: null, rules: {},
  thresholds: null, sound: false, openIncident: null,
};
try { state.sound = localStorage.getItem("nw_sound") === "1"; } catch (e) { /* без хранилища */ }

function readToken() {
  const m = location.hash.match(/token=([0-9a-zA-Z]+)/);
  if (m) {
    state.token = m[1];
    try { localStorage.setItem("nw_token", m[1]); } catch (e) { /* ok */ }
    history.replaceState(null, "", location.pathname);
  } else {
    try { state.token = localStorage.getItem("nw_token") || ""; } catch (e) { state.token = ""; }
  }
}

// ------------------------------------------------------------------ API
class AuthError extends Error {}
async function api(cmd, params = {}) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v != null && v !== "") q.set(k, v);
  const res = await fetch(`/api/${cmd}?${q}`, { headers: { "X-Token": state.token } });
  return unwrap(res);
}
async function post(body) {
  const res = await fetch("/api/cmd", {
    method: "POST", headers: { "X-Token": state.token, "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  return unwrap(res);
}
async function unwrap(res) {
  if (res.status === 401) { showLogin("Токен не подошёл. Возьмите ссылку из лога сервера."); throw new AuthError("401"); }
  const data = await res.json();
  if (!data.ok) throw new Error(data.error || "ошибка сервера");
  return data.data;
}

// ------------------------------------------------------------------ тосты и звук
function toast({ title, sub = "", sev = "info", onClick = null, ttl = 9000 }) {
  const el = document.createElement("div");
  el.className = "toast " + sev;
  el.innerHTML = `<b>${esc(title)}</b><button aria-label="Закрыть">×</button><small>${esc(sub)}</small>`;
  const close = () => el.remove();
  el.querySelector("button").onclick = (e) => { e.stopPropagation(); close(); };
  el.onclick = () => { close(); onClick && onClick(); };
  $("#toasts").prepend(el);
  while ($("#toasts").children.length > 4) $("#toasts").lastChild.remove();
  setTimeout(close, ttl);
}
let audioCtx = null;
function beep() {
  if (!state.sound) return;
  try {
    audioCtx = audioCtx || new (window.AudioContext || window.webkitAudioContext)();
    const o = audioCtx.createOscillator(), g = audioCtx.createGain();
    o.frequency.value = 880; o.type = "sine";
    g.gain.setValueAtTime(0.0001, audioCtx.currentTime);
    g.gain.exponentialRampToValueAtTime(0.15, audioCtx.currentTime + 0.02);
    g.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + 0.35);
    o.connect(g).connect(audioCtx.destination); o.start(); o.stop(audioCtx.currentTime + 0.4);
  } catch (e) { /* звук недоступен */ }
}
function setSound(on) {
  state.sound = on;
  $("#sound-btn").setAttribute("aria-pressed", on ? "true" : "false");
  try { localStorage.setItem("nw_sound", on ? "1" : "0"); } catch (e) { /* ok */ }
  if (on) beep();
}

// ------------------------------------------------------------------ диалог
function ask({ title, text = "", value = null, ok = "OK" }) {
  const dlg = $("#ask");
  $("#ask-title").textContent = title;
  $("#ask-text").textContent = text;
  const input = $("#ask-input");
  input.hidden = value === null;
  input.value = value ?? "";
  $("#ask-ok").textContent = ok;
  dlg.returnValue = "";
  dlg.showModal();
  if (value !== null) setTimeout(() => input.select(), 30);
  return new Promise((resolve) => {
    dlg.addEventListener("close", () => resolve(dlg.returnValue === "ok" ? (value === null ? true : input.value) : null), { once: true });
  });
}

// ------------------------------------------------------------------ вкладки
function switchTab(tab) {
  state.tab = tab;
  document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.id === "view-" + tab));
  refreshTab(true);
}
async function refreshTab(force = false) {
  try {
    if (state.tab === "agents") await loadAgents();
    else if (state.tab === "report") { if (force || !state.agents.length) await loadAgents(false); await loadReport(); }
    else if (state.tab === "incidents") { if (force) await loadAgents(false); await loadIncidents(); }
    else if (state.tab === "thresholds" && force) await loadThresholds();
  } catch (e) { if (!(e instanceof AuthError)) console.warn(e); }
}

// ------------------------------------------------------------------ агенты
async function loadAgents(render = true) {
  state.agents = await api("agents");
  fillNodeFilter();
  if (render) renderAgents();
}
function renderAgents() {
  const tbody = $("#agents-table tbody");
  $("#agents-empty").hidden = state.agents.length > 0;
  $("#agents-table").closest(".table-wrap").hidden = state.agents.length === 0;
  tbody.innerHTML = state.agents.map((a) => {
    const lossCls = a.loss_pct > 5 ? "loss-bad" : "";
    const tcp = a.tcp;
    return `<tr class="data st-${a.status}">
      <td class="c-node" data-label="Узел"><div class="node-name">${esc(a.node)}</div>
        <div class="node-sub" title="${esc((a.os || "") + " " + (a.os_release || ""))}">${esc(a.os || "ОС неизвестна")}${a.groups.length ? " · группы: " + esc(a.groups.join(", ")) : ""}</div></td>
      <td class="c-status" data-label="Статус"><span class="status ${a.status}">${STATUS_RU[a.status] || a.status}</span></td>
      <td data-label="IP">${esc(a.ip || "–")}</td>
      <td data-label="Последний пакет" title="${fmt.datetime(a.last_seen)}">${fmt.ago(a.age_s)}</td>
      <td class="num" data-label="Пакеты">${fmt.num(a.packets, 0)}</td>
      <td class="num ${lossCls}" data-label="Потери" title="повторов отброшено: ${a.replay}, перезапусков: ${a.restarts}">${a.lost} (${fmt.num(a.loss_pct, 1)} %)</td>
      <td class="num" data-label="Буфер">${a.buffer} / ${a.buffer_cap}</td>
      <td class="num" data-label="Инциденты">${a.incidents}${a.open_incidents ? ` <span class="muted">(${a.open_incidents} откр.)</span>` : ""}</td>
      <td data-label="Профиль · интервал">${esc(a.profile)} · ${a.interval ? fmt.num(a.interval, 1) + " с" : "–"}</td></tr>
      <tr class="act st-${a.status}"><td colspan="9"><div class="actions">
        <button class="btn ${a.paused ? "" : "warn"}" data-act="${a.paused ? "resume" : "pause"}" data-node="${esc(a.node)}" ${tcp ? "" : "disabled"}>${a.paused ? "Продолжить" : "Пауза"}</button>
        <button class="btn" data-act="interval" data-node="${esc(a.node)}" data-val="${a.interval || 2}" ${tcp ? "" : "disabled"}>Интервал</button>
        <button class="btn" data-act="snapshot" data-node="${esc(a.node)}" ${tcp ? "" : "disabled"}>Снимок</button>
        <button class="btn" data-act="test" data-node="${esc(a.node)}">Тест-инцидент</button>
        <button class="btn ghost danger" data-act="forget" data-node="${esc(a.node)}" title="Убрать узел из списка">Забыть</button>
      </div></td></tr>`;
  }).join("");
}
async function agentAction(btn) {
  const node = btn.dataset.node, act = btn.dataset.act;
  try {
    if (act === "pause" || act === "resume") {
      const r = await post({ cmd: "agent", node, action: act });
      report(r, act === "pause" ? "Отправка метрик приостановлена" : "Отправка метрик возобновлена");
    } else if (act === "interval") {
      const v = await ask({ title: "Интервал отправки", text: `Узел ${node}. Сколько секунд между замерами (0.5–60)?`, value: btn.dataset.val, ok: "Применить" });
      if (v == null) return;
      const r = await post({ cmd: "agent", node, action: "interval", value: parseFloat(String(v).replace(",", ".")) });
      report(r, "Интервал изменён");
    } else if (act === "snapshot") {
      btn.disabled = true; btn.textContent = "Снимаю…";
      const r = await post({ cmd: "agent", node, action: "snapshot" });
      const res = r[node];
      if (res && res.ok) openDrawer(renderSnapshotCard(node, res.data));
      else toast({ title: "Снимок не получен", sub: res ? res.error : "", sev: "medium" });
    } else if (act === "test") {
      const r = await post({ cmd: "test_incident", node });
      toast({ title: "Тест-инцидент создан", sub: r.created.join(", "), sev: "info", ttl: 3000 });
    } else if (act === "forget") {
      const ok = await ask({ title: "Забыть узел?", text: `${node} исчезнет из списка. Если агент ещё работает, он появится снова. Инциденты сохранятся.`, ok: "Забыть" });
      if (!ok) return;
      await post({ cmd: "forget", node });
    }
  } catch (e) {
    if (!(e instanceof AuthError)) toast({ title: "Команда не выполнена", sub: e.message, sev: "medium" });
  }
  loadAgents().catch(() => {});
}
function report(results, okText) {
  for (const [node, r] of Object.entries(results)) {
    if (r.ok) toast({ title: okText, sub: node, sev: "info", ttl: 3000 });
    else toast({ title: "Ошибка на " + node, sub: r.error, sev: "medium" });
  }
}

// ------------------------------------------------------------------ отчёт и графики
async function loadReport() {
  const pick = $("#node-pick");
  if (!state.agents.length) {
    pick.innerHTML = ""; $("#charts").innerHTML = `<div class="empty"><h2>Нет данных</h2><p>Графики появятся, когда хотя бы один агент пришлёт метрики.</p></div>`;
    $("#summary-table tbody").innerHTML = ""; $("#report-meta").textContent = ""; $("#cores").innerHTML = "";
    return;
  }
  if (!state.agents.some((a) => a.node === state.reportNode)) state.reportNode = state.agents[0].node;
  pick.innerHTML = state.agents.map((a) =>
    `<button data-node="${esc(a.node)}" class="${a.node === state.reportNode ? "active" : ""}"><i class="dot ${a.status}"></i>${esc(a.node)}</button>`).join("");
  const data = await api("report", { node: state.reportNode, n: 300 });
  const ag = data.agent, s = data.series;
  const span = s.t.length > 1 ? s.t[s.t.length - 1] - s.t[0] : 0;
  $("#report-meta").innerHTML = `<b>${esc(data.node)}</b> — ${STATUS_RU[ag.status]}, ${s.t.length} точек за ${fmt.num(span / 60, 1)} мин,
    интервал ${fmt.num(ag.interval, 1)} с, буфер ${ag.buffer}/${ag.buffer_cap}, потери ${ag.lost}`;
  $("#cores").innerHTML = data.cores.length ? `<span class="label">Ядра CPU</span>` +
    data.cores.map((c, i) => `<div class="core" title="ядро ${i}: ${c}%"><i style="height:${Math.max(2, Math.min(100, c))}%"></i></div>`).join("") : "";
  renderCharts(s);
  $("#summary-table tbody").innerHTML = Object.entries(data.summary).map(([k, st]) => {
    const [label, f] = SUMMARY_LABELS[k] || [k, fmt.plain];
    return `<tr><td>${label}</td><td class="num">${f(st.mean)}</td><td class="num">${f(st.p95)}</td><td class="num">${f(st.max)}</td><td class="num">${f(st.last)}</td></tr>`;
  }).join("");
}
function renderCharts(series) {
  const box = $("#charts");
  if (!box.querySelector("canvas")) {
    box.innerHTML = Object.entries(METRICS).map(([k, m]) => `<div class="chart">
      <header><div><h3>${m.label}</h3><span class="key">${k}</span></div><span class="now" id="now-${k}">–</span></header>
      <canvas id="cv-${k}"></canvas></div>`).join("");
    box.querySelectorAll("canvas").forEach((cv) => {
      cv.addEventListener("pointermove", (e) => { const r = cv.getBoundingClientRect(); cv._hover = (e.clientX - r.left) / r.width; drawChart(cv); });
      cv.addEventListener("pointerleave", () => { cv._hover = null; drawChart(cv); });
    });
  }
  for (const [k, meta] of Object.entries(METRICS)) {
    const cv = $("#cv-" + k);
    cv._d = { t: series.t, v: series[k] || [], meta };
    const vals = cv._d.v;
    $("#now-" + k).textContent = vals.length ? meta.f(vals[vals.length - 1]) : "–";
    drawChart(cv);
  }
}
function drawChart(cv) {
  const d = cv._d; if (!d) return;
  const dpr = window.devicePixelRatio || 1, w = cv.clientWidth, h = cv.clientHeight;
  if (!w) return;
  cv.width = w * dpr; cv.height = h * dpr;
  const g = cv.getContext("2d"); g.setTransform(dpr, 0, 0, dpr, 0, 0); g.clearRect(0, 0, w, h);
  const L = 64, R = 6, T = 8, B = 20, pw = w - L - R, ph = h - T - B;
  const vals = d.v.map((x) => (x == null ? 0 : Number(x)));
  g.font = "11px " + getComputedStyle(document.body).fontFamily; g.fillStyle = "#8a9cad";
  if (vals.length < 2) { g.fillText("собираю данные…", L, T + ph / 2); return; }
  let lo = Math.min(...vals), hi = Math.max(...vals);
  lo = d.meta.signed ? Math.min(0, lo) : 0;
  if (hi - lo < 1e-9) hi = lo + 1;
  hi += (hi - lo) * 0.08;
  const X = (i) => L + (i / (vals.length - 1)) * pw, Y = (v) => T + ph - ((v - lo) / (hi - lo)) * ph;
  // сетка и подписи оси Y
  g.strokeStyle = "#2a3a4a"; g.lineWidth = 1; g.textAlign = "right"; g.textBaseline = "middle";
  for (let i = 0; i <= 3; i++) {
    const v = lo + ((hi - lo) * i) / 3, y = Math.round(Y(v)) + 0.5;
    g.beginPath(); g.moveTo(L, y); g.lineTo(w - R, y); g.stroke();
    g.fillText(d.meta.f(v), L - 6, y);
  }
  if (d.meta.signed && lo < 0) { g.strokeStyle = "#4a5d70"; g.beginPath(); g.moveTo(L, Y(0)); g.lineTo(w - R, Y(0)); g.stroke(); }
  // подписи времени
  g.textBaseline = "alphabetic";
  [[0, "left"], [Math.floor((vals.length - 1) / 2), "center"], [vals.length - 1, "right"]].forEach(([i, al]) => {
    g.textAlign = al; g.fillText(fmt.time(d.t[i]), X(i), h - 4);
  });
  // линия и заливка
  const grad = g.createLinearGradient(0, T, 0, T + ph);
  grad.addColorStop(0, d.meta.color + "40"); grad.addColorStop(1, d.meta.color + "00");
  g.beginPath(); vals.forEach((v, i) => (i ? g.lineTo(X(i), Y(v)) : g.moveTo(X(i), Y(v))));
  g.lineTo(X(vals.length - 1), Y(Math.max(lo, 0))); g.lineTo(X(0), Y(Math.max(lo, 0))); g.closePath();
  g.fillStyle = grad; g.fill();
  g.beginPath(); vals.forEach((v, i) => (i ? g.lineTo(X(i), Y(v)) : g.moveTo(X(i), Y(v))));
  g.strokeStyle = d.meta.color; g.lineWidth = 1.6; g.lineJoin = "round"; g.stroke();
  // наведение
  if (cv._hover != null) {
    const px = cv._hover * w;
    const i = Math.max(0, Math.min(vals.length - 1, Math.round(((px - L) / pw) * (vals.length - 1))));
    const x = X(i), y = Y(vals[i]);
    g.strokeStyle = "#8a9cad"; g.setLineDash([3, 3]); g.beginPath(); g.moveTo(x, T); g.lineTo(x, T + ph); g.stroke(); g.setLineDash([]);
    g.fillStyle = d.meta.color; g.beginPath(); g.arc(x, y, 3.5, 0, 7); g.fill();
    const label = `${fmt.time(d.t[i])}  ${d.meta.f(d.v[i])}`;
    g.font = "12px " + getComputedStyle(document.body).fontFamily;
    const tw = g.measureText(label).width + 12, bx = Math.min(Math.max(L, x - tw / 2), w - R - tw);
    g.fillStyle = "#0d141b"; g.fillRect(bx, T, tw, 20); g.strokeStyle = "#2a3a4a"; g.strokeRect(bx + 0.5, T + 0.5, tw - 1, 19);
    g.fillStyle = "#dde6ee"; g.textAlign = "left"; g.textBaseline = "middle"; g.fillText(label, bx + 6, T + 10);
  }
}

// ------------------------------------------------------------------ инциденты
function fillNodeFilter() {
  const sel = $("#f-node"), cur = sel.value;
  const nodes = state.agents.map((a) => a.node);
  sel.innerHTML = `<option value="">все</option>` + nodes.map((n) => `<option ${n === cur ? "selected" : ""}>${esc(n)}</option>`).join("");
}
async function loadIncidents() {
  const items = await api("incidents", { node: $("#f-node").value, rule: $("#f-rule").value, status: $("#f-status").value, limit: 200 });
  $("#inc-empty").hidden = items.length > 0;
  $("#inc-list").innerHTML = items.map((i) => `<li class="inc sev-${i.severity} ${i.status === "acknowledged" ? "acked" : ""}" data-id="${i.id}" tabindex="0">
      <span class="sev"></span>
      <div><div class="title">${esc(i.title)}</div>
        <div class="meta"><span class="rule">${esc(i.rule)}</span><span>${esc(i.node)}</span><span>${fmt.datetime(i.ts)}</span><span>${i.id}</span><span>важность: ${SEV_RU[i.severity] || i.severity}</span></div></div>
      <span class="pill ${i.status}">${i.status === "open" ? "открыт" : "подтверждён"}</span></li>`).join("");
}
async function openIncident(id) {
  try {
    const inc = await api("incident", { id });
    state.openIncident = id;
    openDrawer(renderIncidentCard(inc));
    if (inc.snapshot_status === "pending") setTimeout(() => { if (state.openIncident === id && $("#drawer").classList.contains("open")) openIncident(id); }, 1500);
  } catch (e) { if (!(e instanceof AuthError)) toast({ title: "Не удалось открыть инцидент", sub: e.message, sev: "medium" }); }
}
function evidenceValue(v) {
  if (v == null) return "–";
  if (typeof v === "boolean") return v ? "да" : "нет";
  if (typeof v === "object") {
    if ("ready" in v) return v.ready ? `медиана ${fmt.num(v.median, 2)}, MAD ${fmt.num(v.mad, 2)}, p95 ${fmt.num(v.p95, 2)} (${v.points} точек)` : `ещё копится (${v.points} точек)`;
    return esc(JSON.stringify(v));
  }
  return typeof v === "number" ? fmt.num(v, 2) : esc(v);
}
function procTable(rows, withCmd = false) {
  if (!rows || !rows.length) return `<p class="muted">нет данных</p>`;
  return `<div class="table-wrap"><table class="grid"><thead><tr><th>PID</th><th>Процесс</th><th>Пользователь</th><th class="num">CPU</th><th class="num">RAM</th>${withCmd ? "<th>Запущен</th>" : ""}</tr></thead><tbody>` +
    rows.map((p) => `<tr><td>${p.pid}</td><td>${esc(p.name)}${withCmd && p.cmdline ? `<div class="cmd">${esc(p.cmdline)}</div>` : ""}</td><td>${esc(p.user || "–")}</td>
      <td class="num">${fmt.pct(p.cpu)}</td><td class="num">${fmt.mb(p.rss_mb)}</td>${withCmd ? `<td>${fmt.time(p.started)}</td>` : ""}</tr>`).join("") + `</tbody></table></div>`;
}
function snapshotHtml(snap) {
  const cs = snap.conn_summary || {};
  const conns = (snap.connections || []).slice(0, 12);
  return `
    <div class="facts">
      <div class="fact"><span>Память</span><b>${fmt.mb(snap.memory.used_mb)} из ${fmt.mb(snap.memory.total_mb)} (${fmt.pct(snap.memory.percent)})</b></div>
      <div class="fact"><span>Подкачка</span><b>${fmt.mb(snap.swap.used_mb)} из ${fmt.mb(snap.swap.total_mb)}</b></div>
      <div class="fact"><span>Процессов</span><b>${snap.process_count}</b></div>
      <div class="fact"><span>Соединений</span><b>${cs.total ?? "–"}${cs.ESTABLISHED ? `, установлено ${cs.ESTABLISHED}` : ""}</b></div>
    </div>
    <h3>Топ процессов по CPU</h3>${procTable(snap.top_cpu)}
    <h3>Топ процессов по памяти</h3>${procTable(snap.top_mem)}
    <h3>Самые новые процессы</h3>${procTable(snap.newest, true)}
    <h3>Сетевые соединения</h3>${conns.length ? `<div class="table-wrap"><table class="grid"><thead><tr><th>Локальный</th><th>Удалённый</th><th>Состояние</th><th>Процесс</th></tr></thead><tbody>` +
      conns.map((c) => `<tr><td>${esc(c.laddr)}</td><td>${esc(c.raddr)}</td><td>${esc(c.status)}</td><td>${esc(c.name || c.pid || "–")}</td></tr>`).join("") + `</tbody></table></div>` : `<p class="muted">${esc(cs.error || "внешних соединений нет")}</p>`}
    <h3>Пользователи в системе</h3>${(snap.users || []).length ? `<p>${snap.users.map((u) => esc(u.name) + (u.host ? " с " + esc(u.host) : "") + (u.terminal ? ` (${esc(u.terminal)})` : "")).join(", ")}</p>` : `<p class="muted">нет активных сеансов</p>`}`;
}
function renderIncidentCard(inc) {
  const ev = Object.entries(inc.evidence || {}).map(([k, v]) => `<tr><td>${EVIDENCE_RU[k] || esc(k)}</td><td>${evidenceValue(v)}</td></tr>`).join("");
  const tail = (inc.tail || []).slice(-10);
  const tailHtml = tail.length ? `<div class="table-wrap"><table class="grid"><thead><tr><th>Время</th><th class="num">CPU польз.</th><th class="num">Сеть</th><th class="num">Диск</th><th class="num">Память</th><th class="num">Δ памяти</th><th class="num">Проц/с</th><th class="num">Потоки/с</th></tr></thead><tbody>` +
    tail.map((r) => `<tr><td>${fmt.time(r.t)}</td><td class="num">${fmt.pct(r.cpu_user)}</td><td class="num">${fmt.rate(r.net_total)}</td><td class="num">${fmt.rate(r.disk_total)}</td>
      <td class="num">${fmt.mb(r.mem_used)}</td><td class="num">${fmt.mbs(r.mem_delta)}</td><td class="num">${fmt.num(r.proc_new_ps)}</td><td class="num">${fmt.num(r.thr_new_ps)}</td></tr>`).join("") + `</tbody></table></div>` : `<p class="muted">буфер был пуст</p>`;
  const snap = inc.snapshot ? snapshotHtml(inc.snapshot) :
    `<p class="muted">${inc.snapshot_status === "pending" ? "Снимок запрошен у агента, подождите пару секунд…" : "Снимок недоступен: " + esc(inc.snapshot_status)}</p>`;
  return `<div class="card-head">
      <div class="sevline"><span class="sevtag ${inc.severity}">${SEV_RU[inc.severity] || inc.severity}</span><span>${esc(inc.rule)}</span><span>${inc.id}</span>
        <span class="pill ${inc.status}">${inc.status === "open" ? "открыт" : "подтверждён"}</span></div>
      <h2>${esc(inc.title)}</h2></div>
    <div class="facts">
      <div class="fact"><span>Узел</span><b>${esc(inc.node)}</b></div>
      <div class="fact"><span>IP</span><b>${esc(inc.ip || "–")}</b></div>
      <div class="fact"><span>Время</span><b>${fmt.datetime(inc.ts)}</b></div>
      <div class="fact"><span>Подтверждён</span><b>${inc.ack_ts ? fmt.datetime(inc.ack_ts) + " (" + esc(inc.ack_by) + ")" : "ещё нет"}</b></div>
    </div>
    <div class="card-actions">${inc.status === "open" ? `<button class="btn primary" data-ack="${inc.id}">Подтвердить</button>` : ""}
      <span class="muted">${inc.source === "test" ? "Тестовый инцидент, создан вручную" : "Обнаружен анализатором"}</span></div>
    <h3>Доказательства</h3><div class="table-wrap"><table class="grid ev-table"><tbody>${ev}</tbody></table></div>
    <h3>Последние значения метрик</h3>${tailHtml}
    <h3>Снимок состояния узла</h3>${snap}`;
}
function renderSnapshotCard(node, snap) {
  return `<div class="card-head"><div class="sevline"><span>Снимок по запросу</span><span>${fmt.datetime(snap.ts)}</span></div>
    <h2>${esc(node)}</h2></div>${snapshotHtml(snap)}`;
}
function openDrawer(html) {
  $("#drawer-body").innerHTML = html;
  $("#drawer").classList.add("open"); $("#drawer").setAttribute("aria-hidden", "false");
  $("#drawer-backdrop").hidden = false;
}
function closeDrawer() {
  state.openIncident = null;
  $("#drawer").classList.remove("open"); $("#drawer").setAttribute("aria-hidden", "true");
  $("#drawer-backdrop").hidden = true;
}

// ------------------------------------------------------------------ пороги
async function loadThresholds() {
  const data = await api("thresholds");
  state.thresholds = data.items;
  const groups = {};
  data.items.forEach((it) => (groups[it.group] = groups[it.group] || []).push(it));
  $("#th-form").innerHTML = Object.entries(groups).map(([g, items]) => `<fieldset class="th-group"><legend>${esc(g)}</legend>
      <p class="rule-desc">${esc(RULE_DESC[g] || "")}</p>${items.map(thRow).join("")}</fieldset>`).join("");
  markDirty();
}
function thRow(it) {
  const prof = Object.entries(it.profiles || {}).map(([p, v]) => `${p}: ${v}`).join(", ");
  let input;
  if (it.type === "bool") input = `<label class="switch"><input type="checkbox" name="${it.key}" ${it.value ? "checked" : ""}><span></span></label>`;
  else if (it.type === "choice") input = `<select name="${it.key}">${it.choices.map((c) => `<option ${c === it.value ? "selected" : ""}>${c}</option>`).join("")}</select>`;
  else input = `<input type="number" name="${it.key}" value="${it.value}" min="0" step="${it.type === "int" ? 1 : "any"}" inputmode="decimal">`;
  return `<div class="th-row" data-key="${it.key}"><label>${esc(it.label)}<span class="k">${it.key}${prof ? ` · <span class="prof">профиль ${esc(prof)}</span>` : ""}</span></label>${input}</div>`;
}
function readForm() {
  const changes = {};
  for (const it of state.thresholds || []) {
    const el = $("#th-form").elements[it.key]; if (!el) continue;
    let v = el.type === "checkbox" ? el.checked : el.value;
    if (it.type === "int") v = parseInt(v, 10); else if (it.type === "float") v = parseFloat(String(v).replace(",", "."));
    const row = el.closest(".th-row");
    const changed = v !== it.value && !(typeof v === "number" && isNaN(v));
    row.classList.toggle("dirty", changed);
    if (changed) changes[it.key] = v;
  }
  return changes;
}
function markDirty() {
  const n = Object.keys(readForm()).length;
  $("#th-dirty").textContent = n ? `Изменено параметров: ${n}` : "Изменений нет";
  $("#th-save").disabled = n === 0;
}

// ------------------------------------------------------------------ опрос событий
async function poll() {
  try {
    const ev = await api("events", { since: state.lastEvent ?? 0 });
    $("#sum-online").textContent = ev.agents_online;
    $("#sum-total").textContent = ev.agents_total;
    $("#sum-open").textContent = ev.open;
    $("#sum-open-wrap").classList.toggle("hot", ev.open > 0);
    const badge = $("#inc-badge");
    badge.hidden = ev.open === 0; badge.textContent = ev.open;
    if (state.lastEvent !== null && ev.events.length) {
      ev.events.slice(-3).forEach((e) => toast({
        title: `Новый инцидент на ${e.node}: ${e.rule}`, sub: `${e.title} · ${fmt.time(e.ts)} · нажмите, чтобы открыть`,
        sev: e.severity === "critical" ? "high" : e.severity, onClick: () => { switchTab("incidents"); openIncident(e.id); },
      }));
      badge.classList.remove("ping"); void badge.offsetWidth; badge.classList.add("ping");
      beep();
      if (state.tab === "incidents") loadIncidents().catch(() => {});
    }
    state.lastEvent = ev.last;
    if (state.tab !== "thresholds") await refreshTab(false);
  } catch (e) { if (!(e instanceof AuthError)) console.warn("poll", e); }
}

// ------------------------------------------------------------------ вход
function showLogin(msg = "") { $("#login").hidden = false; $("#login-error").textContent = msg; }

// ------------------------------------------------------------------ старт
async function start() {
  readToken();
  if (!state.token) { showLogin(); return; }
  try {
    const info = await api("info");
    state.rules = info.rules;
    $("#f-rule").innerHTML = `<option value="">все</option>` + Object.keys(info.rules).map((r) => `<option>${r}</option>`).join("");
    $("#login").hidden = true;
  } catch (e) { return; }
  setSound(state.sound);
  await poll();
  setInterval(poll, POLL_MS);
}

document.addEventListener("DOMContentLoaded", () => {
  $("#tabs").addEventListener("click", (e) => { const b = e.target.closest("button[data-tab]"); if (b) switchTab(b.dataset.tab); });
  $("#agents-table").addEventListener("click", (e) => { const b = e.target.closest("button[data-act]"); if (b) agentAction(b); });
  $("#node-pick").addEventListener("click", (e) => { const b = e.target.closest("button[data-node]"); if (b) { state.reportNode = b.dataset.node; loadReport().catch(() => {}); } });
  $("#inc-list").addEventListener("click", (e) => { const li = e.target.closest(".inc"); if (li) openIncident(li.dataset.id); });
  $("#inc-list").addEventListener("keydown", (e) => { const li = e.target.closest(".inc"); if (li && e.key === "Enter") openIncident(li.dataset.id); });
  ["#f-node", "#f-rule", "#f-status"].forEach((s) => $(s).addEventListener("change", () => loadIncidents().catch(() => {})));
  $("#inc-refresh").addEventListener("click", () => { loadIncidents().then(() => toast({ title: "Список обновлён", sev: "info", ttl: 1500 })).catch(() => {}); });
  $("#drawer-close").addEventListener("click", closeDrawer);
  $("#drawer-backdrop").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });
  $("#drawer-body").addEventListener("click", async (e) => {
    const b = e.target.closest("button[data-ack]"); if (!b) return;
    try {
      await post({ cmd: "ack", id: b.dataset.ack, by: "панель" });
      toast({ title: "Инцидент подтверждён", sub: b.dataset.ack, sev: "info", ttl: 2500 });
      openIncident(b.dataset.ack); loadIncidents().catch(() => {}); poll();
    } catch (err) { toast({ title: "Не удалось подтвердить", sub: err.message, sev: "medium" }); }
  });
  $("#th-form").addEventListener("input", markDirty);
  $("#th-form").addEventListener("change", markDirty);
  $("#th-save").addEventListener("click", async () => {
    const changes = readForm(); if (!Object.keys(changes).length) return;
    try {
      await post({ cmd: "thresholds", set: changes });
      toast({ title: "Пороги сохранены", sub: Object.keys(changes).join(", "), sev: "info", ttl: 3000 });
      loadThresholds();
    } catch (e) { toast({ title: "Пороги не сохранены", sub: e.message, sev: "medium" }); }
  });
  $("#th-reset").addEventListener("click", async () => {
    if (!(await ask({ title: "Сбросить пороги?", text: "Все параметры вернутся к значениям по умолчанию.", ok: "Сбросить" }))) return;
    await post({ cmd: "thresholds", reset: true });
    toast({ title: "Пороги сброшены", sev: "info", ttl: 2500 });
    loadThresholds();
  });
  $("#sound-btn").addEventListener("click", () => setSound(!state.sound));
  $("#login-form").addEventListener("submit", (e) => {
    e.preventDefault();
    state.token = $("#login-token").value.trim().replace(/^.*token=/, "");
    try { localStorage.setItem("nw_token", state.token); } catch (err) { /* ok */ }
    start();
  });
  window.addEventListener("resize", () => document.querySelectorAll(".charts canvas").forEach(drawChart));
  start();
});
