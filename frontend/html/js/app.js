// Sentinel dashboard controller.
const App = (() => {
  let me = null;
  let ws = null;
  let resourceChart = null;
  let netChart = null;
  let pollTimer = null;

  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const sevBadge = (s) => `<span class="badge sev-${esc(s)}">${esc(s)}</span>`;
  const kb = (bps) => (bps / 1024).toFixed(1);
  const fmtUptime = (s) => {
    const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    return (d ? d + "d " : "") + h + "h " + m + "m";
  };

  function toast(msg, ok = true) {
    const t = $("toast");
    t.textContent = msg;
    t.className = "toast " + (ok ? "ok" : "bad");
    setTimeout(() => t.classList.add("hidden"), 4000);
  }

  // ---------- Auth / boot ----------
  async function boot() {
    if (!Api.getToken()) return showLogin();
    try {
      me = await Api.get("/api/auth/me");
      showApp();
    } catch {
      showLogin();
    }
  }

  function showLogin() {
    $("login").classList.remove("hidden");
    $("app").classList.add("hidden");
  }

  async function showApp() {
    $("login").classList.add("hidden");
    $("app").classList.remove("hidden");
    $("who").textContent = me.username + " (" + me.role + ")";
    if (me.role !== "admin") {
      document.querySelectorAll(".admin-only").forEach((e) => e.classList.add("hidden"));
    }
    initCharts();
    connectWs();
    await loadHost();
    await refreshAll();
    pollTimer = setInterval(refreshActiveTab, 5000);
  }

  // ---------- WebSocket live metrics ----------
  function connectWs() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    ws = new WebSocket(`${proto}://${location.host}/api/ws?token=${Api.getToken()}`);
    ws.onopen = () => $("ws-status").className = "dot online";
    ws.onclose = () => { $("ws-status").className = "dot offline"; setTimeout(connectWs, 5000); };
    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data);
      if (msg.type === "metric") applyLiveMetric(msg.data);
    };
  }

  function applyLiveMetric(d) {
    $("m-cpu").textContent = d.cpu_percent;
    $("m-mem").textContent = d.mem_percent;
    $("m-disk").textContent = d.disk_percent;
    $("m-load").textContent = d.load1;
    $("m-net-rx").textContent = kb(d.net_recv_bps);
    $("m-net-tx").textContent = kb(d.net_sent_bps);
    pushChart(resourceChart, [d.cpu_percent, d.mem_percent, d.disk_percent]);
    pushChart(netChart, [d.net_recv_bps / 1024, d.net_sent_bps / 1024]);
  }

  // ---------- Charts ----------
  const MAX_POINTS = 60;
  function initCharts() {
    const common = {
      responsive: true, animation: false, maintainAspectRatio: false,
      scales: { x: { display: false }, y: { beginAtZero: true, ticks: { color: "#8b949e" }, grid: { color: "#2a3441" } } },
      plugins: { legend: { labels: { color: "#8b949e", boxWidth: 12 } } },
    };
    resourceChart = new Chart($("chart-resources"), {
      type: "line",
      data: { labels: [], datasets: [
        ds("CPU %", "#2f81f7"), ds("Mem %", "#3fb950"), ds("Disk %", "#d29922")] },
      options: { ...common, scales: { ...common.scales, y: { ...common.scales.y, max: 100 } } },
    });
    netChart = new Chart($("chart-net"), {
      type: "line",
      data: { labels: [], datasets: [ds("RX KB/s", "#79c0ff"), ds("TX KB/s", "#ff7b72")] },
      options: common,
    });
  }
  const ds = (label, color) => ({
    label, data: [], borderColor: color, backgroundColor: color + "22",
    borderWidth: 2, pointRadius: 0, tension: 0.3, fill: true,
  });
  function pushChart(chart, values) {
    if (!chart) return;
    chart.data.labels.push("");
    values.forEach((v, i) => chart.data.datasets[i].data.push(v));
    if (chart.data.labels.length > MAX_POINTS) {
      chart.data.labels.shift();
      chart.data.datasets.forEach((d) => d.data.shift());
    }
    chart.update("none");
  }

  // ---------- Tabs ----------
  function switchTab(name) {
    document.querySelectorAll(".nav-btn").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
    document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.id === "tab-" + name));
    $("page-title").textContent = document.querySelector(`[data-tab="${name}"]`).textContent.replace(/^\S+\s/, "");
    refreshActiveTab();
  }
  function activeTab() {
    const el = document.querySelector(".tab.active");
    return el ? el.id.replace("tab-", "") : "overview";
  }

  // ---------- Loaders ----------
  async function loadHost() {
    try {
      const h = await Api.get("/api/system/host");
      $("host-os").textContent = h.os || "unknown";
    } catch {}
  }

  async function refreshAll() { await refreshActiveTab(); await loadOverviewExtras(); }

  async function refreshActiveTab() {
    const tab = activeTab();
    try {
      if (tab === "overview") await loadOverviewExtras();
      else if (tab === "security") await loadSecurity();
      else if (tab === "firewall") await loadFirewall();
      else if (tab === "events") await loadEvents();
      else if (tab === "logs") await loadLogFiles();
      else if (tab === "services") await loadServices();
      else if (tab === "updates") await loadUpdates();
      else if (tab === "audit") await loadAudit();
    } catch (e) { /* surfaced per-action */ }
  }

  async function loadOverviewExtras() {
    try {
      const [live, det, procs, posture, alerts, events] = await Promise.all([
        Api.get("/api/system/live"),
        Api.get("/api/system/detailed"),
        Api.get("/api/system/processes?limit=8"),
        Api.get("/api/security/posture"),
        Api.get("/api/alerts?only_open=true&limit=100"),
        Api.get("/api/logs/events?limit=8"),
      ]);
      applyLiveMetric(live);
      $("host-uptime").textContent = fmtUptime(det.uptime_seconds);
      $("m-score").textContent = posture.score;
      $("m-alerts").textContent = alerts.length;
      $("proc-table").innerHTML = table(["PID", "Name", "User", "CPU%", "Mem%"],
        procs.map((p) => [p.pid, esc(p.name), esc(p.user), p.cpu, p.mem]));
      $("overview-events").innerHTML = eventsTable(events, true);
    } catch (e) {}
  }

  async function loadSecurity() {
    const p = await Api.get("/api/security/posture");
    $("sec-score").textContent = p.score;
    const ring = document.querySelector(".score-ring");
    ring.style.borderColor = p.score >= 80 ? "var(--ok)" : p.score >= 50 ? "var(--warn)" : "var(--crit)";
    $("sec-checks").innerHTML = p.checks.map((c) =>
      `<div class="check"><span class="mark ${c.ok ? "ok-text" : "bad-text"}">${c.ok ? "✓" : "✗"}</span>
       <span title="${esc(c.hint)}">${esc(c.name)}</span></div>`).join("");

    const ports = await Api.get("/api/security/ports");
    $("ports-table").innerHTML = table(["Proto", "Address", "Process", "Exposed"],
      ports.map((x) => [x.proto, esc(x.address), esc(x.process),
        x.exposed ? '<span class="bad-text">yes</span>' : '<span class="ok-text">no</span>']));

    const s = await Api.get("/api/security/sessions");
    $("sessions-box").innerHTML =
      "<b>Logged in:</b><br>" + (s.logged_in.map((u) => `${esc(u.user)} @ ${esc(u.tty)} ${esc(u.from)}`).join("<br>") || "<span class='muted'>none</span>") +
      "<br><br><b>Recent failed logins:</b><pre class='output'>" + esc((s.failed_logins || []).join("\n") || "none") + "</pre>";

    const f = await Api.get("/api/security/fail2ban");
    if (!f.available) { $("f2b-box").innerHTML = "<span class='muted'>fail2ban not available</span>"; }
    else {
      $("f2b-box").innerHTML = f.jails.map((j) =>
        `<div><b>${esc(j.jail)}</b> — banned ${j.currently_banned}, total ${j.total_banned}
         ${(j.banned_ips || []).map((ip) => `<div class="badge sev-high">${esc(ip)}
         ${me.role === "admin" ? `<a class="link" onclick="App.unban('${esc(j.jail)}','${esc(ip)}')">unban</a>` : ""}</div>`).join(" ")}</div>`).join("<hr>") || "no jails";
    }
  }

  async function loadFirewall() {
    const s = await Api.get("/api/firewall/status");
    if (!s.available) { $("fw-status").innerHTML = "<span class='warn-text'>UFW not reachable. Enable host commands (see SECURITY.md).</span>"; $("fw-rules").innerHTML = ""; return; }
    $("fw-status").innerHTML = `Status: <b class="${s.enabled ? "ok-text" : "bad-text"}">${s.enabled ? "active" : "inactive"}</b> · ${esc(s.default || "")}`;
    $("fw-rules").innerHTML = table(["#", "To", "Action", "From", ""],
      s.rules.map((r, i) => [i + 1, esc(r.to), esc(r.action), esc(r.from),
        me.role === "admin" ? `<button class="btn sm warn" onclick="App.delRule(${i + 1})">del</button>` : ""]));
  }

  async function loadEvents() {
    const sev = $("ev-sev").value, src = $("ev-src").value;
    let q = "/api/logs/events?limit=300";
    if (sev) q += "&severity=" + sev;
    if (src) q += "&source=" + src;
    const events = await Api.get(q);
    $("events-table").innerHTML = eventsTable(events, false);
  }

  async function loadLogFiles() {
    const files = await Api.get("/api/logs/files");
    $("log-files").innerHTML = table(["File", "Size (KB)", ""],
      files.map((f) => [esc(f.name), f.size_kb,
        `<button class="btn sm" onclick="App.viewLog('${esc(f.name)}')">view</button>`]));
  }

  async function loadServices() {
    const svc = await Api.get("/api/services");
    $("svc-table").innerHTML = table(["Service", "Active", "Enabled", me.role === "admin" ? "Actions" : ""],
      svc.map((s) => [esc(s.name),
        `<span class="${s.running ? "ok-text" : "bad-text"}">${esc(s.active)}</span>`,
        esc(s.enabled),
        me.role === "admin"
          ? `<button class="btn sm ok" onclick="App.svc('${esc(s.name)}','restart')">restart</button>
             <button class="btn sm warn" onclick="App.svc('${esc(s.name)}','stop')">stop</button>` : ""]));
  }

  async function loadUpdates() {
    const u = await Api.get("/api/services/updates/available");
    if (!u.available) { $("upd-summary").innerHTML = "<span class='muted'>apt not reachable (host commands disabled).</span>"; return; }
    $("upd-summary").innerHTML = `<b>${u.count}</b> upgradable · <b class="warn-text">${u.security_count}</b> security`;
    $("upd-list").innerHTML = table(["Package", "Security"],
      u.packages.map((p) => [esc(p.name), p.security ? '<span class="bad-text">security</span>' : ""]));
  }

  async function loadAudit() {
    const a = await Api.get("/api/audit");
    $("audit-table").innerHTML = table(["Time", "User", "Action", "Target", "OK"],
      a.map((x) => [new Date(x.ts).toLocaleString(), esc(x.username), esc(x.action), esc(x.target),
        x.success ? '<span class="ok-text">✓</span>' : '<span class="bad-text">✗</span>']));
  }

  // ---------- Helpers ----------
  function table(headers, rows) {
    if (!rows.length) return "<p class='muted'>No data.</p>";
    return `<table><thead><tr>${headers.map((h) => `<th>${h}</th>`).join("")}</tr></thead>
      <tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
  }
  function eventsTable(events, compact) {
    if (!events.length) return "<p class='muted'>No events.</p>";
    const rows = events.map((e) => [new Date(e.ts).toLocaleTimeString(), sevBadge(e.severity),
      esc(e.source), esc(e.message), esc(e.host_ip || "")]);
    return table(compact ? ["Time", "Sev", "Src", "Message", "IP"] : ["Time", "Severity", "Source", "Message", "IP"], rows);
  }

  // ---------- Actions ----------
  async function action(promise, okMsg) {
    try { const r = await promise; if (r && r.success === false) toast(r.error || "failed", false);
      else toast(okMsg, true); await refreshActiveTab(); return r; }
    catch (e) { toast(e.message, false); }
  }

  return {
    init() {
      $("login-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        $("login-error").textContent = "";
        try { await Api.login($("username").value, $("password").value); await boot(); }
        catch (err) { $("login-error").textContent = err.message; }
      });
      $("logout").addEventListener("click", () => { Api.clearToken(); if (ws) ws.close(); clearInterval(pollTimer); location.reload(); });
      document.querySelectorAll(".nav-btn").forEach((b) => b.addEventListener("click", () => switchTab(b.dataset.tab)));
      boot();
    },
    loadEvents,
    fw: (a) => action(Api.post("/api/firewall/" + a), "Firewall: " + a),
    addRule() {
      const body = { port: parseInt($("fw-port").value), protocol: $("fw-proto").value,
        action: $("fw-action").value, from_ip: $("fw-from").value || null, comment: $("fw-comment").value || null };
      if (!body.port) return toast("Enter a port", false);
      action(Api.post("/api/firewall/rule", body), "Rule added");
    },
    delRule: (n) => action(Api.del("/api/firewall/rule/" + n), "Rule deleted"),
    svc: (name, act) => action(Api.post(`/api/services/${name}/${act}`), `${name}: ${act}`),
    unban: (jail, ip) => action(Api.post(`/api/security/fail2ban/${jail}/unban/${ip}`), "Unbanned " + ip),
    refreshUpdates: () => action(Api.post("/api/services/updates/refresh"), "Index refreshed"),
    applySecurity: () => action(Api.post("/api/services/updates/security"), "Security updates applied"),
    async scan(tool) {
      $("scan-output").textContent = "Running " + tool + " … (this can take minutes)";
      try { const r = await Api.post("/api/security/scan/" + tool);
        $("scan-output").textContent = (r.output || "") + (r.error ? "\n[stderr]\n" + r.error : ""); }
      catch (e) { $("scan-output").textContent = "Error: " + e.message; }
    },
    async viewLog(name) {
      $("log-title").textContent = name;
      const r = await Api.get("/api/logs/files/" + encodeURIComponent(name) + "?lines=400");
      $("log-view").textContent = (r.lines || []).join("");
    },
  };
})();

document.addEventListener("DOMContentLoaded", App.init);
