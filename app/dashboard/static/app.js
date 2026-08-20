/* HoneyPork dashboard client. */
(function () {
  "use strict";

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function fmtTime(ts) {
    if (!ts) return "";
    const d = new Date(ts * 1000);
    return d.toLocaleString();
  }

  function fmtDetails(details) {
    if (!details) return "";
    try {
      const o = typeof details === "string" ? JSON.parse(details) : details;
      return esc(JSON.stringify(o));
    } catch (e) {
      return esc(details);
    }
  }

  async function api(path, opts) {
    const resp = await fetch(path, opts);
    if (resp.status === 401) {
      window.location.href = "/login";
      throw new Error("unauthenticated");
    }
    return resp.json();
  }

  function renderStats(stats) {
    const el = document.getElementById("stats");
    const cards = [
      ["events", "Events", stats.events],
      ["credentials", "Credentials", stats.credentials],
      ["sessions", "Sessions", stats.sessions],
      ["alerts", "Alerts", stats.alerts],
    ];
    let html = "";
    for (const [key, label, val] of cards) {
      html +=
        '<div class="card stat"><div class="num">' + val +
        '</div><div class="label">' + label + "</div></div>";
    }
    el.innerHTML = html;
  }

  function renderServices(services) {
    const el = document.getElementById("services");
    if (!services || !services.length) {
      el.innerHTML = '<div class="empty">No services registered</div>';
      return;
    }
    let html = "";
    for (const s of services) {
      html +=
        '<div class="service">' +
        '<div><div class="name">' + esc(s.display_name || s.name) + "</div>" +
        '<div class="port">port ' + s.port + "</div></div>" +
        '<label class="switch"><input type="checkbox" data-service="' + esc(s.name) + '"' +
        (s.enabled ? " checked" : "") + ">" +
        '<span class="slider"></span></label></div>';
    }
    el.innerHTML = html;
    el.querySelectorAll("input[data-service]").forEach(function (input) {
      input.addEventListener("change", function () {
        const name = input.dataset.service;
        const enabled = input.checked;
        api("/api/services/" + encodeURIComponent(name) + "/toggle", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ enabled: enabled }),
        }).then(function (res) {
          renderServices(res.services);
        });
      });
    });
  }

  function renderEvents(events) {
    const tbody = document.querySelector("#events-table tbody");
    if (!events || !events.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty">No events yet</td></tr>';
      return;
    }
    let html = "";
    for (const e of events) {
      html +=
        "<tr><td class='nowrap mono'>" + fmtTime(e.ts) + "</td>" +
        "<td>" + esc(e.service) + "</td>" +
        "<td class='mono'>" + esc(e.source_ip) + "</td>" +
        "<td>" + esc(e.event_type) + "</td>" +
        "<td class='wrap-cell muted'>" + fmtDetails(e.details) + "</td></tr>";
    }
    tbody.innerHTML = html;
  }

  function renderCreds(creds) {
    const tbody = document.querySelector("#creds-table tbody");
    if (!creds || !creds.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty">No credentials captured</td></tr>';
      return;
    }
    let html = "";
    for (const c of creds) {
      html +=
        "<tr><td class='nowrap mono'>" + fmtTime(c.ts) + "</td>" +
        "<td>" + esc(c.service) + "</td>" +
        "<td class='mono'>" + esc(c.source_ip) + "</td>" +
        "<td class='mono'>" + esc(c.username) + "</td>" +
        "<td class='mono wrap-cell'>" + esc(c.secret) + "</td></tr>";
    }
    tbody.innerHTML = html;
  }

  function renderAlerts(alerts) {
    const tbody = document.querySelector("#alerts-table tbody");
    if (!alerts || !alerts.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty">No alerts</td></tr>';
      return;
    }
    let html = "";
    for (const a of alerts) {
      const badge =
        '<span class="badge ' + esc(a.severity) + '">' + esc(a.severity) + "</span>";
      const ackBtn = a.acknowledged
        ? '<span class="muted" style="font-size:12px">acknowledged</span>'
        : '<button class="btn danger" data-ack="' + a.id + '" style="padding:3px 8px">ack</button>';
      html +=
        "<tr><td class='nowrap mono'>" + fmtTime(a.ts) + "</td>" +
        "<td>" + badge + "</td>" +
        "<td>" + esc(a.type) + "</td>" +
        "<td class='mono'>" + esc(a.source_ip || "") + "</td>" +
        "<td class='wrap-cell'>" + esc(a.description) + "</td>" +
        "<td class='nowrap'>" + ackBtn + "</td></tr>";
    }
    tbody.innerHTML = html;
    tbody.querySelectorAll("button[data-ack]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        api("/api/alerts/" + btn.dataset.ack + "/ack", { method: "POST" }).then(refreshAlerts);
      });
    });
  }

  async function refreshStats() {
    try {
      const stats = await api("/api/stats");
      renderStats(stats);
      renderServices(stats.services);
    } catch (e) { /* handled */ }
  }

  async function refreshEvents() {
    try {
      const d = await api("/api/events?limit=200");
      renderEvents(d.events);
    } catch (e) { /* handled */ }
  }

  async function refreshCreds() {
    try {
      const d = await api("/api/credentials?limit=200");
      renderCreds(d.credentials);
    } catch (e) { /* handled */ }
  }

  async function refreshAlerts() {
    try {
      const unacked = document.getElementById("alerts-unacked").checked;
      const d = await api("/api/alerts?limit=200&unacked=" + unacked);
      renderAlerts(d.alerts);
    } catch (e) { /* handled */ }
  }

  function refreshAll() {
    refreshStats();
    refreshEvents();
    refreshCreds();
    refreshAlerts();
  }

  // Theme toggle
  function initTheme() {
    const btn = document.getElementById("theme-toggle");
    if (!btn) return;
    btn.addEventListener("click", function () {
      const isLight = document.documentElement.getAttribute("data-theme") === "light";
      const next = isLight ? "dark" : "light";
      if (next === "light") {
        document.documentElement.setAttribute("data-theme", "light");
      } else {
        document.documentElement.removeAttribute("data-theme");
      }
      try { localStorage.setItem("honeypork-theme", next); } catch (e) {}
    });
  }

  // Telegram config
  function loadTelegram() {
    api("/api/settings/telegram").then(function (d) {
      document.getElementById("tg-chat").value = d.chat_id || "";
      document.getElementById("tg-token").placeholder = d.has_token
        ? "Saved (" + d.token_masked + ")"
        : "Paste bot token";
      document.getElementById("tg-status").textContent = d.has_token ? "configured" : "not configured";
    });
  }

  document.getElementById("tg-save").addEventListener("click", function () {
    const token = document.getElementById("tg-token").value.trim();
    const chat = document.getElementById("tg-chat").value.trim();
    api("/api/settings/telegram", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: token, chat_id: chat }),
    }).then(function (d) {
      document.getElementById("tg-token").value = "";
      document.getElementById("tg-status").textContent = d.configured ? "saved & configured" : "saved";
      loadTelegram();
    });
  });

  document.getElementById("tg-test").addEventListener("click", function () {
    const status = document.getElementById("tg-status");
    status.textContent = "sending...";
    api("/api/telegram/test", { method: "POST" }).then(function (d) {
      status.textContent = d.ok ? "test sent" : "failed to send";
    });
  });

  document.getElementById("alerts-unacked").addEventListener("change", refreshAlerts);

  document.getElementById("alerts-ack-all").addEventListener("click", function () {
    api("/api/alerts?limit=200&unacked=true").then(function (d) {
      const ids = (d.alerts || []).map(function (a) { return a.id; });
      Promise.all(
        ids.map(function (id) {
          return api("/api/alerts/" + id + "/ack", { method: "POST" });
        })
      ).then(refreshAlerts);
    });
  });

  refreshAll();
  loadTelegram();
  initTheme();
  setInterval(refreshAll, 5000);
})();
