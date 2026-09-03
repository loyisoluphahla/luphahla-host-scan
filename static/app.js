/* app.js - Luphahla Bugscan dashboard (v4 - complete single file) */
(function () {
"use strict";

/* ---------- API base ---------- */
var API_BASE = "";
if (!/(^|\.)onrender\.com$/.test(location.hostname)) {
  API_BASE = window.LUPHAHLA_API_URL || "https://luphahla-bugscan.onrender.com";
}

/* ---------- state ---------- */
var state = {
  country: "zw",
  config: null,
  last: null,
  searchTerm: "",
  sortMode: "fastest",
  filterVerdict: "working",
  lastCycle: 0,
  history: [],
  timer: null
};

/* ---------- helpers ---------- */
function $(id) { return document.getElementById(id); }

function setText(id, value) {
  var el = $(id);
  if (el) el.textContent = value;
}

function esc(v) {
  return String(v == null ? "" : v).replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;",
             '"': "&quot;", "'": "&#39;" }[c];
  });
}

function fmtTime(epoch) {
  if (!epoch) return "-";
  return new Date(epoch * 1000).toISOString().replace("T", " ").slice(0, 16) + " UTC";
}

function fmtKbps(k) {
  if (k == null) return "-";
  if (k >= 1000) return (k / 1000).toFixed(1) + " MB/s";
  return k.toFixed(1) + " KB/s";
}

function setStatus(mode) {
  var pill = $("statusPill");
  var text = $("statusText");
  if (pill) pill.className = "status-pill " + mode;
  if (text) {
    if (mode === "is-live") text.textContent = "LIVE";
    else if (mode === "is-error") text.textContent = "Backend unreachable";
    else text.textContent = "Connecting...";
  }
}

function showError(msg) {
  setText("errorText", msg);
  if ($("errorBanner")) $("errorBanner").hidden = false;
}

function hideError() {
  if ($("errorBanner")) $("errorBanner").hidden = true;
}

var toastTimer = null;
function toast(msg) {
  var el = $("toast");
  if (!el) return;
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(function () { el.hidden = true; }, 4000);
}

/* ---------- network (retry once for Render cold start) ---------- */
function fetchJSON(url, attempt) {
  attempt = attempt || 1;
  return fetch(url).then(function (r) {
    if (!r.ok) throw new Error("HTTP " + r.status);
    return r.json();
  }).catch(function (err) {
    if (attempt < 2) {
      return new Promise(function (res) { setTimeout(res, 3000); })
        .then(function () { return fetchJSON(url, attempt + 1); });
    }
    throw err;
  });
}

function postJSON(url, body) {
  return fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {})
  }).then(function (r) {
    if (!r.ok) throw new Error("HTTP " + r.status);
    return r.json();
  });
}

/* ---------- data ---------- */
function loadConfig() {
  return fetchJSON(API_BASE + "/api/config").then(function (cfg) {
    state.config = cfg;
    state.country = cfg.default_country || state.country;
    renderConfig(cfg);
    renderCountrySelect();
    updateFeedLinks();
    setStatus("is-live");
  });
}

function loadResults() {
  pollOnce();
  if (state.timer) clearInterval(state.timer);
  state.timer = setInterval(pollOnce, 30000);
}

function pollOnce() {
  var url = API_BASE + "/api/results?country=" + encodeURIComponent(state.country);
  return fetchJSON(url).then(function (data) {
    state.last = data;
    renderResults(data);
    hideError();
    setStatus("is-live");
  }).catch(function (err) {
    setStatus("is-error");
    showError("Backend unreachable: " + err.message);
  });
}

function forceScan() {
  toast("Rescan requested...");
  postJSON(API_BASE + "/api/scan", { country: state.country })
    .then(function () {
      toast("Rescan started - verifying hosts now");
      pollOnce();
    })
    .catch(function (err) {
      toast("Rescan failed: " + err.message);
    });
}

function switchCountry(cc) {
  if (!cc || cc === state.country) return;
  state.country = cc;
  renderCountrySelect();
  updateFeedLinks();
  pollOnce();
}

/* ---------- rendering ---------- */
function renderConfig(cfg) {
  setText("cfgService", cfg.tool || "Luphahla Bugscan");
  setText("cfgDefault", (cfg.default_country || "").toUpperCase());
  setText("cfgCountries", Object.keys(cfg.countries || {}).length + " regions");
  setText("cfgPorts", (cfg.ports || []).join(", "));
  var s = cfg.reverify_every_s || 0;
  setText("cfgReverify", s % 3600 === 0 ? (s / 3600) + " h" : (s / 60) + " min");

  if (cfg.endpoints && $("cfgEndpoints")) {
    var list = $("cfgEndpoints");
    var html = "";
    for (var name in cfg.endpoints) {
      if (Object.prototype.hasOwnProperty.call(cfg.endpoints, name)) {
        html += "<li>" + esc(name) + " -&gt; " + esc(cfg.endpoints[name]) + "</li>";
      }
    }
    list.innerHTML = html;
  }
  if (cfg.ports) setText("scanPorts", cfg.ports.join(", "));
  setText("sumCountry", (cfg.default_country || "").toUpperCase());
}

function renderCountrySelect() {
  var sel = $("countrySelect");
  if (!sel || !state.config) return;
  var html = "";
  var countries = state.config.countries || {};
  for (var code in countries) {
    if (!Object.prototype.hasOwnProperty.call(countries, code)) continue;
    var label = countries[code].label || code.toUpperCase();
    html += '<option value="' + esc(code) + '"' +
            (code === state.country ? " selected" : "") + ">" +
            esc(label) + "</option>";
  }
  sel.innerHTML = html;
  sel.value = state.country;
}

function updateFeedLinks() {
  var cc = encodeURIComponent(state.country);
  if ($("feedHosts")) $("feedHosts").href = API_BASE + "/hosts?country=" + cc;
  if ($("feedTop")) $("feedTop").href = API_BASE + "/top?country=" + cc;
  if ($("feedApi")) $("feedApi").href = API_BASE + "/api/results?country=" + cc;
}

function countWorking(rows) {
  var n = 0;
  for (var i = 0; i < rows.length; i++) {
    if (rows[i].verdict === "fast" || rows[i].verdict === "usable") n++;
  }
  return n;
}

function verdictRank(r) {
  if (r.verdict === "fast") return 0;
  if (r.verdict === "usable") return 1;
  return 2;
}

function filterRows(rows) {
  var out = [];
  var term = state.searchTerm;
  for (var i = 0; i < rows.length; i++) {
    var r = rows[i];
    var isWorking = r.verdict === "fast" || r.verdict === "usable";
    if (state.filterVerdict === "working" && !isWorking) continue;
    if (state.filterVerdict === "fast" && r.verdict !== "fast") continue;
    if (state.filterVerdict === "usable" && r.verdict !== "usable") continue;
    if (state.filterVerdict === "blocked" && isWorking) continue;
    if (term && r.host.toLowerCase().indexOf(term) === -1) continue;
    out.push(r);
  }
  out.sort(function (a, b) {
    if (state.sortMode === "name") return a.host < b.host ? -1 : 1;
    if (state.sortMode === "status") {
      return (a.status_code || 999) - (b.status_code || 999);
    }
    var w = verdictRank(a) - verdictRank(b);
    if (w) return w;
    return (b.speed_kbps || 0) - (a.speed_kbps || 0);
  });
  return out;
}

function verdictClass(v) {
  if (v === "fast") return "v-fast";
  if (v === "usable") return "v-usable";
  if (v === "throttled") return "v-throt";
  if (v === "proxy-mitm") return "v-mitm";
  return "v-tls";
}

function renderResults(data) {
  var rows = data.results || [];
  var working = countWorking(rows);

  setText("verifiedCount", working + " / " + rows.length);
  setText("sumCountry", (data.country || state.country).toUpperCase());
  setText("lastScan", data.last_epoch ? fmtTime(data.last_epoch) : "-");
  setText("lastCycle", data.scan_count ? "cycle #" + data.scan_count : "-");
  setText("scanPhase", data.phase || (data.scanning ? "scanning" : "idle"));

  /* top 3 fastest */
  var topList = $("topFastList");
  if (topList) {
    var fast = [];
    for (var i = 0; i < rows.length; i++) {
      if (rows[i].verdict === "fast") fast.push(rows[i]);
    }
    fast.sort(function (a, b) { return (b.speed_kbps || 0) - (a.speed_kbps || 0); });
    fast = fast.slice(0, 3);
    if (!fast.length) {
      topList.innerHTML = '<div class="empty-state">No verified hosts yet.</div>';
    } else {
      var thtml = "";
      for (var j = 0; j < fast.length; j++) {
        thtml += '<div class="top-row"><span class="mono">' + esc(fast[j].host) +
                 "</span><span>" + fmtKbps(fast[j].speed_kbps) + "</span></div>";
      }
      topList.innerHTML = thtml;
    }
  }

  renderHosts(rows);
  detectCycleEvents(data);
}

function renderHosts(rows) {
  var body = $("rowsBody");
  var filtered = filterRows(rows);
  if ($("hostsCounter")) {
    $("hostsCounter").textContent = filtered.length + " hosts";
  }
  if (!body) return;

  if (!filtered.length) {
    body.innerHTML = '<tr><td colspan="6" class="empty-state">' +
      (rows.length ? "No results match." : "No hosts yet - scan is still running.") +
      "</td></tr>";
    return;
  }
  var html = "";
  for (var i = 0; i < filtered.length; i++) {
    var r = filtered[i];
    html += '<tr data-index="' + i + '">' +
            "<td>" + (i + 1) + "</td>" +
            '<td class="mono">' + esc(r.host) + "</td>" +
            "<td>" + r.port + "</td>" +
            '<td class="' + verdictClass(r.verdict) + '">' + esc(r.verdict) + "</td>" +
            "<td>" + fmtKbps(r.speed_kbps) + "</td>" +
            "<td>" + esc(r.server_header || "-") + "</td></tr>";
  }
  body.innerHTML = html;
}

function detectCycleEvents(data) {
  var cycle = data.scan_count || 0;
  var working = countWorking(data.results || []);
  if (state.lastCycle === 0 && cycle > 0 && !data.scanning) {
    pushHistory("Results loaded (cycle #" + cycle + ") - " + working + " verified", "done");
  } else if (cycle > state.lastCycle) {
    pushHistory("Scan cycle #" + cycle + " complete - " + working + " verified", "done");
  }
  state.lastCycle = Math.max(state.lastCycle, cycle);
  renderHistory();
}

function pushHistory(text, kind) {
  state.history.unshift({ text: text, kind: kind || "done", time: fmtTime(Date.now() / 1000) });
  if (state.history.length > 50) state.history.length = 50;
}

function renderHistory() {
  var list = $("historyList");
  var empty = $("historyEmpty");
  if (empty) empty.hidden = state.history.length > 0;
  if (!list) return;
  var html = "";
  for (var i = 0; i < state.history.length; i++) {
    html += '<div class="history-row is-' + esc(state.history[i].kind) + '">' +
            "<span>" + esc(state.history[i].text) + "</span><span>" +
            esc(state.history[i].time) + "</span></div>";
  }
  list.innerHTML = html;
}

/* ---------- view switching ---------- */
function gotoView(name) {
  var views = document.querySelectorAll(".view");
  for (var i = 0; i < views.length; i++) {
    views[i].hidden = views[i].getAttribute("data-view") !== name;
  }
  var btns = document.querySelectorAll("[data-goto]");
  for (var j = 0; j < btns.length; j++) {
    var b = btns[j];
    if (b.classList.contains("nav-btn")) {
      b.classList.toggle("is-active", b.getAttribute("data-goto") === name);
    }
  }
  var menu = $("mobileMenu");
  if (menu && !menu.hidden) {
    menu.hidden = true;
    if ($("menuBtn")) $("menuBtn").setAttribute("aria-expanded", "false");
  }
  window.scrollTo(0, 0);
}

/* ---------- row detail ---------- */
function toggleDetail(tr) {
  var next = tr.nextElementSibling;
  if (next && next.classList.contains("detail-row")) {
    next.remove();
    return;
  }
  var idx = Number(tr.getAttribute("data-index"));
  var rows = state.last ? filterRows(state.last.results || []) : [];
  var r = rows[idx];
  if (!r) return;
  var detail = document.createElement("tr");
  detail.className = "detail-row";
  detail.innerHTML = "<td></td><td colspan=\"5\"><div class=\"detail-grid\">" +
    "<div><b>Host:</b> " + esc(r.host) + "</div>" +
    "<div><b>Port:</b> " + r.port + "</div>" +
    "<div><b>Verdict:</b> " + esc(r.verdict) + "</div>" +
    "<div><b>Reason:</b> " + esc(r.reason || "n/a") + "</div>" +
    "<div><b>Latency:</b> " + (r.latency_ms != null ? r.latency_ms + " ms" : "n/a") + "</div>" +
    "<div><b>Status code:</b> " + (r.status_code != null ? r.status_code : "n/a") + "</div>" +
    "<div><b>Server header:</b> " + esc(r.server_header || "n/a") + "</div>" +
    "</div></td>";
  tr.after(detail);
}

/* ---------- wiring ---------- */
function wire() {
  document.addEventListener("click", function (ev) {
    var el = ev.target.closest ? ev.target.closest("[data-goto]") : null;
    if (el) {
      ev.preventDefault();
      gotoView(el.getAttribute("data-goto"));
    }
  });

  if ($("menuBtn")) {
    $("menuBtn").addEventListener("click", function () {
      var menu = $("mobileMenu");
      var open = menu.hidden;
      menu.hidden = !open;
      this.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }

  if ($("retryBtn")) $("retryBtn").addEventListener("click", pollOnce);
  if ($("scanBtn")) $("scanBtn").addEventListener("click", forceScan);

  if ($("countrySelect")) {
    $("countrySelect").addEventListener("change", function () {
      switchCountry(this.value);
    });
  }

  if ($("hSearch")) {
    $("hSearch").addEventListener("input", function () {
      state.searchTerm = this.value.trim().toLowerCase();
      if (state.last) renderHosts(state.last.results || []);
    });
  }

  if ($("hSort")) {
    $("hSort").addEventListener("change", function () {
      state.sortMode = this.value;
      if (state.last) renderHosts(state.last.results || []);
    });
  }

  if ($("chipGroup")) {
    $("chipGroup").addEventListener("click", function (ev) {
      var chip = ev.target.closest ? ev.target.closest(".chip[data-verdict]") : null;
      if (!chip) return;
      state.filterVerdict = chip.getAttribute("data-verdict");
      var chips = this.querySelectorAll(".chip[data-verdict]");
      for (var i = 0; i < chips.length; i++) {
        chips[i].classList.toggle("is-on", chips[i] === chip);
      }
      if (state.last) renderHosts(state.last.results || []);
    });
  }

  if ($("filterReset")) {
    $("filterReset").addEventListener("click", function () {
      state.filterVerdict = "working";
      state.searchTerm = "";
      state.sortMode = "fastest";
      if ($("hSearch")) $("hSearch").value = "";
      if ($("hSort")) $("hSort").value = "fastest";
      if (state.last) renderHosts(state.last.results || []);
    });
  }

  if ($("rowsBody")) {
    $("rowsBody").addEventListener("click", function (ev) {
      var tr = ev.target.closest ? ev.target.closest("tr[data-index]") : null;
      if (tr) toggleDetail(tr);
    });
  }
}

/* ---------- boot ---------- */
function boot() {
  wire();
  gotoView("overview");
  setStatus("is-connecting");
  loadConfig()
    .then(loadResults)
    .catch(function (err) {
      setStatus("is-error");
      showError("Could not reach the backend: " + err.message);
    });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", boot);
} else {
  boot();
}

})();
