/* app.js — Luphahla Bugscan dashboard client.

Changes in this version (the "Connecting... / Backend unreachable" fix):
  1. API_BASE — when the page is NOT served from Render (APK WebView,
     file://, locally bundled assets), all API calls use the absolute
     Render origin. Relative URLs previously hit the APK's internal
     origin and failed.
  2. Cold-start tolerant fetch — 45s timeout + 1 automatic retry, because
     the Render free tier can take 30-60s to wake up.
  3. Defensive rendering — missing summary element IDs are skipped
     harmlessly instead of throwing.
*/

(function () {
"use strict";

// ---------------------------------------------------------------------------
// API base — CHANGE THIS to your actual Render URL if it differs
// ---------------------------------------------------------------------------

var SERVICE_URL = window.LUPHAHLA_API_URL || "https://luphahla-bugscan.onrender.com";

function isServiceOrigin() {
  return /(^|\.)onrender\.com$/.test(location.hostname);
}

var API_BASE = isServiceOrigin() ? "" : SERVICE_URL;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

function sleep(ms) {
  return new Promise(function (r) { setTimeout(r, ms); });
}

function fmtTime(epoch) {
  if (!epoch) return "—";
  var d = new Date(epoch * 1000);
  return d.toISOString().replace("T", " ").slice(0, 16) + " UTC";
}

function fmtInterval(s) {
  if (!s) return "—";
  if (s % 3600 === 0) return (s / 3600) + " h";
  if (s % 60 === 0) return (s / 60) + " min";
  return s + " s";
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

var state = {
  config: null, last: null, country: "zw", countries: [],
  searchTerm: "", sortMode: "fastest", filterVerdict: "working",
  history: [], lastCycle: 0, pollTimer: null
};

// ---------------------------------------------------------------------------
// Fetch — 45s timeout + 1 retry (Render cold start)
// ---------------------------------------------------------------------------

async function fetchJSON(url, attempt) {
  attempt = attempt || 1;
  var controller = new AbortController();
  var timer = setTimeout(function () { controller.abort(); }, 45000);
  try {
    var resp = await fetch(url, { signal: controller.signal });
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    return await resp.json();
  } catch (err) {
    if (err.name === "AbortError") {
      err = new Error("request timed out (service waking up?)");
    }
    // Render free tier cold start can take 30-60s — retry once
    if (attempt < 2) {
      await sleep(3000);
      return fetchJSON(url, attempt + 1);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

async function postJSON(url, body) {
  var controller = new AbortController();
  var timer = setTimeout(function () { controller.abort(); }, 45000);
  try {
    var resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
      signal: controller.signal
    });
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    return await resp.json();
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// Status pill / error banner / toast
// ---------------------------------------------------------------------------

function setStatus(mode) {
  var pill = $("statusPill"), text = $("statusText");
  if (pill) {
    pill.className = "status-pill " +
      (mode === "live" ? "is-live" :
       mode === "error" ? "is-error" : "is-connecting");
  }
  if (text) {
    text.textContent =
      mode === "live" ? "LIVE" :
      mode === "error" ? "Backend unreachable" : "Connecting...";
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

// ---------------------------------------------------------------------------
// Data loading
// ---------------------------------------------------------------------------

async function loadConfig() {
  var cfg = await fetchJSON(API_BASE + "/api/config");
  state.config = cfg;
  state.country = cfg.default_country || state.country;
  renderConfig(cfg);
  renderCountrySelect();
  setStatus("live");
}

async function loadResults() {
  pollOnce();
  if (state.pollTimer) clearInterval(state.pollTimer);
  state.pollTimer = setInterval(pollOnce, 30000);
}

async function pollOnce() {
  try {
    var url = API_BASE + "/api/results" +
      (state.country ? "?country=" + encodeURIComponent(state.country) : "");
    var data = await fetchJSON(url);
    state.last = data;
    renderResults(data);
    hideError();
    setStatus("live");
  } catch (err) {
    setStatus("error");
    showError("Backend unreachable: " + err.message);
  }
}

function switchCountry(cc) {
  state.country = cc;
  renderCountrySelect();
  updateFeedLinks();
  pollOnce();
}

async function forceScan() {
  try {
    toast("Rescan requested...");
    await postJSON(API_BASE + "/api/scan", { country: state.country });
    toast("Rescan started — verifying hosts now");
    pollOnce();
  } catch (err) {
    toast("Rescan failed: " + err.message);
  }
}

// ---------------------------------------------------------------------------
// Rendering — config / countries / feed links
// ---------------------------------------------------------------------------

function renderConfig(cfg) {
  setText("cfgService", cfg.tool || "Luphahla Bugscan");
  setText("cfgDefault", (cfg.default_country || "").toUpperCase());
  setText("cfgCountries",
    Object.keys(cfg.countries || {}).length + " regions");
  setText("cfgPorts", (cfg.ports || []).join(", "));
  setText("cfgReverify", fmtInterval(cfg.reverify_every_s));

  if (cfg.endpoints) {
    var list = $("cfgEndpoints");
    if (list) {
      list.innerHTML = "";
      for (var name in cfg.endpoints) {
        if (!Object.prototype.hasOwnProperty.call(cfg.endpoints, name)) continue;
        var li = document.createElement("li");
        li.textContent = name + " -> " + cfg.endpoints[name];
        list.appendChild(li);
      }
    }
  }
  if (cfg.ports && $("scanPorts")) {
    $("scanPorts").textContent = cfg.ports.join(", ");
  }
  setText("sumCountry", (cfg.default_country || "").toUpperCase());
}

function renderCountrySelect() {
  var sel = $("countrySelect");
  if (!sel) return;

  state.countries = [];
  var cfg = state.config || {};
  for (var code function renderCountrySelect() {
  var sel = $("countrySelect");
  if (!sel) return;

  state.countries = [];
  var cfg = state.config || {};
  for (var code in cfg.countries) {
    if (!Object.prototype.hasOwnProperty.call(cfg.countries, code)) continue;
    state.countries.push({ code: code,
                           label: cfg.countries[code].label || code.toUpperCase() });
  }

  var html = "";
  for (var i = 0; i < state.countries.length; i++) {
    var c = state.countries[i];
    html += '<option value="' + esc(c.code) + '"' +
            (c.code === state.country ? " selected" : "") + ">" +
            esc(c.label) + "</option>";
  }
  sel.innerHTML = html;
  sel.value = state.country;
  updateFeedLinks();
}

function updateFeedLinks() {
  var cc = encodeURIComponent(state.country);
  if ($("feedHosts")) $("feedHosts").href = "/hosts?country=" + cc;
  if ($("feedTop")) $("feedTop").href = "/top?country=" + cc;
  if ($("feedApi")) $("feedApi").href = "/api/results?country=" + cc;
}

// ---------------------------------------------------------------------------
// Rendering — results / summary / top3 / host table
// ---------------------------------------------------------------------------

function countWorking(rows) {
  var n = 0;
  for (var i = 0; i < rows.length; i++) {
    if (rows[i].verdict === "fast" || rows[i].verdict === "usable") n++;
  }
  return n;
}

function filterRows(rows) {
  var out = [];
  var term = state.searchTerm;
  for (var i = 0; i < rows.length; i++) {
    var r = rows[i];
    if (state.filterVerdict === "working" &&
        r.verdict !== "fast" && r.verdict !== "usable") continue;
    if (state.filterVerdict === "fast" && r.verdict !== "fast") continue;
    if (state.filterVerdict === "usable" && r.verdict !== "usable") continue;
    if (state.filterVerdict === "blocked" &&
        r.verdict === "fast" && r.verdict === "usable") continue;
    if (state.filterVerdict === "all" || state.filterVerdict === "blocked") {
      // "all" passes everything; "blocked" passes everything non-working
      if (state.filterVerdict === "blocked" &&
          (r.verdict === "fast" || r.verdict === "usable")) continue;
    }
    if (term && r.host.toLowerCase().indexOf(term) === -1) continue;
    out.push(r);
  }
  return sortRows(out);
}

function sortRows(rows) {
  var sorted = rows.slice();
  if (state.sortMode === "fastest") {
    sorted.sort(function (a, b) {
      var w = verdictRank(a) - verdictRank(b);
      if (w) return w;
      return (b.speed_kbps || 0) - (a.speed_kbps || 0);
    });
  } else if (state.sortMode === "name") {
    sorted.sort(function (a, b) { return a.host < b.host ? -1 : 1; });
  } else if (state.sortMode === "status") {
    sorted.sort(function (a, b) {
      return (a.status_code || 999) - (b.status_code || 999);
    });
  }
  return sorted;
}

function verdictRank(r) {
  return r.verdict === "fast" ? 0 :
         r.verdict === "usable" ? 1 : 2;
}

function verdictClass(v) {
  return v === "fast" ? "v-fast" :
         v === "usable" ? "v-usable" :
         v === "throttled" ? "v-throt" :
         v === "proxy-mitm" ? "v-mitm" : "v-tls";
}

function renderResults(data) {
  var rows = data.results || [];
  var working = countWorking(rows);

  // --- summary card (all defensive — missing IDs are skipped) ---
  setText("verifiedCount", working + " / " + rows.length);
  setText("hostsCount", rows.length + " scanned");
  setText("sumCountry", (data.country || "").toUpperCase());
  setText("lastScan", data.last_epoch ? fmtTime(data.last_epoch) : "—");
  setText("lastCycle", data.scan_count ? "cycle #" + data.scan_count : "—");
  setText("scanCount", rows.length ? rows.length + " hosts" : "—");
  setText("scanPorts", (data.ports || []).join(", "));
  setText("scanPhase", data.phase || (data.scanning ? "scanning" : "idle"));

  var phase = $("scanPhase");
  if (phase) {
    phase.className = data.scanning ? "phase is-scanning" : "phase is-idle";
  }

  // --- top 3 fastest working hosts ---
  var fast = rows.filter(function (r) { return r.verdict === "fast"; })
    .sort(function (a, b) { return (b.speed_kbps || 0) - (a.speed_kbps || 0); })
    .slice(0, 3);

  var topList = $("topFastList");
  if (topList) {
    if (!fast.length) {
      topList.innerHTML = '<div class="empty-state">No verified hosts yet - ' +
        'the first scan is still gathering data.</div>';
    } else {
      topList.innerHTML = fast.map(function (r) {
        return '<div class="top-row"><span class="mono">' + esc(r.host) +
          "</span><span>" + fmtKbps(r.speed_kbps) + "</span></div>";
      }).join("");
    }
  }

  // --- recently verified (first 5 working) ---
  var recentList = $("recentList");
  if (recentList) {
    var recent = rows.filter(function (r) {
      return r.verdict === "fast" || r.verdict === "usable";
    }).slice(0, 5);
    recentList.innerHTML = recent.length
      ? recent.map(function (r) {
          return '<div class="recent-row"><span class="mono">' + esc(r.host) +
            ":" + r.port + "</span><span>" + esc(r.verdict) + "</span></div>";
        }).join("")
      : '<div class="empty-state">Nothing verified yet.</div>';
  }

  // --- host table ---
  renderHosts(data);

  // --- cycle history (new cycles observed this session) ---
  detectCycleEvents(data);
}

function fmtKbps(kbps) {
  if (kbps == null) return "—";
  if (kbps >= 1000) return (kbps / 1000).toFixed(1) + " MB/s";
  return kbps.toFixed(1) + " KB/s";
}

function renderHosts(data) {
  var rows = filterRows(data.results || []);
  var body = $("rowsBody");
  var counter = $("hostsCounter");

  if (counter) counter.textContent = rows.length + " hosts";
  if (!body) return;

  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="6" class="empty-state">' +
      (state.last && (state.last.results || []).length
        ? "No results match."
        : "No hosts yet — start a scan.") +
      "</td></tr>";
    if ($("emptyState")) $("emptyState").hidden = true;
    return;
  }

  var html = "";
  for (var i = 0; i < rows.length; i++) {
    var r = rows[i];
    html +=
      '<tr data-host="' + esc(r.host) + '" data-index="' + i + '">' +
      "<td>" + (i + 1) + "</td>" +
      '<td class="mono">' + esc(r.host) + "</td>" +
      "<td>" + r.port + "</td>" +
      '<td class="' + verdictClass(r.verdict) + '">' + esc(r.verdict) + "</td>" +
      "<td>" + fmtKbps(r.speed_kbps) + "</td>" +
      "<td>" + esc(r.server_header || "—") + "</td>" +
      "</tr>";
  }
  body.innerHTML = html;
  if ($("emptyState")) $("emptyState").hidden = true;
}

// ---------------------------------------------------------------------------
// Cycle history
// ---------------------------------------------------------------------------

function detectCycleEvents(data) {
  var cycle = data.scan_count || 0;
  var working = countWorking(data.results || []);

  if (state.lastCycle === 0) {
    if (data.scanning) {
      pushHistory("Scan in progress (cycle #" + cycle + ")", "started");
    } else if (cycle > 0) {
      pushHistory("Results loaded (cycle #" + cycle + ") - " +
                  working + " verified", "done");
    }
  } else if (cycle > state.lastCycle) {
    pushHistory("Scan cycle #" + cycle + " complete - " +
                working + " verified", "done");
  }
  state.lastCycle = Math.max(state.lastCycle, cycle);
  renderHistory();
}

function pushHistory(text, kind) {
  state.history.unshift({ text: text, kind: kind || "done",
                          time: fmtTime(Date.now() / 1000) });
  if (state.history.length > 50) state.history.length = 50;
}

function renderHistory() {
  var list = $("historyList"), empty = $("historyEmpty");
  if (empty) empty.hidden = state.history.length > 0;
  if (!list) return;
  list.innerHTML = state.history.map(function (h) {
    return '<div class="history-row is-' + esc(h.kind) + '">' +
           "<span>" + esc(h.text) + "</span><span>" +
           esc(h.time) + "</span></div>";
  }).join("");
}

// ---------------------------------------------------------------------------
// View switching
// ---------------------------------------------------------------------------

function gotoView(name) {
  var views = document.querySelectorAll(".view");
  for (var i = 0; i < views.length; i++) {
    views[i].hidden = views[i].getAttribute("data-view") !== name;
  }
  var btns = document.querySelectorAll("[data-goto]");
  for (var j = 0; j < btns.length; j++) {
    var b = btns[j];
    var on = b.getAttribute("data-goto") === name;
    if (b.classList.contains("nav-btn") ||
        b.classList.contains("mobile-menu")) {
      b.classList.toggle("is-active", on);
    }
  }
  var menu = $("mobileMenu");
  if (menu && !menu.hidden) {
    menu.hidden = true;
    if ($("menuBtn")) $("menuBtn").setAttribute("aria-expanded", "false");
  }
  window.scrollTo({ top: 0 });
}

// ---------------------------------------------------------------------------
// Row detail (tap a row for host info)
// ---------------------------------------------------------------------------

function toggleDetail(tr) {
  var next = tr.nextElementSibling;
  if (next && next.classList.contains("detail-row")) {
    next.remove();
    return;
  }
  var idx = Number(tr.getAttribute("data-index"));
  var rows = filterRows((state.last && state.last.results) || []);
  var r = rows[idx];
  if (!r) return;
  var detail = document.createElement("tr");
  detail.className = "detail-row";
  detail.innerHTML =
    "<td></td>" +
    '<td colspan="5"><div class="detail-grid">' +
    '<div><b>Host:</b> <a class="host-link" href="' + API_BASE +
    '/api/results" target="_blank" rel="noopener">' + esc(r.host) + "</a></div>" +
    '<div><b>Port:</b> ' + r.port + "</div>" +
    '<div><b>Verdict:</b> ' + esc(r.verdict) + "</div>" +
    '<div><b>Reason:</b> ' + esc(r.reason || "n/a") + "</div>" +
    '<div><b>Latency:</b> ' + (r.latency_ms != null ? r.latency_ms + " ms" : "n/a") + "</div>" +
    '<div><b>Status code:</b> ' + (r.status_code != null ? r.status_code : "n/a") + "</div>" +
    '<div><b>Server header:</b> ' + esc(r.server_header || "n/a") + "</div>" +
    "</div></td>";
  tr.after(detail);
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

function wire() {
  document.addEventListener("click", function (ev) {
    var el = ev.target.closest("[data-goto]");
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
      renderHosts(state.last);
    });
  }

  if ($("hSort")) {
    $("hSort").addEventListener("change", function () {
      state.sortMode = this.value;
      renderHosts(state.last);
    });
  }

  if ($("chipGroup")) {
    $("chipGroup").addEventListener("click", function (ev) {
      var chip = ev.target.closest(".chip[data-verdict]");
      if (!chip) return;
      state.filterVerdict = chip.getAttribute("data-verdict");
      var chips = this.querySelectorAll(".chip[data-verdict]");
      for (var i = 0; i < chips.length; i++) {
        var on = chips[i] === chip;
        chips[i].classList.toggle("is-on", on);
        chips[i].setAttribute("aria-pressed", on ? "true" : "false");
      }
      renderHosts(state.last);
    });
  }

  if ($("filterReset")) {
    $("filterReset").addEventListener("click", function () {
      state.filterVerdict = "working";
      state.searchTerm = "";
      state.sortMode = "fastest";
      if ($("hSearch")) $("hSearch").value = "";
      if ($("hSort")) $("hSort").value = "fastest";
      var chips = document.querySelectorAll("#chipGroup .chip[data-verdict]");
      for (var i = 0; i < chips.length; i++) {
        var on = chips[i].getAttribute("data-verdict") === "working";
        chips[i].classList.toggle("is-on", on);
        chips[i].setAttribute("aria-pressed", on ? "true" : "false");
      }
      renderHosts(state.last);
    });
  }

  if ($("goScanEmpty")) {
    $("goScanEmpty").addEventListener("click", function () {
      gotoView("scan");
    });
  }

  if ($("rowsBody")) {
    $("rowsBody").addEventListener("click", function (ev) {
      var tr = ev.target.closest("tr[data-host]");
      if (!tr) return;
      toggleDetail(tr);
    });
  }
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

async function boot() {
  wire();
  gotoView("overview");
  setStatus("connecting");
  try {
    await loadConfig();
    await loadResults();
  } catch (err) {
    setStatus("error");
    showError("Could not reach the backend: " + err.message +
              " — check your connection and tap Retry.");
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", boot);
} else {
  boot();
}

})();
