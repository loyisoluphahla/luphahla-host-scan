/* ============================================================
   Luphahla Bugscan - dashboard client
   Lightweight vanilla JS. Reads REAL data from the backend:
     GET  /api/results?country=xx  (live scan state + rows)
     GET  /api/config              (ports, interval, countries)
     POST /api/scan                (triggers the REAL country scan task)
   No fake data anywhere. Polls every 5s while a scan runs.
   ============================================================ */

(function () {
  "use strict";

  var DEFAULT_COUNTRY = "zw";
  var POLL_SLOW_MS = 10000;
  var POLL_FAST_MS = 4000;

  var state = {
    country: DEFAULT_COUNTRY,
    countries: [],
    cfg: null,
    last: { results: [], last_error: "", last_scan_epoch: 0,
            scan_count: 0, scanning: false, phase: "" },
    pollTimer: null,
    pollMs: POLL_SLOW_MS,
    speedHistory: {},   // host -> last speed, for trend arrows
    sessionLog: [],     // history view entries
    logSeenCycle: -1,
    filterVerdict: "working",
    searchTerm: "",
    sortMode: "fastest"
  };

  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;",
               '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function fmtTime(epoch) {
    if (!epoch) return "never";
    var d = new Date(epoch * 1000);
    function p(n) { return (n < 10 ? "0" : "") + n; }
    return d.getUTCFullYear() + "-" + p(d.getUTCMonth() + 1) + "-" +
           p(d.getUTCDate()) + " " + p(d.getUTCHours()) + ":" +
           p(d.getUTCMinutes()) + " UTC";
  }
  function fmtSpeed(kbps) {
    if (kbps == null) return "-";
    if (kbps >= 1000) return (kbps / 1000).toFixed(1) + " MB/s";
    return Number(kbps).toFixed(1) + " KB/s";
  }
  function fmtInterval(s) {
    var h = Math.round(s / 3600);
    return "Auto-reverify every " + h + " hour" + (h === 1 ? "" : "s");
  }
  function label(cc) {
    for (var i = 0; i < state.countries.length; i++) {
      if (state.countries[i].code === cc) return state.countries[i].label;
    }
    return cc.toUpperCase();
  }
  function toast(msg) {
    var t = $("toast");
    t.textContent = msg;
    t.hidden = false;
    clearTimeout(state.toastTimer);
    state.toastTimer = setTimeout(function () { t.hidden = true; }, 3500);
  }

  /* ---------------- data ---------------- */

  function fetchJSON(url, opts) {
    return fetch(url, opts).then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    });
  }

  function loadConfig() {
    return fetchJSON("/api/config").then(function (cfg) {
      state.cfg = cfg;
      state.countries = Object.keys(cfg.countries).map(function (code) {
        return { code: code, label: cfg.countries[code].label };
      });
      if (state.countries.length &&
          !state.countries.some(function (c) {
            return c.code === state.country;
          })) {
        state.country = cfg.default_country || state.countries[0].code;
      }
      renderConfig(cfg);
      renderCountrySelect();
    });
  }

  function loadResults() {
    return fetchJSON("/api/results?country=" +
                     encodeURIComponent(state.country))
      .then(function (d) {
        state.last = d;
        detectCycleEvents(d);
        renderAll();
        hideError();
        schedulePoll(d.scanning ? POLL_FAST_MS : POLL_SLOW_MS);
      })
      .catch(function (err) {
        showError("Backend unreachable (" + err.message +
                  "). Retrying automatically.");
        $("statusPill").className = "status-pill is-error";
        $("statusText").textContent = "Offline";
        schedulePoll(POLL_SLOW_MS);
      });
  }

  function schedulePoll(ms) {
    clearTimeout(state.pollTimer);
    state.pollTimer = setTimeout(pollOnce, ms);
  }
  function pollOnce() {
    clearTimeout(state.pollTimer);
    loadResults();
  }

  function forceScan()
