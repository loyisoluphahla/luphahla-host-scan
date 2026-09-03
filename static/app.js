function forceScan() {
    var btn = $("scanBtn");
    var sel = $("countrySelect");
    var cc = sel ? sel.value : state.country;
    btn.disabled = true;
    btn.setAttribute("data-loading", "1");
    $("scanBtnText").textContent = "Starting scan...";
    $("scanError").hidden = true;
    toast("Scan started for " + label(cc));
    return fetchJSON("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ country: cc })
    }).then(function (d) {
      state.country = d.country;
      pollOnce();
      return d;
    }).catch(function (err) {
      $("scanError").textContent = "Could not start scan: " + err.message;
      $("scanError").hidden = false;
      btn.disabled = false;
      btn.removeAttribute("data-loading");
      $("scanBtnText").textContent = "Scan this country";
    });
  }

  function switchCountry(cc) {
    if (!cc || cc === state.country) return;
    state.country = cc;
    updateFeedLinks();
    pollOnce();
  }

  /* ---------------- cycle events (history log) ---------------- */

  function detectCycleEvents(d) {
    var seen = state.logSeenCycle;
    var cycle = d.scan_count;
    if (d.scanning && seen !== -1 && cycle !== seen &&
        cycle > seen) {
      pushHistory("Scan cycle #" + cycle + " started", "started");
    }
    if (!d.scanning && seen !== -1 && cycle > seen &&
        d.results.length > 0) {
      var working = countWorking(d.results);
      pushHistory("Scan cycle #" + cycle + " complete - " +
                  working + " verified", "done");
    }
    if (seen === -1) {
      if (d.scanning) {
        pushHistory("Scan in progress (cycle #" + cycle + ")", "started");
      } else if (cycle > 0 && d.results.length > 0) {
        pushHistory("Results loaded (cycle #" + cycle + ")", "done");
      }
    }
    state.logSeenCycle = cycle;
    renderHistory();
  }

  function pushHistory(text, kind) {
    state.sessionLog.unshift({
      text: text, kind: kind, time: new Date()
    });
    if (state.sessionLog.length > 50) state.sessionLog.pop();
  }

  function countWorking(results) {
    var n = 0;
    for (var i = 0; i < results.length; i++) {
      if (results[i].verdict === "fast" ||
          results[i].verdict === "usable") n++;
    }
    return n;
  }

  /* ---------------- rendering ---------------- */

  function renderAll() {
    var d = state.last;
    renderStatus(d);
    renderSummary(d);
    renderTop3(d);
    renderMiniList(d);
    renderHosts(d);
  }

  function renderStatus(d) {
    var pill = $("statusPill");
    var text = $("statusText");
    if (d.scanning) {
      pill.className = "status-pill is-scanning";
      text.textContent = "Scanning";
    } else if (d.last_error) {
      pill.className = "status-pill is-error";
      text.textContent = "Scan error";
    } else if (d.scan_count > 0) {
      pill.className = "status-pill is-idle";
      text.textContent = "Live";
    } else {
      pill.className = "status-pill is-connecting";
      text.textContent = "First scan...";
    }

    $("actTitle").textContent = d.scanning
      ? "Scan engine running"
      : "Scan engine idle";
    $("actPhase").textContent = d.scanning ? (d.phase || "working") : "";
    $("actBarWrap").hidden = !d.scanning;
    $("actLast").textContent =
      "Last completed scan: " + fmtTime(d.last_scan_epoch) +
      (d.last_error ? "  |  Last error: " + d.last_error : "");
  }

  function renderSummary(d) {
    $("ovVerified").textContent = countWorking(d.results);
    $("ovScanned").textContent = d.results.length;
    $("statLastScan").textContent = fmtTime(d.last_scan_epoch);
    $("statCycle").textContent = "#" + d.scan_count;
    $("statCountry").textContent = label(d.country);
    if (state.cfg) {
      $("statReverify").textContent = fmtInterval(state.cfg.reverify_every_s);
    }
  }

  function renderTop3(d) {
    var grid = $("top3Grid");
    var empty = $("top3Empty");
    var working = getWorking(d.results).slice(0, 3);
    $("top3Country").textContent = label(d.country);
    if (!working.length) {
      grid.innerHTML = "";
      empty.hidden = false;
      return;
    }
    empty.hidden = true;
    var medals = ["1", "2", "3"];
    var html = "";
    for (var i = 0; i < working.length; i++) {
      var r = working[i];
      html +=
        '<div class="podium p-' + (i + 1) + '">' +
        '<div class="rank">' + medals[i] + '</div>' +
        '<span class="p-host">' + esc(r.host) + '</span>' +
        '<div class="p-stats">' +
        '<span class="p-speed">' + fmtSpeed(r.speed_kbps) + '</span>' +
        '<span>' + esc(String(r.verdict).toUpperCase()) +
        ' &middot; port ' + r.port + '</span>' +
        '</div></div>';
    }
    grid.innerHTML = html;
  }

  function renderMiniList(d) {
    var list = $("miniList");
    var empty = $("miniEmpty");
    var working = getWorking(d.results).slice(0, 5);
    if (!working.length) {
      list.innerHTML = "";
      empty.hidden = false;
      return;
    }
    empty.hidden = true;
    var html = "";
    for (var i = 0; i < working.length; i++) {
      var r = working[i];
      html +=
        '<div class="mini-row">' +
        '<span class="mini-host">' + esc(r.host) + '</span>' +
        '<span class="mini-speed">' + fmtSpeed(r.speed_kbps) + '</span>' +
        '</div>';
    }
    list.innerHTML = html;
  }

  function getWorking(results) {
    var out = [];
    for (var i = 0; i < results.length; i++) {
      var v = results[i].verdict;
      if (v === "fast" || v === "usable") out.push(results[i]);
    }
    out.sort(function (a, b) {
      if ((a.verdict === "fast") !== (b.verdict === "fast")) {
        return a.verdict === "fast" ? -1 : 1;
      }
      return (b.speed_kbps || 0) - (a.speed_kbps || 0);
    });
    return out;
  }

  /* ---------------- hosts table ---------------- */

  function renderHosts(d) {
    var body = $("rowsBody");
    var noRows = $("noRows");
    var results = d.results;
    var rows = filterRows(results);
    $("hostCount").textContent = rows.length + " of " +
      results.length + " hosts";
    $("hostsCountry").textContent = label(d.country);

    if (!rows.length) {
      body.innerHTML = "";
      noRows.hidden = false;
      $("noRowsMsg").textContent = results.length
        ? "No results match your filter."
        : (d.scanning
           ? "Scan in progress - hosts appear when the quick pass lands."
           : "No results yet. Start a scan below.");
      return;
    }
    noRows.hidden = true;

    var html = "";
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i];
      html +=
        '<tr data-host="' + esc(r.host) + '" data-index="' + i + '">' +
        '<td class="host-row-num">' + (i + 1) + '</td>' +
        '<td class="row-host">' + esc(r.host) + '</td>' +
        '<td class="host-port">' + r.port + '</td>' +
        '<td>' + pillHTML(r.verdict) + '</td>' +
        '<td>' + speedHTML(r.speed_kbps) + '</td>' +
        '<td class="trend-cell">' + trendHTML(r) + '</td>' +
        '</tr>';
    }
    body.innerHTML = html;
  }

  function filterRows(results) {
    var term = state.searchTerm;
    var rows = [];
    for (var i = 0; i < results.length; i++) {
      var r = results[i];
      if (state.filterVerdict === "working" &&
          !(r.verdict === "fast" || r.verdict === "usable")) continue;
      if (state.filterVerdict === "blocked" &&
          (r.verdict === "fast" || r.verdict === "usable")) continue;
      if ((state.filterVerdict === "fast" ||
           state.filterVerdict === "usable") &&
          r.verdict !== state.filterVerdict) continue;
      if (term && r.host.indexOf(term) === -1) continue;
      rows.push(r);
    }
    var mode = state.sortMode;
    rows.sort(function (a, b) {
      if (mode === "slowest") {
        return (a.speed_kbps || 0) - (b.speed_kbps || 0);
      }
      if (mode === "name-asc") return a.host.localeCompare(b.host);
      if (mode === "name-desc") return b.host.localeCompare(a.host);
      if (mode === "port") return a.port - b.port || a.host.localeCompare(b.host);
      return (b.speed_kbps || 0) - (a.speed_kbps || 0);
    });
    return rows;
  }

  function pillHTML(verdict) {
    var cls = { "fast": "p-fast", "usable": "p-usable",
                "throttled": "p-throttled", "tls-blocked": "p-tls-blocked",
                "proxy-mitm": "p-proxy-mitm", "blocked": "p-blocked" }[verdict];
    if (!cls) cls = "p-blocked";
    return '<span class="pill ' + cls + '"><span class="pdot"></span>' +
           esc(verdict) + '</span>';
  }

  function speedHTML(kbps) {
    if (kbps == null) return '<span class="speed-cell nil">-</span>';
    var cls = kbps >= 10 ? "ok" : "";
    return '<span class="speed-cell ' + cls + '">' +
           Number(kbps).toFixed(2) + '</span>';
  }

  function trendHTML(r) {
    var key = r.host + ":" + r.port;
    var prev = state.speedHistory[key];
    var cur = r.speed_kbps;
    if (cur != null) state.speedHistory[key] = cur;
    var svg = '';
    if (cur == null) {
      return '<span class="delta flat">n/a</span>';
    }
    if (prev == null || cur === prev) {
      svg = '<svg class="trend-svg" viewBox="0 0 20 12" width="20" height="12" aria-hidden="true">' +
            '<path d="M1 6h18" stroke="#6b7280" stroke-width="1.6" stroke-linecap="round"/></svg>';
      return svg + '<span class="delta flat">stable</span>';
    }
    if (cur > prev) {
      svg = '<svg class="trend-svg" viewBox="0 0 20 12" width="20" height="12" aria-hidden="true">' +
            '<path d="M1 10 L10 2 L19 10 M10 2 v0" stroke="#22d3ee" stroke-width="1.8" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>';
      return svg + '<span class="delta up">up</span>';
    }
    svg = '<svg class="trend-svg" viewBox="0 0 20 12" width="20" height="12" aria-hidden="true">' +
          '<path d="M1 2 L10 10 L19 2" stroke="#ff5fa2" stroke-width="1.8" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>';
    return svg + '<span class="delta down">down</span>';
  }

  /* ---------------- history ---------------- */

  function renderHistory() {
    var list = $("historyList");
    var empty = $("historyEmpty");
    if (!state.sessionLog.length) {
      list.innerHTML = "";
      empty.hidden = false;
      return;
    }
    empty.hidden = true;
    var html = "";
    for (var i = 0; i < state.sessionLog.length; i++) {
      var h = state.sessionLog[i];
      html +=
        '<div class="hist-row">' +
        '<div class="hist-main">' +
        '<span class="hist-dot ' + esc(h.kind) + '"></span>' +
        '<div><div>' + esc(h.text) + '</div>' +
        '<div class="hist-meta">' + h.time.toISOString() + '</div></div>' +
        '</div></div>';
    }
    list.innerHTML = html;
  }

  /* ---------------- config / countries ---------------- */

  function renderConfig(cfg) {
    $("cfgService").textContent = cfg.tool || "Luphahla Bugscan";
    $("cfgDefault").textContent =
      (cfg.default_country || "").toUpperCase();
    $("cfgCountries").textContent =
      Object.keys(cfg.countries).length + " regions";
    $("cfgPorts").textContent = (cfg.ports || []).join(", ");
    $("cfgReverify").textContent = fmtInterval(cfg.reverify_every_s);
    if (cfg.endpoints) {
      var list = $("cfgEndpoints");
      list.innerHTML = "";
      for (var name in cfg.endpoints) {
        if (!Object.prototype.hasOwnProperty.call(cfg.endpoints, name)) continue;
        var li = document.createElement("li");
        li.textContent = name + " -> " + cfg.endpoints[name];
        list.appendChild(li);
      }
    }
    if (cfg.ports && $("scanPorts")) {
      $("scanPorts").textContent = cfg.ports.join(", ");
    }
  }

  function renderCountrySelect() {
    var sel = $("countrySelect");
    if (!sel) return;
    var html = "";
    for (var i = 0; i < state.countries.length; i++) {
      var c = state.countries[i];
      html += '<option value="' + esc(c.code) + '"' +
              (c.code === state.country ? " selected" : "") + '>' +
              esc(c.label) + '</option>';
    }
    sel.innerHTML = html;
    sel.value = state.country;
    updateFeedLinks();
  }

  function updateFeedLinks() {
    var cc = encodeURIComponent(state.country);
    $("feedHosts").href = "/hosts?country=" + cc;
    $("feedTop").href = "/top?country=" + cc;
    $("feedApi").href = "/api/results?country=" + cc;
  }

  /* ---------------- errors ---------------- */

  function showError(msg) {
    $("errorText").textContent = msg;
    $("errorBanner").hidden = false;
  }
  function hideError() {
    $("errorBanner").hidden = true;
  }

  /* ---------------- view switching ---------------- */

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
    if (!menu.hidden) {
      menu.hidden = true;
      $("menuBtn").setAttribute("aria-expanded", "false");
    }
    window.scrollTo({ top: 0 });
  }

  /* ---------------- wiring ---------------- */

  function wire() {
    document.addEventListener("click", function (ev) {
      var el = ev.target.closest("[data-goto]");
      if (el) {
        ev.preventDefault();
        var name = el.getAttribute("data-goto");
        if (name === "scan") {
          var btn = $("scanBtn");
          if (btn) btn.focus({ preventScroll: true });
        }
        gotoView(name);
      }
    });

    $("menuBtn").addEventListener("click", function () {
      var menu = $("mobileMenu");
      var open = menu.hidden;
      menu.hidden = !open;
      this.setAttribute("aria-expanded", open ? "true" : "false");
    });

    $("retryBtn").addEventListener("click", pollOnce);

    $("scanBtn").addEventListener("click", forceScan);

    $("countrySelect").addEventListener("change", function () {
      switchCountry(this.value);
    });

    $("hSearch").addEventListener("input", function () {
      state.searchTerm = this.value.trim().toLowerCase();
      renderHosts(state.last);
    });

    $("hSort").addEventListener("change", function () {
      state.sortMode = this.value;
      renderHosts(state.last);
    });

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

    $("filterReset").addEventListener("click", function () {
      state.filterVerdict = "working";
      state.searchTerm = "";
      state.sortMode = "fastest";
      $("hSearch").value = "";
      $("hSort").value = "fastest";
      var chips = document.querySelectorAll("#chipGroup .chip[data-verdict]");
      for (var i = 0; i < chips.length; i++) {
        var on = chips[i].getAttribute("data-verdict") === "working";
        chips[i].classList.toggle("is-on", on);
        chips[i].setAttribute("aria-pressed", on ? "true" : "false");
      }
      renderHosts(state.last);
    });

    $("goScanEmpty").addEventListener("click", function () {
      gotoView("scan");
    });

    $("rowsBody").addEventListener("click", function (ev) {
      var tr = ev.target.closest("tr[data-host]");
      if (!tr) return;
      toggleDetail(tr);
    });
  }

  function toggleDetail(tr) {
    var next = tr.nextElementSibling;
    if (next && next.classList.contains("detail-row")) {
      next.remove();
      return;
    }
    var idx = Number(tr.getAttribute("data-index"));
    var rows = filterRows(state.last.results);
    var r = rows[idx];
    if (!r) return;
    var detail = document.createElement("tr");
    detail.className = "detail-row";
    detail.innerHTML =
      '<td></td>' +
      '<td colspan="5"><div class="detail-grid">' +
      '<div><b>Host:</b> <a class="host-link" href="/api/results" target="_blank" rel="noopener">' + esc(r.host) + '</a></div>' +
      '<div><b>Reason:</b> ' + esc(r.reason || "n/a") + '</div>' +
      '<div><b>Latency:</b> ' + (r.latency_ms != null ? r.latency_ms + " ms" : "n/a") + '</div>' +
      '<div><b>Status code:</b> ' + (r.status_code != null ? r.status_code : "n/a") + '</div>' +
      '<div><b>Server header:</b> ' + esc(r.server_header || "n/a") + '</div>' +
      '</div></td>';
    tr.after(detail);
  }

  /* ---------------- boot ---------------- */

  function boot() {
    wire();
    gotoView("overview");
    loadConfig()
      .then(loadResults)
      .catch(function (err) {
        showError("Could not load config: " + err.message);
      });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }

})();
