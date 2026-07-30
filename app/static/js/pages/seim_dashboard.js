/* ==========================================================================
   siem-dashboard.js — page module for app/siem.html
   Depends on: LOGS_DATA, SAVED_SEARCHES_DATA (data/*), XDR_CHART_DEFAULTS,
   XDR_PALETTE, xdrGradient (core/charts.js), XDRUtils (app.js)
   ========================================================================== */

   (function () {
    const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
  
    function timeAgo(ts) {
      const diff = Math.max(0, (Date.now() - new Date(ts).getTime()) / 1000);
      if (diff < 60) return "just now";
      if (diff < 3600) return `${Math.floor(diff / 60)} min ago`;
      return `${Math.floor(diff / 3600)}h ago`;
    }
  
    // ---------- KPI: events/sec (simulated, deterministic-ish) ----------
    let eps = 812;
    function tickEps() {
      eps = Math.max(120, Math.round(eps + (Math.random() - 0.5) * 90));
      document.getElementById("kpiEps").textContent = eps.toLocaleString();
    }
    tickEps();
    setInterval(tickEps, 2500);
  
    // ---------- Live log stream ----------
    const streamEl = document.getElementById("liveLogStream");
    const sorted = LOGS_DATA.slice().sort((a, b) => new Date(b.ts) - new Date(a.ts));
  
    function logRowHtml(row, isNew) {
      return `<div class="log-stream-row sev-${row.sev} ${isNew ? "log-row-new" : ""}">
        <span class="lt-time">${row.ts.slice(11, 19)}</span>
        <span class="lt-host">${row.host}</span>
        <span class="lt-msg">${XDRUtils.escapeHtml(row.message)}</span>
      </div>`;
    }
  
    streamEl.innerHTML = sorted.slice(0, 18).map((r) => logRowHtml(r)).join("");
  
    let liveCounter = 0;
    function pushLiveRow() {
      const template = sorted[liveCounter % sorted.length];
      liveCounter++;
      const fresh = { ...template, ts: new Date().toISOString(), id: `LOG-LIVE-${Date.now()}` };
      streamEl.insertAdjacentHTML("afterbegin", logRowHtml(fresh, true));
      while (streamEl.children.length > 24) streamEl.removeChild(streamEl.lastChild);
    }
    setInterval(pushLiveRow, 4000);
  
    // ---------- Event volume chart (24h, stacked by severity) ----------
    const buckets = {};
    for (let h = 23; h >= 0; h--) buckets[h] = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const now = new Date("2026-07-24T09:58:00Z").getTime();
    LOGS_DATA.forEach((row) => {
      const hoursAgo = Math.floor((now - new Date(row.ts).getTime()) / 3600000);
      if (hoursAgo >= 0 && hoursAgo <= 23) buckets[hoursAgo][row.sev]++;
    });
    const hourLabels = [];
    for (let h = 23; h >= 0; h--) hourLabels.push(`${h}h ago`);
  
    new Chart(document.getElementById("eventVolumeChart"), {
      type: "bar",
      data: {
        labels: hourLabels,
        datasets: ["critical", "high", "medium"].map((sev) => ({
          label: sev,
          data: Array.from({ length: 24 }, (_, i) => buckets[23 - i][sev]),
          backgroundColor: XDR_PALETTE.severity[sev],
          borderRadius: 2,
        })),
      },
      options: {
        ...XDR_CHART_DEFAULTS,
        scales: {
          x: { ...XDR_CHART_DEFAULTS.scales.x, stacked: true },
          y: { ...XDR_CHART_DEFAULTS.scales.y, stacked: true },
        },
      },
    });
  
    // ---------- Severity donut ----------
    const sevCounts = SEV_ORDER.map((s) => LOGS_DATA.filter((r) => r.sev === s).length);
    new Chart(document.getElementById("severityDonutChart"), {
      type: "doughnut",
      data: {
        labels: SEV_ORDER.map((s) => s[0].toUpperCase() + s.slice(1)),
        datasets: [{
          data: sevCounts,
          backgroundColor: SEV_ORDER.map((s) => XDR_PALETTE.severity[s]),
          borderWidth: 0,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false, cutout: "68%",
        plugins: { legend: { display: true, position: "bottom", labels: { usePointStyle: true, boxWidth: 8, boxHeight: 8 } } },
      },
    });
  
    // ---------- Top sources ----------
    const sourceCounts = {};
    LOGS_DATA.forEach((r) => { sourceCounts[r.source] = (sourceCounts[r.source] || 0) + 1; });
    const topSources = Object.entries(sourceCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);
    const maxSourceCount = topSources[0]?.[1] || 1;
    document.getElementById("topSourcesList").innerHTML = topSources.map(([name, count]) => `
      <div class="mb-3">
        <div class="d-flex justify-content-between text-sm mb-1"><span>${name}</span><span class="text-muted">${count}</span></div>
        <div class="xdr-progress"><div class="xdr-progress-bar bar-primary" style="width:${Math.round((count / maxSourceCount) * 100)}%"></div></div>
      </div>`).join("");
  
    // ---------- Noisiest hosts ----------
    const hostStats = {};
    LOGS_DATA.forEach((r) => {
      hostStats[r.host] = hostStats[r.host] || { count: 0, sevRank: 4 };
      hostStats[r.host].count++;
      const rank = SEV_ORDER.indexOf(r.sev);
      if (rank < hostStats[r.host].sevRank) hostStats[r.host].sevRank = rank;
    });
    const topHosts = Object.entries(hostStats).sort((a, b) => b[1].count - a[1].count).slice(0, 6);
    document.getElementById("topHostsBody").innerHTML = topHosts.map(([host, stat]) => `
      <tr>
        <td><a href="../app/assets.html" style="color:var(--text);font-weight:600;">${host}</a></td>
        <td>${stat.count}</td>
        <td>${XDRUtils.severityBadge(SEV_ORDER[stat.sevRank])}</td>
      </tr>`).join("");
  
    // ---------- Pinned searches ----------
    const pinned = SAVED_SEARCHES_DATA.filter((s) => s.pinned);
    document.getElementById("pinnedSearchesList").innerHTML = pinned.map((s) => `
      <div class="mini-status-row">
        <span class="d-flex align-items-center gap-2">
          <i class="bi bi-bookmark-star text-muted"></i>
          <a href="log-explorer.html" style="color:var(--text);font-weight:600;">${s.name}</a>
        </span>
        <span class="badge ${s.alerting ? "badge-warning" : "badge-neutral"}">${s.hits} hits</span>
      </div>`).join("");
  
    // Live indicator label refresh (cosmetic — keeps "Live" tag accurate to time)
    setInterval(() => {
      const el = document.getElementById("liveIndicator");
      if (el) el.title = `Updated ${timeAgo(new Date().toISOString())}`;
    }, 5000);
  })();
  