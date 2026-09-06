/* ==========================================================================
   siem-dashboard.js — page module for app/templates/siem/siem.html
   Fetches live data from /siem/api/dashboard, updates KPIs, charts, stream,
   sources, hosts, and pinned searches.
   ========================================================================== */

(function () {
  const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
  let eventVolumeChart = null;
  let severityDonutChart = null;
  let liveEps = 812;

  function timeAgo(ts) {
    if (!ts) return "just now";
    const diff = Math.max(0, (Date.now() - new Date(ts).getTime()) / 1000);
    if (diff < 60) return "just now";
    if (diff < 3600) return `${Math.floor(diff / 60)} min ago`;
    return `${Math.floor(diff / 3600)}h ago`;
  }

  function logRowHtml(row, isNew) {
    const timeStr = row.ts ? row.ts.slice(11, 19) : "--:--:--";
    return `<div class="log-stream-row sev-${row.sev} ${isNew ? "log-row-new" : ""}">
      <span class="lt-time">${timeStr}</span>
      <span class="lt-host">${XDRUtils.escapeHtml(row.host || "UNKNOWN")}</span>
      <span class="lt-msg"><a href="/siem/log-details?id=${row.id}" style="color:inherit;text-decoration:none;">${XDRUtils.escapeHtml(row.message || "")}</a></span>
    </div>`;
  }

  // ---------- KPI: Events per second ----------
  function tickEps() {
    liveEps = Math.max(120, Math.round(liveEps + (Math.random() - 0.5) * 80));
    const kpiEl = document.getElementById("kpiEps");
    if (kpiEl) kpiEl.textContent = liveEps.toLocaleString();
  }
  setInterval(tickEps, 2500);

  // ---------- Charts Init & Update ----------
  function renderCharts(chartData, sevCounts) {
    const volEl = document.getElementById("eventVolumeChart");
    if (volEl) {
      const volCtx = volEl.getContext("2d");
      const datasets = ["critical", "high", "medium"].map((sev) => ({
        label: sev.charAt(0).toUpperCase() + sev.slice(1),
        data: chartData?.datasets?.[sev] || Array(24).fill(0),
        backgroundColor: (window.XDR_PALETTE && window.XDR_PALETTE.severity[sev]) || (sev === "critical" ? "#ef4444" : sev === "high" ? "#f97316" : "#eab308"),
        borderRadius: 2,
      }));

      if (eventVolumeChart) {
        eventVolumeChart.data.labels = chartData?.labels || [];
        eventVolumeChart.data.datasets = datasets;
        eventVolumeChart.update();
      } else {
        eventVolumeChart = new Chart(volCtx, {
          type: "bar",
          data: {
            labels: chartData?.labels || [],
            datasets,
          },
          options: {
            ...(window.XDR_CHART_DEFAULTS || {}),
            responsive: true,
            maintainAspectRatio: false,
            scales: {
              x: { stacked: true },
              y: { stacked: true },
            },
          },
        });
      }
    }

    const donutEl = document.getElementById("severityDonutChart");
    if (donutEl) {
      const donutCtx = donutEl.getContext("2d");
      const counts = SEV_ORDER.map((s) => (sevCounts ? sevCounts[s] || 0 : 0));
      const colors = SEV_ORDER.map((s) => (window.XDR_PALETTE ? window.XDR_PALETTE.severity[s] : "#94a3b8"));

      if (severityDonutChart) {
        severityDonutChart.data.datasets[0].data = counts;
        severityDonutChart.update();
      } else {
        severityDonutChart = new Chart(donutCtx, {
          type: "doughnut",
          data: {
            labels: SEV_ORDER.map((s) => s.charAt(0).toUpperCase() + s.slice(1)),
            datasets: [{
              data: counts,
              backgroundColor: colors,
              borderWidth: 0,
            }],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "68%",
            plugins: {
              legend: {
                display: true,
                position: "bottom",
                labels: { usePointStyle: true, boxWidth: 8, boxHeight: 8 },
              },
            },
          },
        });
      }
    }
  }

  // ---------- Populate Lists & Tables ----------
  function renderDashboardUI(data) {
    if (!data) return;

    // KPIs
    if (data.kpi) {
      if (data.kpi.total_events_24h != null) {
        const el = document.getElementById("kpi24h");
        if (el) el.textContent = data.kpi.total_events_24h.toLocaleString();
      }
      if (data.kpi.active_sources_count != null) {
        const el = document.getElementById("kpiSources");
        if (el) el.textContent = data.kpi.active_sources_count.toString();
      }
      if (data.kpi.parsed_rate) {
        const el = document.getElementById("kpiParsed");
        if (el) el.textContent = data.kpi.parsed_rate;
      }
      if (data.kpi.eps) {
        liveEps = data.kpi.eps;
        const el = document.getElementById("kpiEps");
        if (el) el.textContent = liveEps.toLocaleString();
      }
    }

    // Charts
    renderCharts(data.chart, data.severity_counts);

    // Top Sources
    const sourcesEl = document.getElementById("topSourcesList");
    if (sourcesEl && data.top_sources) {
      sourcesEl.innerHTML = data.top_sources.map((s) => `
        <div class="mb-3">
          <div class="d-flex justify-content-between text-sm mb-1">
            <span style="font-weight:500;">${XDRUtils.escapeHtml(s.name)}</span>
            <span class="text-muted">${s.count.toLocaleString()}</span>
          </div>
          <div class="xdr-progress">
            <div class="xdr-progress-bar bar-primary" style="width:${Math.max(4, s.percent)}%"></div>
          </div>
        </div>
      `).join("");
    }

    // Noisiest Hosts
    const hostsEl = document.getElementById("topHostsBody");
    if (hostsEl && data.noisiest_hosts) {
      hostsEl.innerHTML = data.noisiest_hosts.map((h) => `
        <tr>
          <td><a href="/siem/log-explorer?host=${encodeURIComponent(h.host)}" style="color:var(--text);font-weight:600;">${XDRUtils.escapeHtml(h.host)}</a></td>
          <td>${h.count.toLocaleString()}</td>
          <td>${XDRUtils.severityBadge(h.severity)}</td>
        </tr>
      `).join("");
    }

    // Pinned Searches
    const pinnedEl = document.getElementById("pinnedSearchesList");
    if (pinnedEl && data.pinned_searches) {
      pinnedEl.innerHTML = data.pinned_searches.length
        ? data.pinned_searches.map((s) => `
            <div class="mini-status-row">
              <span class="d-flex align-items-center gap-2">
                <i class="bi bi-bookmark-star-fill text-warning"></i>
                <a href="/siem/log-explorer?query=${encodeURIComponent(s.query)}" style="color:var(--text);font-weight:600;">${XDRUtils.escapeHtml(s.name)}</a>
              </span>
              <span class="badge ${s.alerting ? "badge-warning" : "badge-neutral"}">${s.hits || 0} hits</span>
            </div>
          `).join("")
        : `<p class="text-muted text-sm mb-0">No searches pinned yet.</p>`;
    }

    // Live Stream initial rows
    const streamEl = document.getElementById("liveLogStream");
    if (streamEl && data.stream && streamEl.children.length === 0) {
      streamEl.innerHTML = data.stream.map((r) => logRowHtml(r, false)).join("");
    }
  }

  // ---------- Live Stream Polling / Simulation ----------
  let streamEvents = [];
  function pushStreamRow() {
    const streamEl = document.getElementById("liveLogStream");
    if (!streamEl || streamEvents.length === 0) return;

    const template = streamEvents[Math.floor(Math.random() * streamEvents.length)];
    const fresh = {
      ...template,
      ts: new Date().toISOString(),
      id: template.id,
    };
    streamEl.insertAdjacentHTML("afterbegin", logRowHtml(fresh, true));
    while (streamEl.children.length > 24) {
      streamEl.removeChild(streamEl.lastChild);
    }
  }

  // ---------- Load Live Data from API ----------
  function loadDashboardData() {
    fetch("/siem/api/dashboard")
      .then((res) => res.json())
      .then((payload) => {
        if (payload && payload.success && payload.data) {
          streamEvents = payload.data.stream || [];
          renderDashboardUI(payload.data);
        }
      })
      .catch((err) => {
        console.warn("Could not load /siem/api/dashboard, using local fallback:", err);
        // Fallback to LOGS_DATA if available
        if (typeof LOGS_DATA !== "undefined" && typeof SAVED_SEARCHES_DATA !== "undefined") {
          streamEvents = LOGS_DATA;
          const streamEl = document.getElementById("liveLogStream");
          if (streamEl && streamEl.children.length === 0) {
            streamEl.innerHTML = LOGS_DATA.slice(0, 18).map((r) => logRowHtml(r, false)).join("");
          }
        }
      });
  }

  loadDashboardData();
  setInterval(pushStreamRow, 4000);

  // Live indicator tooltip refresh
  setInterval(() => {
    const el = document.getElementById("liveIndicator");
    if (el) el.title = `Updated ${timeAgo(new Date().toISOString())}`;
  }, 5000);
})();

