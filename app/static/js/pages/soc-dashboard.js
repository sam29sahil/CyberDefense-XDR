/**
 * soc-dashboard.js — SOC Operations Dashboard Controller
 * Fetches real, aggregated security telemetry from /soc-dashboard/api/dashboard.
 * Completely replaces all legacy mock data with live database records.
 */

(function () {
  "use strict";

  let trendChartInstance = null;
  let sevChartInstance = null;
  let autoRefreshTimer = null;
  let autoRefreshEnabled = true;

  document.addEventListener("DOMContentLoaded", () => {
    loadDashboardData();
    initRefreshControls();
  });

  function escapeHtml(str) {
    if (!str && str !== 0) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function getSeverityBadge(sev) {
    const s = (sev || "low").toLowerCase();
    if (s === "critical") return `<span class="badge bg-danger text-uppercase fw-semibold">Critical</span>`;
    if (s === "high") return `<span class="badge bg-danger-subtle text-danger text-uppercase fw-semibold">High</span>`;
    if (s === "medium") return `<span class="badge bg-warning-subtle text-warning text-uppercase fw-semibold">Medium</span>`;
    if (s === "low") return `<span class="badge bg-info-subtle text-info text-uppercase fw-semibold">Low</span>`;
    return `<span class="badge bg-secondary-subtle text-light text-uppercase">${escapeHtml(s)}</span>`;
  }

  /* ----------------------------------------------------
   * Main Data Fetcher
   * ---------------------------------------------------- */
  async function loadDashboardData() {
    const refreshBtn = document.getElementById("btnManualRefresh");
    const refreshIcon = document.getElementById("refreshIcon");

    if (refreshBtn) refreshBtn.disabled = true;
    if (refreshIcon) refreshIcon.classList.add("spin");

    try {
      const res = await fetch("/soc-dashboard/api/dashboard");
      if (!res.ok) throw new Error(`HTTP ${res.status}: Failed to fetch SOC dashboard data`);
      const data = await res.json();

      if (!data.success) {
        throw new Error(data.error || "Unknown server response");
      }

      // 1. Update Timestamp
      const updatedEl = document.getElementById("lastUpdatedText");
      if (updatedEl) {
        const d = new Date(data.generatedAt || new Date());
        updatedEl.textContent = d.toLocaleTimeString();
      }

      // 2. Render KPIs
      renderKPIs(data.summary || {});

      // 3. Render Charts
      renderTrendChart(data.trendTimeline || {});
      renderSeverityChart(data.alertOverview?.bySeverity || {});

      // 4. Render Operational Tables
      renderTopRiskAssets(data.assetRiskOverview?.topRiskAssets || []);
      renderRecentIncidents(data.incidentOverview?.recentIncidents || []);
      renderRecentAlerts(data.alertOverview?.recentAlerts || []);

      // 5. Render Activity Stream
      renderActivityFeed(data.activityFeed || []);

      // 6. Render Module Telemetry Snapshots
      renderModuleSnapshots(data);

    } catch (err) {
      console.error("SOC Dashboard fetch error:", err);
      const updatedEl = document.getElementById("lastUpdatedText");
      if (updatedEl) updatedEl.innerHTML = `<span class="text-danger">Error updating</span>`;
    } finally {
      if (refreshBtn) refreshBtn.disabled = false;
      if (refreshIcon) refreshIcon.classList.remove("spin");
    }
  }

  /* ----------------------------------------------------
   * 1. Render Top-Level KPIs
   * ---------------------------------------------------- */
  function renderKPIs(s) {
    const setVal = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val != null ? val.toLocaleString() : "0";
    };

    setVal("kpiTotalAssets", s.totalAssets || 0);
    setVal("kpiOnlineAssets", s.onlineAssets || 0);
    setVal("kpiOpenAlerts", s.openAlerts || 0);
    setVal("kpiCriticalAlerts", s.criticalAlerts || 0);
    setVal("kpiActiveIncidents", s.activeIncidents || 0);
    setVal("kpiCritIncidents", s.criticalIncidents || 0);
    setVal("kpiOpenVulns", s.openVulnerabilities || 0);
    setVal("kpiCritVulns", s.criticalVulnerabilities || 0);
    setVal("kpiIdsAlerts", s.idsAlertsToday || 0);
    setVal("kpiSiemEvents", s.siemEventsToday || 0);
  }

  /* ----------------------------------------------------
   * 2. Render 24-Hour Trend Chart
   * ---------------------------------------------------- */
  function renderTrendChart(trend) {
    const canvas = document.getElementById("chartTrend24h");
    if (!canvas) return;

    if (trendChartInstance) {
      trendChartInstance.destroy();
      trendChartInstance = null;
    }

    const labels = trend.hours || [];
    const alertsData = trend.alerts || [];
    const idsData = trend.idsAlerts || [];
    const detectionsData = trend.detections || [];

    const ctx = canvas.getContext("2d");
    trendChartInstance = new Chart(ctx, {
      type: "line",
      data: {
        labels: labels,
        datasets: [
          {
            label: "Security Alerts",
            data: alertsData,
            borderColor: "#dc3545",
            backgroundColor: "rgba(220, 53, 69, 0.15)",
            tension: 0.3,
            fill: true,
            pointRadius: 2,
            borderWidth: 2,
          },
          {
            label: "IDS Alerts",
            data: idsData,
            borderColor: "#0dcaf0",
            backgroundColor: "rgba(13, 202, 240, 0.1)",
            tension: 0.3,
            fill: true,
            pointRadius: 2,
            borderWidth: 2,
          },
          {
            label: "Detection Events",
            data: detectionsData,
            borderColor: "#ffc107",
            backgroundColor: "rgba(255, 193, 7, 0.1)",
            tension: 0.3,
            fill: true,
            pointRadius: 2,
            borderWidth: 2,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "rgba(15, 23, 42, 0.9)",
            titleFont: { family: "Inter", size: 12 },
            bodyFont: { family: "JetBrains Mono", size: 11 },
          },
        },
        scales: {
          x: {
            grid: { color: "rgba(255, 255, 255, 0.05)" },
            ticks: { color: "rgba(255, 255, 255, 0.5)", font: { family: "JetBrains Mono", size: 10 } },
          },
          y: {
            beginAtZero: true,
            grid: { color: "rgba(255, 255, 255, 0.05)" },
            ticks: {
              color: "rgba(255, 255, 255, 0.5)",
              font: { family: "JetBrains Mono", size: 10 },
              precision: 0,
            },
          },
        },
      },
    });
  }

  /* ----------------------------------------------------
   * 3. Render Alert Severity Doughnut Chart
   * ---------------------------------------------------- */
  function renderSeverityChart(bySev) {
    const canvas = document.getElementById("chartAlertSeverity");
    if (!canvas) return;

    if (sevChartInstance) {
      sevChartInstance.destroy();
      sevChartInstance = null;
    }

    const counts = [
      bySev.critical || 0,
      bySev.high || 0,
      bySev.medium || 0,
      bySev.low || 0,
    ];

    const allZero = counts.every((c) => c === 0);

    const ctx = canvas.getContext("2d");
    sevChartInstance = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: ["Critical", "High", "Medium", "Low"],
        datasets: [
          {
            data: allZero ? [1] : counts,
            backgroundColor: allZero
              ? ["rgba(255, 255, 255, 0.1)"]
              : ["#dc3545", "#fd7e14", "#ffc107", "#0dcaf0"],
            borderWidth: 0,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "70%",
        plugins: {
          legend: {
            display: !allZero,
            position: "bottom",
            labels: {
              color: "rgba(255, 255, 255, 0.7)",
              font: { family: "Inter", size: 11 },
              usePointStyle: true,
              boxWidth: 8,
              padding: 12,
            },
          },
          tooltip: {
            enabled: !allZero,
            backgroundColor: "rgba(15, 23, 42, 0.9)",
          },
        },
      },
    });
  }

  /* ----------------------------------------------------
   * 4. Render Top Risk Assets
   * ---------------------------------------------------- */
  function renderTopRiskAssets(assets) {
    const tbody = document.getElementById("topRiskAssetsBody");
    if (!tbody) return;

    if (!assets || assets.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted py-4"><i class="bi bi-shield-check text-success fs-4 d-block mb-1"></i>No assets currently registered or evaluated.</td></tr>`;
      return;
    }

    tbody.innerHTML = assets.map((a) => `
      <tr>
        <td>
          <a href="/assets/${encodeURIComponent(a.assetId)}" class="fw-semibold text-light text-decoration-none hover-primary">
            ${escapeHtml(a.name)}
          </a>
          <div class="text-muted cell-mono text-xs">${escapeHtml(a.assetId)}</div>
        </td>
        <td>
          <div class="cell-mono text-info">${escapeHtml(a.ip)}</div>
          <span class="badge bg-secondary-subtle text-light text-xs">${escapeHtml(a.type || 'Server')}</span>
        </td>
        <td>
          <div class="fw-bold cell-mono ${a.riskScore >= 80 ? 'text-danger' : a.riskScore >= 60 ? 'text-warning' : 'text-info'}">
            ${a.riskScore} <span class="text-muted text-xs">/ 100</span>
          </div>
        </td>
        <td>${getSeverityBadge(a.severity)}</td>
        <td>
          <span class="badge bg-danger-subtle text-danger me-1 cell-mono" title="Vulnerabilities">${a.openVulns || 0}V</span>
          <span class="badge bg-warning-subtle text-warning cell-mono" title="Active Alerts">${a.openAlerts || 0}A</span>
        </td>
        <td>
          <span class="badge ${a.status === 'online' ? 'bg-success-subtle text-success' : 'bg-secondary-subtle text-muted'}">
            ${escapeHtml(a.status || 'offline')}
          </span>
        </td>
      </tr>
    `).join("");
  }

  /* ----------------------------------------------------
   * 5. Render Active Incidents
   * ---------------------------------------------------- */
  function renderRecentIncidents(incidents) {
    const tbody = document.getElementById("recentIncidentsBody");
    if (!tbody) return;

    if (!incidents || incidents.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted py-4"><i class="bi bi-check-circle text-success fs-4 d-block mb-1"></i>No active security incidents at this time.</td></tr>`;
      return;
    }

    tbody.innerHTML = incidents.map((inc) => `
      <tr>
        <td>
          <a href="/incidents/${encodeURIComponent(inc.incidentId)}" class="cell-mono fw-semibold text-primary text-decoration-none">
            ${escapeHtml(inc.incidentId)}
          </a>
        </td>
        <td class="fw-medium text-light text-truncate" style="max-width: 180px;" title="${escapeHtml(inc.title)}">
          ${escapeHtml(inc.title)}
        </td>
        <td>${getSeverityBadge(inc.severity)}</td>
        <td><span class="badge bg-secondary-subtle text-capitalize">${escapeHtml(inc.status)}</span></td>
        <td class="small text-muted">${escapeHtml(inc.assignedTo)}</td>
        <td class="cell-mono text-muted text-xs">${escapeHtml(inc.createdAt)}</td>
      </tr>
    `).join("");
  }

  /* ----------------------------------------------------
   * 6. Render Recent Alerts
   * ---------------------------------------------------- */
  function renderRecentAlerts(alerts) {
    const tbody = document.getElementById("recentAlertsBody");
    if (!tbody) return;

    if (!alerts || alerts.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted py-4"><i class="bi bi-bell-slash text-muted fs-4 d-block mb-1"></i>No security alerts recorded.</td></tr>`;
      return;
    }

    tbody.innerHTML = alerts.map((a) => `
      <tr>
        <td>${getSeverityBadge(a.severity)}</td>
        <td>
          <a href="/alert-center/" class="fw-semibold text-light text-decoration-none hover-primary">
            ${escapeHtml(a.title)}
          </a>
          <div class="text-muted cell-mono text-xs">${escapeHtml(a.alertId)}</div>
        </td>
        <td class="cell-mono text-info small">${escapeHtml(a.host)}</td>
        <td><span class="badge bg-secondary-subtle text-light text-xs">${escapeHtml(a.source || 'Alert')}</span></td>
        <td><span class="badge bg-secondary-subtle text-capitalize">${escapeHtml(a.status)}</span></td>
        <td class="cell-mono text-muted text-xs">${escapeHtml(a.createdAt)}</td>
      </tr>
    `).join("");
  }

  /* ----------------------------------------------------
   * 7. Render Unified Activity Feed
   * ---------------------------------------------------- */
  function renderActivityFeed(feed) {
    const container = document.getElementById("activityFeedContainer");
    const countEl = document.getElementById("activityFeedCount");
    if (!container) return;

    if (countEl) countEl.textContent = `${feed.length} events`;

    if (!feed || feed.length === 0) {
      container.innerHTML = `<p class="text-center text-muted py-4"><i class="bi bi-inbox text-muted fs-4 d-block mb-1"></i>No recent security activity logged.</p>`;
      return;
    }

    container.innerHTML = feed.map((item) => {
      const sevClass = `sev-${(item.severity || "low").toLowerCase()}`;
      return `
        <div class="soc-feed-item ${sevClass}">
          <div class="d-flex justify-content-between align-items-center mb-1">
            <div>
              <span class="badge bg-secondary-subtle text-light me-1">${escapeHtml(item.source)}</span>
              ${getSeverityBadge(item.severity)}
            </div>
            <span class="text-muted cell-mono text-xs">${escapeHtml(item.timestamp)}</span>
          </div>
          <a href="${escapeHtml(item.url || '#')}" class="text-decoration-none fw-semibold text-light hover-primary d-block">
            ${escapeHtml(item.title)}
          </a>
          <div class="small text-muted text-truncate">${escapeHtml(item.description)}</div>
        </div>
      `;
    }).join("");
  }

  /* ----------------------------------------------------
   * 8. Render Module Snapshots
   * ---------------------------------------------------- */
  function renderModuleSnapshots(data) {
    // Network IDS
    const ids = data.idsOverview || {};
    const idsSensor = ids.sensorStatus || {};
    const stateBadge = document.getElementById("idsSensorStateBadge");
    if (stateBadge) {
      const isRunning = idsSensor.running;
      stateBadge.className = `badge ${isRunning ? 'bg-success-subtle text-success' : 'bg-secondary-subtle text-muted'}`;
      stateBadge.textContent = isRunning ? "Running" : "Stopped";
    }
    const idsTot = document.getElementById("idsTotalToday");
    if (idsTot) idsTot.textContent = (ids.eventsToday || 0).toLocaleString();
    const idsSec = document.getElementById("idsSecurityAlertsToday");
    if (idsSec) idsSec.textContent = (ids.alertsToday || 0).toLocaleString();
    const idsTop = document.getElementById("idsTopSignature");
    if (idsTop) {
      const topSig = ids.topSignatures && ids.topSignatures[0];
      idsTop.textContent = topSig ? `${topSig.signature} (${topSig.count})` : "None captured";
    }

    // SIEM
    const siem = data.siemOverview || {};
    const siemTot = document.getElementById("siemTotalToday");
    if (siemTot) siemTot.textContent = (siem.eventsToday || 0).toLocaleString();
    const siemCrit = document.getElementById("siemCritCount");
    if (siemCrit) siemCrit.textContent = (siem.bySeverity?.critical || 0).toLocaleString();
    const siemSources = document.getElementById("siemSourcesCount");
    if (siemSources) siemSources.textContent = (siem.topSources ? siem.topSources.length : 0).toString();
    const siemTop = document.getElementById("siemTopSource");
    if (siemTop) {
      const topSrc = siem.topSources && siem.topSources[0];
      siemTop.textContent = topSrc ? `${topSrc.source} (${topSrc.count})` : "None recorded";
    }

    // Detection
    const det = data.detectionOverview || {};
    const detRules = document.getElementById("detectionActiveRules");
    if (detRules) detRules.textContent = (det.activeRules || 0).toLocaleString();
    const detEvts = document.getElementById("detectionEventsToday");
    if (detEvts) detEvts.textContent = (det.eventsToday || 0).toLocaleString();
    const detCrit = document.getElementById("detectionCritHighToday");
    if (detCrit) detCrit.textContent = (det.criticalHighEvents || 0).toLocaleString();

    // Threat Intel
    const ti = data.threatIntelOverview || {};
    const tiIocs = document.getElementById("tiTotalIocs");
    if (tiIocs) tiIocs.textContent = (ti.totalIocs || 0).toLocaleString();
    const tiCamps = document.getElementById("tiActiveCampaigns");
    if (tiCamps) tiCamps.textContent = (ti.activeCampaigns || 0).toLocaleString();
    const tiActs = document.getElementById("tiThreatActors");
    if (tiActs) tiActs.textContent = (ti.threatActors || 0).toLocaleString();
    const tiFeeds = document.getElementById("tiActiveFeeds");
    if (tiFeeds) tiFeeds.textContent = (ti.activeFeeds || 0).toLocaleString();
  }

  /* ----------------------------------------------------
   * 9. Refresh & Auto-Refresh Controls
   * ---------------------------------------------------- */
  function initRefreshControls() {
    const manualBtn = document.getElementById("btnManualRefresh");
    if (manualBtn) {
      manualBtn.addEventListener("click", () => {
        loadDashboardData();
      });
    }

    const autoBtn = document.getElementById("btnAutoRefresh");
    const autoStatus = document.getElementById("autoRefreshStatus");

    function setupAutoRefresh() {
      if (autoRefreshTimer) {
        clearInterval(autoRefreshTimer);
        autoRefreshTimer = null;
      }
      if (autoRefreshEnabled) {
        autoRefreshTimer = setInterval(() => {
          loadDashboardData();
        }, 30000);
      }
    }

    if (autoBtn) {
      autoBtn.addEventListener("click", () => {
        autoRefreshEnabled = !autoRefreshEnabled;
        autoBtn.dataset.enabled = autoRefreshEnabled ? "true" : "false";
        if (autoRefreshEnabled) {
          autoBtn.className = "btn btn-outline-secondary btn-sm";
          if (autoStatus) autoStatus.textContent = "30s";
        } else {
          autoBtn.className = "btn btn-outline-danger btn-sm";
          if (autoStatus) autoStatus.textContent = "Off";
        }
        setupAutoRefresh();
      });
    }

    setupAutoRefresh();
  }

})();