/**
 * analytics.js — Security Analytics Dashboard Controller
 * CyberDefense XDR
 *
 * Communicates with /analytics/api/dashboard to display real, database-backed
 * cross-module metrics, time-series telemetry trends, and threat correlations.
 */

(function () {
  "use strict";

  // Chart instances for lifecycle management (destroy before recreate)
  let multiTrendChart = null;
  let alertSevChart = null;
  let incidentStatusChart = null;
  let vulnSevChart = null;
  let idsBreakdownChart = null;
  let siemSourcesChart = null;
  let iocTypesChart = null;
  let assetEnvChart = null;

  // Active filters state
  let currentRange = "7d";
  let customStart = null;
  let customEnd = null;

  // Auto-refresh state (default: 30 seconds)
  let autoRefreshTimer = null;
  let autoRefreshEnabled = true;
  const REFRESH_INTERVAL_MS = 30000;

  document.addEventListener("DOMContentLoaded", () => {
    initTimeRangeControls();
    initRefreshControls();
    loadAnalyticsData();
    startAutoRefresh();
  });

  /* ----------------------------------------------------
   * Utility Functions
   * ---------------------------------------------------- */
  function escapeHtml(str) {
    if (!str && str !== 0) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function setElText(id, val) {
    const el = document.getElementById(id);
    if (el) {
      el.textContent = val != null ? val.toLocaleString() : "0";
    }
  }

  function getSeverityBadge(sev) {
    const s = (sev || "low").toLowerCase();
    if (s === "critical") return '<span class="badge bg-danger text-uppercase fw-semibold">Critical</span>';
    if (s === "high") return '<span class="badge bg-danger-subtle text-danger text-uppercase fw-semibold">High</span>';
    if (s === "medium") return '<span class="badge bg-warning-subtle text-warning text-uppercase fw-semibold">Medium</span>';
    if (s === "low") return '<span class="badge bg-info-subtle text-info text-uppercase fw-semibold">Low</span>';
    return `<span class="badge bg-secondary-subtle text-light text-uppercase">${escapeHtml(s)}</span>`;
  }

  function getStatusBadge(status) {
    const s = (status || "unknown").toLowerCase();
    if (s === "online" || s === "closed" || s === "resolved") {
      return `<span class="badge bg-success-subtle text-success text-uppercase">${escapeHtml(s)}</span>`;
    }
    if (s === "offline" || s === "open" || s === "critical") {
      return `<span class="badge bg-danger-subtle text-danger text-uppercase">${escapeHtml(s)}</span>`;
    }
    if (s === "investigating" || s === "assigned" || s === "in_progress") {
      return `<span class="badge bg-warning-subtle text-warning text-uppercase">${escapeHtml(s)}</span>`;
    }
    return `<span class="badge bg-secondary-subtle text-light text-uppercase">${escapeHtml(s)}</span>`;
  }

  /* ----------------------------------------------------
   * Main Data Fetcher
   * ---------------------------------------------------- */
  async function loadAnalyticsData() {
    const refreshBtn = document.getElementById("btnRefreshNow");
    const refreshIcon = document.getElementById("refreshIcon");

    if (refreshBtn) refreshBtn.disabled = true;
    if (refreshIcon) refreshIcon.classList.add("spin");

    try {
      let url = `/analytics/api/dashboard?range=${encodeURIComponent(currentRange)}`;
      if (currentRange === "custom" && customStart && customEnd) {
        url += `&start=${encodeURIComponent(customStart)}&end=${encodeURIComponent(customEnd)}`;
      }

      const res = await fetch(url);
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: Failed to load analytics telemetry`);
      }
      const data = await res.json();

      if (!data.success) {
        throw new Error(data.error || "Analytics API returned unsuccessful response");
      }

      // Update Evaluation Window & Timestamp
      updateHeaderWindow(data.filters);

      // Render 8 Top KPIs
      renderOverviewKPIs(data.overview || {});

      // Render Multi-domain Trend Chart
      renderMultiTrendChart(data.trends || {});

      // Render Domain Charts
      renderAlertSeverityChart(data.alerts?.by_severity || {});
      renderIncidentStatusChart(data.incidents || {});
      renderVulnSeverityChart(data.vulnerabilities?.by_severity || {});
      renderIdsBreakdownChart(data.ids || {});
      renderSiemSourcesChart(data.siem?.by_source || []);
      renderIocTypesChart(data.threat_intel?.by_type || []);
      renderAssetEnvChart(data.assets?.by_environment || []);

      // Render Domain Details & Badges
      renderIncidentDetails(data.incidents || {});
      renderVulnDetails(data.vulnerabilities || {});
      renderIdsDetails(data.ids || {});
      renderSiemDetails(data.siem || {});
      renderThreatIntelDetails(data.threat_intel || {});
      renderAssetDetails(data.assets || {});

      // Render Cross-Module Correlation Insights
      renderCorrelations(data.correlations || {});

      // Render Top Risk Assets Table
      renderTopRiskAssets(data.assets?.top_risk_assets || []);

    } catch (err) {
      console.error("Analytics fetch error:", err);
      const winEl = document.getElementById("evaluatedWindowText");
      if (winEl) {
        winEl.innerHTML = `<span class="text-danger"><i class="bi bi-exclamation-triangle me-1"></i>${escapeHtml(err.message)}</span>`;
      }
    } finally {
      if (refreshBtn) refreshBtn.disabled = false;
      if (refreshIcon) refreshIcon.classList.remove("spin");
    }
  }

  /* ----------------------------------------------------
   * Active Window & Timestamp
   * ---------------------------------------------------- */
  function updateHeaderWindow(filters) {
    const winEl = document.getElementById("evaluatedWindowText");
    const updatedEl = document.getElementById("lastUpdatedText");

    if (updatedEl) {
      updatedEl.textContent = new Date().toLocaleTimeString();
    }

    if (!winEl || !filters) return;

    const startDate = new Date(filters.start);
    const endDate = new Date(filters.end);
    const startStr = startDate.toLocaleDateString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
    const endStr = endDate.toLocaleDateString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });

    let label = filters.range.toUpperCase();
    if (filters.range === "24h") label = "Last 24 Hours";
    else if (filters.range === "7d") label = "Last 7 Days";
    else if (filters.range === "30d") label = "Last 30 Days";
    else if (filters.range === "90d") label = "Last 90 Days";
    else if (filters.range === "custom") label = "Custom Range";

    winEl.textContent = `${label} (${startStr} — ${endStr})`;
  }

  /* ----------------------------------------------------
   * 8 Key Performance Indicators
   * ---------------------------------------------------- */
  function renderOverviewKPIs(o) {
    setElText("kpiTotalAssets", o.total_assets || 0);
    setElText("kpiOnlineAssets", o.online_assets || 0);
    setElText("kpiTotalAlerts", o.total_alerts || 0);
    setElText("kpiCriticalAlerts", o.critical_alerts || 0);
    setElText("kpiTotalIncidents", o.total_incidents || 0);
    setElText("kpiActiveIncidents", o.active_incidents || 0);
    setElText("kpiTotalVulns", o.total_vulnerabilities || 0);
    setElText("kpiCriticalVulns", o.critical_vulnerabilities || 0);
    setElText("kpiDetectionEvents", o.detection_events || 0);
    setElText("kpiIdsAlerts", o.ids_security_alerts || 0);
    setElText("kpiSiemEvents", o.siem_events || 0);
    setElText("kpiTotalIocs", o.total_iocs || 0);
  }

  /* ----------------------------------------------------
   * Multi-Domain Telemetry Trend Chart
   * ---------------------------------------------------- */
  function renderMultiTrendChart(t) {
    const canvas = document.getElementById("chartMultiTrend");
    if (!canvas) return;

    if (multiTrendChart) {
      multiTrendChart.destroy();
      multiTrendChart = null;
    }

    const labels = t.labels || [];
    const alerts = t.alerts || [];
    const ids = t.ids_alerts || [];
    const siem = t.siem_events || [];
    const detections = t.detections || [];
    const incidents = t.incidents || [];

    const ctx = canvas.getContext("2d");
    multiTrendChart = new Chart(ctx, {
      type: "line",
      data: {
        labels: labels,
        datasets: [
          {
            label: "Alerts",
            data: alerts,
            borderColor: "#dc3545",
            backgroundColor: "rgba(220, 53, 69, 0.12)",
            tension: 0.3,
            fill: true,
            pointRadius: 2,
            borderWidth: 2,
          },
          {
            label: "IDS Alerts",
            data: ids,
            borderColor: "#0dcaf0",
            backgroundColor: "rgba(13, 202, 240, 0.08)",
            tension: 0.3,
            fill: false,
            pointRadius: 2,
            borderWidth: 2,
          },
          {
            label: "SIEM Logs",
            data: siem,
            borderColor: "#198754",
            backgroundColor: "rgba(25, 135, 84, 0.08)",
            tension: 0.3,
            fill: false,
            pointRadius: 2,
            borderWidth: 2,
          },
          {
            label: "Detections",
            data: detections,
            borderColor: "#ffc107",
            backgroundColor: "rgba(255, 193, 7, 0.08)",
            tension: 0.3,
            fill: false,
            pointRadius: 2,
            borderWidth: 2,
          },
          {
            label: "Incidents",
            data: incidents,
            borderColor: "#adb5bd",
            backgroundColor: "rgba(173, 181, 189, 0.08)",
            tension: 0.3,
            fill: false,
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
            backgroundColor: "rgba(15, 23, 42, 0.95)",
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
   * Helper: Generic Doughnut Chart Renderer
   * ---------------------------------------------------- */
  function renderDoughnut(canvasId, labels, dataCounts, colors, existingChart) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return null;

    if (existingChart) {
      existingChart.destroy();
    }

    const allZero = dataCounts.length === 0 || dataCounts.every((c) => c === 0);
    const ctx = canvas.getContext("2d");

    return new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: allZero ? ["No Data"] : labels,
        datasets: [
          {
            data: allZero ? [1] : dataCounts,
            backgroundColor: allZero ? ["rgba(255, 255, 255, 0.1)"] : colors,
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
              font: { family: "Inter", size: 10 },
              usePointStyle: true,
              boxWidth: 8,
              padding: 10,
            },
          },
          tooltip: {
            enabled: !allZero,
            backgroundColor: "rgba(15, 23, 42, 0.95)",
          },
        },
      },
    });
  }

  /* ----------------------------------------------------
   * Alert Severity Chart
   * ---------------------------------------------------- */
  function renderAlertSeverityChart(bySev) {
    const labels = ["Critical", "High", "Medium", "Low"];
    const counts = [
      bySev.critical || 0,
      bySev.high || 0,
      bySev.medium || 0,
      bySev.low || 0,
    ];
    const colors = ["#dc3545", "#fd7e14", "#ffc107", "#0dcaf0"];
    alertSevChart = renderDoughnut("chartAlertSeverity", labels, counts, colors, alertSevChart);
  }

  /* ----------------------------------------------------
   * Incident Status Chart & Details
   * ---------------------------------------------------- */
  function renderIncidentStatusChart(inc) {
    const byStatus = inc.by_status || {};
    const labels = Object.keys(byStatus);
    const counts = labels.map((k) => byStatus[k]);
    const palette = ["#0dcaf0", "#6f42c1", "#ffc107", "#fd7e14", "#198754", "#6c757d"];
    const colors = labels.map((_, i) => palette[i % palette.length]);

    incidentStatusChart = renderDoughnut("chartIncidentStatus", labels.map(l => l.toUpperCase()), counts, colors, incidentStatusChart);
  }

  function renderIncidentDetails(inc) {
    const mttrVal = inc.mttr_hours != null ? `${inc.mttr_hours} hrs` : "N/A";
    const mttrEl = document.getElementById("mttrDisplay");
    const incMttrBadge = document.getElementById("incMttrValue");
    if (mttrEl) mttrEl.textContent = mttrVal;
    if (incMttrBadge) incMttrBadge.textContent = mttrVal;

    const listEl = document.getElementById("incidentCategoriesList");
    if (!listEl) return;

    const cats = inc.top_categories || [];
    if (cats.length === 0) {
      listEl.innerHTML = '<li class="list-group-item bg-transparent text-muted py-1 px-0">No incidents in this window.</li>';
      return;
    }

    listEl.innerHTML = cats.slice(0, 5).map(c => `
      <li class="list-group-item bg-transparent d-flex justify-content-between align-items-center py-1 px-0 border-bottom border-secondary">
        <span class="text-truncate text-light">${escapeHtml(c.category)}</span>
        <span class="badge bg-secondary-subtle text-light cell-mono">${c.count}</span>
      </li>
    `).join("");
  }

  /* ----------------------------------------------------
   * Vulnerability Severity Chart & Details
   * ---------------------------------------------------- */
  function renderVulnSeverityChart(bySev) {
    const labels = ["Critical", "High", "Medium", "Low"];
    const counts = [
      bySev.critical || 0,
      bySev.high || 0,
      bySev.medium || 0,
      bySev.low || 0,
    ];
    const colors = ["#dc3545", "#fd7e14", "#ffc107", "#0dcaf0"];
    vulnSevChart = renderDoughnut("chartVulnSeverity", labels, counts, colors, vulnSevChart);
  }

  function renderVulnDetails(vuln) {
    const toolsContainer = document.getElementById("vulnToolBadges");
    if (toolsContainer) {
      const tools = vuln.by_scanner_tool || [];
      if (tools.length === 0) {
        toolsContainer.innerHTML = '<span class="badge bg-secondary-subtle text-muted">No findings</span>';
      } else {
        toolsContainer.innerHTML = tools.map(t => `
          <span class="badge bg-primary-subtle text-primary border border-primary-subtle cell-mono">
            ${escapeHtml(t.tool)}: ${t.count}
          </span>
        `).join(" ");
      }
    }

    const cveContainer = document.getElementById("topCvesList");
    if (cveContainer) {
      const cves = vuln.top_cves || [];
      if (cves.length === 0) {
        cveContainer.innerHTML = '<span class="text-muted">No CVE findings evaluated.</span>';
      } else {
        cveContainer.innerHTML = cves.slice(0, 4).map(c => `
          <div class="d-flex justify-content-between align-items-center py-1 border-bottom border-secondary">
            <span class="cell-mono text-danger fw-semibold">${escapeHtml(c.cve_id)}</span>
            <span class="badge bg-danger-subtle text-danger cell-mono">${c.count} occurrences</span>
          </div>
        `).join("");
      }
    }
  }

  /* ----------------------------------------------------
   * Network IDS Breakdown Chart & Details
   * ---------------------------------------------------- */
  function renderIdsBreakdownChart(ids) {
    const threats = ids.security_alerts || 0;
    const diags = ids.diagnostic_events || 0;
    const labels = ["Security Alerts", "Checksum Diagnostics"];
    const counts = [threats, diags];
    const colors = ["#dc3545", "#6c757d"];
    idsBreakdownChart = renderDoughnut("chartIdsBreakdown", labels, counts, colors, idsBreakdownChart);
  }

  function renderIdsDetails(ids) {
    setElText("idsThreatsCount", ids.security_alerts || 0);
    setElText("idsDiagCount", ids.diagnostic_events || 0);

    const listEl = document.getElementById("idsSignaturesList");
    if (!listEl) return;

    const sigs = ids.top_signatures || [];
    if (sigs.length === 0) {
      listEl.innerHTML = '<li class="list-group-item bg-transparent text-muted py-1 px-0">No active signatures recorded.</li>';
      return;
    }

    listEl.innerHTML = sigs.slice(0, 4).map(s => `
      <li class="list-group-item bg-transparent d-flex justify-content-between align-items-center py-1 px-0 border-bottom border-secondary">
        <span class="text-truncate text-light me-2" title="${escapeHtml(s.signature)}">${escapeHtml(s.signature)}</span>
        <span class="badge bg-info-subtle text-info cell-mono flex-shrink-0">${s.count}</span>
      </li>
    `).join("");
  }

  /* ----------------------------------------------------
   * SIEM Sources Chart & Details
   * ---------------------------------------------------- */
  function renderSiemSourcesChart(sources) {
    const labels = (sources || []).slice(0, 5).map(s => s.source || "Unknown");
    const counts = (sources || []).slice(0, 5).map(s => s.count || 0);
    const palette = ["#198754", "#0dcaf0", "#ffc107", "#6f42c1", "#fd7e14"];
    const colors = labels.map((_, i) => palette[i % palette.length]);

    siemSourcesChart = renderDoughnut("chartSiemSources", labels, counts, colors, siemSourcesChart);
  }

  function renderSiemDetails(siem) {
    const listEl = document.getElementById("siemSourcesList");
    if (!listEl) return;

    const sources = siem.by_source || [];
    if (sources.length === 0) {
      listEl.innerHTML = '<li class="list-group-item bg-transparent text-muted py-1 px-0">No log sources active.</li>';
      return;
    }

    listEl.innerHTML = sources.slice(0, 5).map(s => `
      <li class="list-group-item bg-transparent d-flex justify-content-between align-items-center py-1 px-0 border-bottom border-secondary">
        <span class="text-truncate text-light">${escapeHtml(s.source)}</span>
        <span class="badge bg-success-subtle text-success cell-mono">${s.count}</span>
      </li>
    `).join("");
  }

  /* ----------------------------------------------------
   * Threat Intelligence Chart & Details
   * ---------------------------------------------------- */
  function renderIocTypesChart(byType) {
    const labels = (byType || []).map(t => (t.type || "unknown").toUpperCase());
    const counts = (byType || []).map(t => t.count || 0);
    const palette = ["#6f42c1", "#0dcaf0", "#198754", "#ffc107", "#dc3545"];
    const colors = labels.map((_, i) => palette[i % palette.length]);

    iocTypesChart = renderDoughnut("chartIocTypes", labels, counts, colors, iocTypesChart);
  }

  function renderThreatIntelDetails(ti) {
    setElText("tiActorsCount", ti.threat_actors_count || 0);
    setElText("tiCampaignsCount", ti.campaigns_count || 0);
    setElText("tiFeedsCount", ti.feeds_count || 0);

    const sevContainer = document.getElementById("tiSeverityBadges");
    if (sevContainer) {
      const sevs = ti.by_severity || [];
      if (sevs.length === 0) {
        sevContainer.innerHTML = '<span class="badge bg-secondary-subtle text-muted">No IOCs loaded</span>';
      } else {
        sevContainer.innerHTML = sevs.map(s => `
          <span class="badge bg-secondary-subtle text-light cell-mono">
            ${escapeHtml(s.severity)}: ${s.count}
          </span>
        `).join(" ");
      }
    }
  }

  /* ----------------------------------------------------
   * Asset Environments Chart & Details
   * ---------------------------------------------------- */
  function renderAssetEnvChart(byEnv) {
    const labels = (byEnv || []).map(e => (e.environment || "Unassigned").toUpperCase());
    const counts = (byEnv || []).map(e => e.count || 0);
    const palette = ["#0d6efd", "#0dcaf0", "#198754", "#ffc107", "#6c757d"];
    const colors = labels.map((_, i) => palette[i % palette.length]);

    assetEnvChart = renderDoughnut("chartAssetEnvironments", labels, counts, colors, assetEnvChart);
  }

  function renderAssetDetails(assets) {
    const riskTiersContainer = document.getElementById("assetRiskTiersList");
    if (riskTiersContainer) {
      const tiers = assets.risk_score_tiers || {};
      riskTiersContainer.innerHTML = `
        <div class="d-flex justify-content-between py-1 border-bottom border-secondary">
          <span class="text-danger fw-semibold">Critical (75-100):</span>
          <span class="cell-mono text-danger fw-bold">${tiers.critical || 0}</span>
        </div>
        <div class="d-flex justify-content-between py-1 border-bottom border-secondary">
          <span class="text-warning fw-semibold">High (50-74):</span>
          <span class="cell-mono text-warning">${tiers.high || 0}</span>
        </div>
        <div class="d-flex justify-content-between py-1 border-bottom border-secondary">
          <span class="text-info fw-semibold">Medium (25-49):</span>
          <span class="cell-mono text-info">${tiers.medium || 0}</span>
        </div>
        <div class="d-flex justify-content-between py-1 border-bottom border-secondary">
          <span class="text-success fw-semibold">Low (0-24):</span>
          <span class="cell-mono text-success">${tiers.low || 0}</span>
        </div>
      `;
    }

    const critContainer = document.getElementById("assetCriticalityBadges");
    if (critContainer) {
      const crits = assets.by_criticality || [];
      if (crits.length === 0) {
        critContainer.innerHTML = '<span class="badge bg-secondary-subtle text-muted">None</span>';
      } else {
        critContainer.innerHTML = crits.map(c => `
          <span class="badge bg-secondary-subtle text-light cell-mono">
            ${escapeHtml(c.criticality)}: ${c.count}
          </span>
        `).join(" ");
      }
    }
  }

  /* ----------------------------------------------------
   * Cross-Module Correlations
   * ---------------------------------------------------- */
  function renderCorrelations(cor) {
    setElText("corDualRiskCount", cor.dual_risk_count || 0);
    setElText("corDetectionsToIncidents", cor.incidents_from_detections || 0);
    setElText("corSiemDetections", cor.siem_correlated_detections || 0);
  }

  /* ----------------------------------------------------
   * Top Risk Monitored Assets Table
   * ---------------------------------------------------- */
  function renderTopRiskAssets(assets) {
    const tbody = document.getElementById("topRiskAssetsBody");
    if (!tbody) return;

    if (!assets || assets.length === 0) {
      tbody.innerHTML = '<tr><td colspan="10" class="text-center text-muted py-4">No monitored assets found in inventory.</td></tr>';
      return;
    }

    tbody.innerHTML = assets.map(a => {
      const score = a.risk_score || 0;
      let scoreColor = "text-success";
      if (score >= 75) scoreColor = "text-danger fw-bold";
      else if (score >= 50) scoreColor = "text-warning fw-semibold";
      else if (score >= 25) scoreColor = "text-info";

      return `
        <tr>
          <td>
            <div class="fw-semibold text-light">${escapeHtml(a.name)}</div>
            <div class="text-muted cell-mono extra-small">${escapeHtml(a.asset_id)}</div>
          </td>
          <td class="cell-mono">${escapeHtml(a.ip_address || "-")}</td>
          <td><span class="badge bg-secondary-subtle text-light">${escapeHtml(a.type || "host")}</span></td>
          <td><span class="badge bg-dark-subtle text-muted border border-secondary">${escapeHtml(a.environment || "default")}</span></td>
          <td>${getSeverityBadge(a.criticality)}</td>
          <td class="cell-mono ${scoreColor}">${score}</td>
          <td class="cell-mono">${a.open_vulnerabilities_count || 0}</td>
          <td class="cell-mono">${a.open_alerts_count || 0}</td>
          <td>${getStatusBadge(a.status)}</td>
          <td class="text-end">
            <a href="/assets/detail/${encodeURIComponent(a.id)}" class="btn btn-outline-primary btn-xs">
              <i class="bi bi-box-arrow-up-right me-1"></i>Inspect
            </a>
          </td>
        </tr>
      `;
    }).join("");
  }

  /* ----------------------------------------------------
   * Time Range & Presets Controls
   * ---------------------------------------------------- */
  function initTimeRangeControls() {
    const btnGroup = document.getElementById("rangeButtonGroup");
    const customCard = document.getElementById("customRangeCard");
    const customForm = document.getElementById("customDateForm");
    const errorEl = document.getElementById("customDateError");

    if (btnGroup) {
      btnGroup.addEventListener("click", (e) => {
        const btn = e.target.closest("button[data-range]");
        if (!btn) return;

        const range = btn.getAttribute("data-range");
        if (!range) return;

        // Update button active styles
        btnGroup.querySelectorAll("button").forEach(b => {
          b.classList.remove("btn-primary");
          b.classList.add("btn-outline-secondary");
        });
        btn.classList.remove("btn-outline-secondary");
        btn.classList.add("btn-primary");

        if (range === "custom") {
          if (customCard) customCard.classList.remove("d-none");
        } else {
          if (customCard) customCard.classList.add("d-none");
          currentRange = range;
          customStart = null;
          customEnd = null;
          loadAnalyticsData();
        }
      });
    }

    if (customForm) {
      customForm.addEventListener("submit", (e) => {
        e.preventDefault();
        const startInput = document.getElementById("customStartDate");
        const endInput = document.getElementById("customEndDate");

        if (!startInput || !endInput) return;
        const sVal = startInput.value;
        const eVal = endInput.value;

        if (!sVal || !eVal) {
          if (errorEl) errorEl.textContent = "Please select both start and end dates.";
          return;
        }

        const sDate = new Date(sVal);
        const eDate = new Date(eVal);

        if (sDate > eDate) {
          if (errorEl) errorEl.textContent = "Start date cannot be after end date.";
          return;
        }

        if (errorEl) errorEl.textContent = "";

        currentRange = "custom";
        customStart = sVal;
        customEnd = eVal;
        loadAnalyticsData();
      });
    }
  }

  /* ----------------------------------------------------
   * Auto-Refresh and Manual Refresh Controls
   * ---------------------------------------------------- */
  function initRefreshControls() {
    const manualBtn = document.getElementById("btnRefreshNow");
    if (manualBtn) {
      manualBtn.addEventListener("click", () => {
        loadAnalyticsData();
      });
    }

    const autoBtn = document.getElementById("btnAutoRefresh");
    const autoStatus = document.getElementById("autoRefreshStatus");
    if (autoBtn) {
      autoBtn.addEventListener("click", () => {
        autoRefreshEnabled = !autoRefreshEnabled;
        if (autoRefreshEnabled) {
          autoBtn.classList.remove("btn-outline-danger");
          autoBtn.classList.add("btn-outline-secondary");
          if (autoStatus) autoStatus.textContent = "30s";
          startAutoRefresh();
        } else {
          autoBtn.classList.remove("btn-outline-secondary");
          autoBtn.classList.add("btn-outline-danger");
          if (autoStatus) autoStatus.textContent = "OFF";
          stopAutoRefresh();
        }
      });
    }
  }

  function startAutoRefresh() {
    stopAutoRefresh();
    autoRefreshTimer = setInterval(() => {
      if (autoRefreshEnabled) {
        loadAnalyticsData();
      }
    }, REFRESH_INTERVAL_MS);
  }

  function stopAutoRefresh() {
    if (autoRefreshTimer) {
      clearInterval(autoRefreshTimer);
      autoRefreshTimer = null;
    }
  }

})();

