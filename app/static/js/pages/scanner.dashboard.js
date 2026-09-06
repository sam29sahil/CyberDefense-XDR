/* ==========================================================================
   scanner.dashboard.js — page module for app/scanner-dashboard.html
   Depends on: SCANS_DATA, VULNERABILITIES_DATA, TARGETS_DATA (fallbacks),
   XDR_CHART_DEFAULTS, XDR_PALETTE, xdrGradient, XDRUtils
   ========================================================================== */

(function () {
  const STATUS_LABEL = { completed: "Completed", running: "Running", queued: "Queued", failed: "Failed" };

  let vulnTrendChartInstance = null;
  let severityChartInstance = null;

  function renderDashboard(data) {
    // 1. KPIs
    const kpis = [
      { label: "Total Scans", value: data.kpis.total_scans, accent: "accent-primary", icon: "bi-search", sub: `${data.kpis.total_targets || 0} targets configured` },
      { label: "Active Scans", value: data.kpis.active_scans, accent: "accent-info", icon: "bi-hourglass-split", sub: "running or queued" },
      { label: "Critical Vulns", value: data.kpis.critical_vulns, accent: "accent-danger", icon: "bi-exclamation-octagon", sub: "unpatched" },
      { label: "Assets Scanned", value: data.kpis.assets_scanned, accent: "accent-success", icon: "bi-hdd-network", sub: "unique hosts" },
      { label: "Avg Risk Score", value: data.kpis.avg_risk_score, accent: "accent-warning", icon: "bi-speedometer2", sub: "0–99 scale" },
      { label: "Overdue Remediation", value: data.kpis.overdue_remediation, accent: "accent-danger", icon: "bi-clock-history", sub: "critical/high, still open" },
    ];
    const kpiRow = document.getElementById("kpiRow");
    if (kpiRow) {
      kpiRow.innerHTML = kpis.map((k) => `
        <div class="col-lg-2 col-md-4 col-6">
          <div class="card stat-card ${k.accent} h-100">
            <div class="eyebrow"><i class="bi ${k.icon}"></i> ${k.label}</div>
            <div class="stat-value">${k.value}</div>
            <span class="stat-delta text-muted text-truncate d-block" title="${k.sub}">${k.sub}</span>
          </div>
        </div>`).join("");
    }

    // 2. Vulnerability Trend (14 days)
    const trendCanvas = document.getElementById("vulnTrendChart");
    if (trendCanvas) {
      const ctx = trendCanvas.getContext("2d");
      const trendLabels = data.trend.map((t) => t.date.slice(5));
      const trendCounts = data.trend.map((t) => t.count);

      if (vulnTrendChartInstance) vulnTrendChartInstance.destroy();

      vulnTrendChartInstance = new Chart(ctx, {
        type: "line",
        data: {
          labels: trendLabels,
          datasets: [{
            label: "Findings",
            data: trendCounts,
            borderColor: XDR_PALETTE.activity[2],
            backgroundColor: xdrGradient(ctx, XDR_PALETTE.activity[2]),
            fill: true,
            tension: 0.35,
            pointRadius: 2,
            borderWidth: 2,
          }],
        },
        options: XDR_CHART_DEFAULTS,
      });
    }

    // 3. Severity Distribution
    const sevCanvas = document.getElementById("severityChart");
    if (sevCanvas) {
      const sevOrder = ["critical", "high", "medium", "low"];
      const sevCounts = sevOrder.map((s) => data.severity_distribution[s] || 0);

      if (severityChartInstance) severityChartInstance.destroy();

      severityChartInstance = new Chart(sevCanvas, {
        type: "doughnut",
        data: {
          labels: sevOrder.map((s) => s[0].toUpperCase() + s.slice(1)),
          datasets: [{
            data: sevCounts,
            backgroundColor: sevOrder.map((s) => XDR_PALETTE.severity[s]),
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

    // 4. Recent Scans Table
    const recentScansBody = document.getElementById("recentScansBody");
    if (recentScansBody) {
      const recent = data.recent_scans || [];
      recentScansBody.innerHTML = recent.length ? recent.map((s) => `
        <tr>
          <td>
            <a href="/scanner/details/${s.id}" style="color:var(--text);font-weight:600;text-decoration:none;">${s.name}</a>
            <div class="text-xs text-muted">${s.type}</div>
          </td>
          <td><span class="status-pill st-${s.status}"><span class="dot"></span>${STATUS_LABEL[s.status] || s.status}</span></td>
          <td>${(s.findingIds || []).length}</td>
          <td><span class="cell-mono">${s.riskScore}</span></td>
        </tr>`).join("") : `<tr><td colspan="4" class="text-center text-muted py-3">No scans recorded yet</td></tr>`;
    }

    // 5. Most Affected Hosts
    const topHostsList = document.getElementById("topHostsList");
    if (topHostsList) {
      const topHosts = data.top_affected_hosts || [];
      const maxCount = topHosts[0]?.count || 1;
      topHostsList.innerHTML = topHosts.length ? topHosts.map((item) => `
        <div class="mb-3">
          <div class="d-flex justify-content-between text-sm mb-1">
            <span><i class="bi bi-hdd-network text-muted me-1"></i>${item.host}</span>
            <span class="text-muted">${item.count} findings</span>
          </div>
          <div class="xdr-progress">
            <div class="xdr-progress-bar bar-danger" style="width:${Math.round((item.count / maxCount) * 100)}%"></div>
          </div>
        </div>`).join("") : `<div class="text-muted text-sm text-center py-3">No affected hosts found</div>`;
    }

    // 6. Critical & High Open Vulnerabilities
    const criticalVulnsBody = document.getElementById("criticalVulnsBody");
    if (criticalVulnsBody) {
      const vulns = data.critical_vulnerabilities || [];
      criticalVulnsBody.innerHTML = vulns.length ? vulns.map((v) => `
        <tr>
          <td><a href="/scanner/vulnerabilities/${v.id}" style="color:var(--text);font-weight:600;text-decoration:none;">${v.title}</a></td>
          <td><span class="cell-mono text-sm">${v.cve}</span></td>
          <td><span class="cvss-badge cvss-${v.severity}">${v.cvssScore}</span></td>
          <td class="text-sm">${(v.affectedAssets || []).join(", ") || "—"}</td>
          <td><span class="status-pill st-${v.status}"><span class="dot"></span>${(v.status || "").replace("_", " ")}</span></td>
        </tr>`).join("") : `<tr><td colspan="5"><div class="empty-state py-4"><i class="bi bi-shield-check text-success"></i><h3>No open critical/high findings</h3></div></td></tr>`;
    }
  }

  // Build fallback structure from local mock data if fetch fails
  function buildFallbackData() {
    const scans = typeof SCANS_DATA !== "undefined" ? SCANS_DATA : [];
    const vulns = typeof VULNERABILITIES_DATA !== "undefined" ? VULNERABILITIES_DATA : [];
    const targets = typeof TARGETS_DATA !== "undefined" ? TARGETS_DATA : [];

    const activeScans = scans.filter((s) => s.status === "running" || s.status === "queued");
    const criticalVulns = vulns.filter((v) => v.severity === "critical" && v.status !== "patched");
    const assetsScanned = [...new Set(scans.flatMap((s) => s.targets || []))].length;
    const avgRisk = scans.length ? Math.round(scans.reduce((s, sc) => s + (sc.riskScore || 0), 0) / scans.length) : 0;
    const overdue = vulns.filter((v) => v.status === "open" && (v.severity === "critical" || v.severity === "high")).length;

    const days = [];
    const now = new Date();
    for (let i = 13; i >= 0; i--) {
      days.push({
        date: new Date(now.getTime() - i * 86400000).toISOString().slice(0, 10),
        count: 0,
      });
    }

    const hostCounts = {};
    vulns.forEach((v) => (v.affectedAssets || []).forEach((h) => { hostCounts[h] = (hostCounts[h] || 0) + 1; }));
    const topHosts = Object.entries(hostCounts).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([host, count]) => ({ host, count }));

    return {
      kpis: {
        total_scans: scans.length,
        active_scans: activeScans.length,
        critical_vulns: criticalVulns.length,
        assets_scanned: assetsScanned,
        avg_risk_score: avgRisk,
        overdue_remediation: overdue,
        total_targets: targets.length,
      },
      severity_distribution: {
        critical: vulns.filter((v) => v.severity === "critical").length,
        high: vulns.filter((v) => v.severity === "high").length,
        medium: vulns.filter((v) => v.severity === "medium").length,
        low: vulns.filter((v) => v.severity === "low").length,
      },
      trend: days,
      recent_scans: scans.slice(0, 6),
      top_affected_hosts: topHosts,
      critical_vulnerabilities: vulns.filter((v) => (v.severity === "critical" || v.severity === "high") && v.status !== "patched").slice(0, 10),
    };
  }

  // Load from API
  fetch("/scanner/api/dashboard")
    .then((res) => (res.ok ? res.json() : Promise.reject(res)))
    .then((data) => {
      renderDashboard(data);
    })
    .catch(() => {
      renderDashboard(buildFallbackData());
    });
})();