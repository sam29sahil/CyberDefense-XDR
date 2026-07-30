/* ==========================================================================
   scanner-dashboard.js — page module for app/scanner-dashboard.html
   Depends on: SCANS_DATA, VULNERABILITIES_DATA, TARGETS_DATA,
   XDR_CHART_DEFAULTS, XDR_PALETTE, xdrGradient, XDRUtils
   ========================================================================== */

   (function () {
    const scans = SCANS_DATA;
    const vulns = VULNERABILITIES_DATA;
    const STATUS_LABEL = { completed: "Completed", running: "Running", queued: "Queued" };
  
    const activeScans = scans.filter((s) => s.status === "running" || s.status === "queued");
    const criticalVulns = vulns.filter((v) => v.severity === "critical" && v.status !== "patched");
    const assetsScanned = [...new Set(scans.flatMap((s) => s.targets))].length;
    const avgRisk = scans.length ? Math.round(scans.reduce((s, sc) => s + sc.riskScore, 0) / scans.length) : 0;
    const overdue = vulns.filter((v) => v.status === "open" && (v.severity === "critical" || v.severity === "high")).length;
  
    const kpis = [
      { label: "Total Scans", value: scans.length, accent: "accent-primary", icon: "bi-search", sub: `${TARGETS_DATA.length} targets configured` },
      { label: "Active Scans", value: activeScans.length, accent: "accent-info", icon: "bi-hourglass-split", sub: "running or queued" },
      { label: "Critical Vulns", value: criticalVulns.length, accent: "accent-danger", icon: "bi-exclamation-octagon", sub: "unpatched" },
      { label: "Assets Scanned", value: assetsScanned, accent: "accent-success", icon: "bi-hdd-network", sub: "unique hosts" },
      { label: "Avg Risk Score", value: avgRisk, accent: "accent-warning", icon: "bi-speedometer2", sub: "0–99 scale" },
      { label: "Overdue Remediation", value: overdue, accent: "accent-danger", icon: "bi-clock-history", sub: "critical/high, still open" },
    ];
    document.getElementById("kpiRow").innerHTML = kpis.map((k) => `
      <div class="col-lg-2 col-md-4 col-6">
        <div class="card stat-card ${k.accent} h-100">
          <div class="eyebrow"><i class="bi ${k.icon}"></i> ${k.label}</div>
          <div class="stat-value">${k.value}</div>
          <span class="stat-delta text-muted text-truncate d-block" title="${k.sub}">${k.sub}</span>
        </div>
      </div>`).join("");
  
    // ---------- Vulnerabilities found trend (14 days, derived from scan completion) ----------
    const days = [];
    const now = new Date("2026-07-24T09:58:00Z");
    for (let i = 13; i >= 0; i--) days.push(new Date(now.getTime() - i * 86400000).toISOString().slice(0, 10));
    const countsByDay = days.map((day) =>
      scans.filter((s) => s.startedAt.startsWith(day)).reduce((sum, s) => sum + s.findingIds.length, 0)
    );
    const ctx = document.getElementById("vulnTrendChart").getContext("2d");
    new Chart(ctx, {
      type: "line",
      data: {
        labels: days.map((d) => d.slice(5)),
        datasets: [{ label: "Findings", data: countsByDay, borderColor: XDR_PALETTE.activity[2], backgroundColor: xdrGradient(ctx, XDR_PALETTE.activity[2]), fill: true, tension: 0.35, pointRadius: 0, borderWidth: 2 }],
      },
      options: XDR_CHART_DEFAULTS,
    });
  
    // ---------- Severity distribution (catalog-wide) ----------
    const sevOrder = ["critical", "high", "medium", "low"];
    const sevCounts = sevOrder.map((s) => vulns.filter((v) => v.severity === s).length);
    new Chart(document.getElementById("severityChart"), {
      type: "doughnut",
      data: { labels: sevOrder.map((s) => s[0].toUpperCase() + s.slice(1)), datasets: [{ data: sevCounts, backgroundColor: sevOrder.map((s) => XDR_PALETTE.severity[s]), borderWidth: 0 }] },
      options: { responsive: true, maintainAspectRatio: false, cutout: "68%", plugins: { legend: { display: true, position: "bottom", labels: { usePointStyle: true, boxWidth: 8, boxHeight: 8 } } } },
    });
  
    // ---------- Recent scans ----------
    const recent = scans.slice(0, 6);
    document.getElementById("recentScansBody").innerHTML = recent.map((s) => `
      <tr>
        <td><a href="scan-details.html?id=${s.id}" style="color:var(--text);font-weight:600;text-decoration:none;">${s.name}</a>
          <div class="text-xs text-muted">${s.type}</div></td>
        <td><span class="status-pill st-${s.status}"><span class="dot"></span>${STATUS_LABEL[s.status]}</span></td>
        <td>${s.findingIds.length}</td>
        <td><span class="cell-mono">${s.riskScore}</span></td>
      </tr>`).join("");
  
    // ---------- Most affected hosts ----------
    const hostCounts = {};
    vulns.forEach((v) => v.affectedAssets.forEach((h) => { hostCounts[h] = (hostCounts[h] || 0) + 1; }));
    const topHosts = Object.entries(hostCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);
    const maxHost = topHosts[0]?.[1] || 1;
    document.getElementById("topHostsList").innerHTML = topHosts.map(([host, count]) => `
      <div class="mb-3">
        <div class="d-flex justify-content-between text-sm mb-1"><span>${host}</span><span class="text-muted">${count} findings</span></div>
        <div class="xdr-progress"><div class="xdr-progress-bar bar-danger" style="width:${Math.round(count / maxHost * 100)}%"></div></div>
      </div>`).join("");
  
    // ---------- Critical/high open vulnerabilities table ----------
    const criticalHigh = vulns.filter((v) => (v.severity === "critical" || v.severity === "high") && v.status !== "patched")
      .sort((a, b) => b.cvssScore - a.cvssScore);
    document.getElementById("criticalVulnsBody").innerHTML = criticalHigh.map((v) => `
      <tr>
        <td><a href="vulnerability-details.html?id=${v.id}" style="color:var(--text);font-weight:600;text-decoration:none;">${v.title}</a></td>
        <td><span class="cell-mono text-sm">${v.cve}</span></td>
        <td><span class="cvss-badge cvss-${v.severity}">${v.cvssScore}</span></td>
        <td class="text-sm">${v.affectedAssets.length} hosts</td>
        <td><span class="status-pill st-${v.status}"><span class="dot"></span>${v.status.replace("_", " ")}</span></td>
      </tr>`).join("") || `<tr><td colspan="5"><div class="empty-state"><i class="bi bi-shield-check"></i><h3>No open critical/high findings</h3></div></td></tr>`;
  })();
  