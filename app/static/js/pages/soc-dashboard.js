/* ==========================================================================
   soc-dashboard.js — page module for app/soc-dashboard.html
   Depends on: ALERTS_DATA, CASES_DATA, ANALYSTS_DATA (data/*),
   XDR_CHART_DEFAULTS, XDR_PALETTE, xdrGradient (core/charts.js), XDRUtils
   ========================================================================== */

   (function () {
    const alerts = ALERTS_DATA;
    const cases = CASES_DATA;
    const analysts = ANALYSTS_DATA;
  
    const now = new Date("2026-07-24T09:58:00Z");
    const openAlerts = alerts.filter((a) => a.status !== "closed");
    const criticalAlerts = alerts.filter((a) => a.severity === "critical" && a.status !== "closed");
    const activeInvestigations = cases.filter((c) => c.status === "open" || c.status === "in_progress");
    const assignedCases = cases.filter((c) => c.status !== "closed");
    const closedAlertsLast30 = alerts.filter((a) => a.status === "closed");
    const avgMttrHours = closedAlertsLast30.length
      ? Math.round(closedAlertsLast30.reduce((sum) => sum + (Math.random() * 5 + 1), 0) / closedAlertsLast30.length * 10) / 10
      : 0;
    const threatScore = Math.min(99, Math.round(40 + criticalAlerts.length * 4 + openAlerts.length * 0.6));
  
    // ---------- KPI cards ----------
    const kpis = [
      { label: "Open Alerts", value: openAlerts.length, accent: "accent-primary", icon: "bi-bell", sub: `${alerts.length} total` },
      { label: "Critical Alerts", value: criticalAlerts.length, accent: "accent-danger", icon: "bi-skull", sub: "unresolved" },
      { label: "Investigations", value: activeInvestigations.length, accent: "accent-warning", icon: "bi-kanban", sub: `${cases.length} total cases` },
      { label: "Assigned Cases", value: assignedCases.length, accent: "accent-info", icon: "bi-person-check", sub: "not yet closed" },
      { label: "Threat Score", value: threatScore, accent: "accent-danger", icon: "bi-speedometer2", sub: "org-wide, 0–99" },
      { label: "MTTR", value: `${avgMttrHours}h`, accent: "accent-success", icon: "bi-stopwatch", sub: "mean time to resolve" },
    ];
    document.getElementById("kpiRow").innerHTML = kpis.map((k) => `
      <div class="col-lg-2 col-md-4 col-6">
        <div class="card stat-card ${k.accent} h-100">
          <div class="eyebrow"><i class="bi ${k.icon}"></i> ${k.label}</div>
          <div class="stat-value">${k.value}</div>
          <span class="stat-delta text-muted text-truncate d-block" title="${XDRUtils.escapeHtml(k.sub)}">${XDRUtils.escapeHtml(k.sub)}</span>
        </div>
      </div>`).join("");
  
    // ---------- Alerts timeline (14 days, stacked crit/high/medium) ----------
    const days = [];
    for (let i = 13; i >= 0; i--) days.push(new Date(now.getTime() - i * 86400000).toISOString().slice(0, 10));
    const bySevByDay = (sev) => days.map((day) => alerts.filter((a) => a.ts.startsWith(day) && a.severity === sev).length);
  
    new Chart(document.getElementById("alertsTimelineChart"), {
      type: "bar",
      data: {
        labels: days.map((d) => d.slice(5)),
        datasets: ["critical", "high", "medium"].map((sev) => ({
          label: sev, data: bySevByDay(sev), backgroundColor: XDR_PALETTE.severity[sev], borderRadius: 2,
        })),
      },
      options: {
        ...XDR_CHART_DEFAULTS,
        scales: { x: { ...XDR_CHART_DEFAULTS.scales.x, stacked: true }, y: { ...XDR_CHART_DEFAULTS.scales.y, stacked: true } },
      },
    });
  
    // ---------- Severity distribution ----------
    const sevOrder = ["critical", "high", "medium", "low"];
    new Chart(document.getElementById("severityDistChart"), {
      type: "doughnut",
      data: {
        labels: sevOrder.map((s) => s[0].toUpperCase() + s.slice(1)),
        datasets: [{ data: sevOrder.map((s) => alerts.filter((a) => a.severity === s).length), backgroundColor: sevOrder.map((s) => XDR_PALETTE.severity[s]), borderWidth: 0 }],
      },
      options: {
        responsive: true, maintainAspectRatio: false, cutout: "68%",
        plugins: { legend: { display: true, position: "bottom", labels: { usePointStyle: true, boxWidth: 8, boxHeight: 8 } } },
      },
    });
  
    // ---------- Alerts per hour, today ----------
    const hours = Array.from({ length: 24 }, (_, h) => h);
    const todayStr = now.toISOString().slice(0, 10);
    const perHour = hours.map((h) => alerts.filter((a) => a.ts.startsWith(todayStr) && new Date(a.ts).getUTCHours() === h).length);
    const perHourCtx = document.getElementById("perHourChart").getContext("2d");
    new Chart(perHourCtx, {
      type: "line",
      data: {
        labels: hours.map((h) => `${h}:00`),
        datasets: [{ label: "Alerts", data: perHour, borderColor: XDR_PALETTE.activity[0], backgroundColor: xdrGradient(perHourCtx, XDR_PALETTE.activity[0]), fill: true, tension: 0.35, pointRadius: 0, borderWidth: 2 }],
      },
      options: XDR_CHART_DEFAULTS,
    });
  
    // ---------- Analyst workload ----------
    const maxWorkload = Math.max(...analysts.map((a) => a.workloadScore), 1);
    document.getElementById("workloadList").innerHTML = analysts.map((a) => `
      <div class="analyst-load-row">
        <span class="avatar avatar-sm">${a.initials}</span>
        <span class="aln-name">${a.name}</span>
        <div class="xdr-progress"><div class="xdr-progress-bar bar-primary" style="width:${Math.round(a.workloadScore / maxWorkload * 100)}%"></div></div>
        <span class="text-muted text-xs">${a.assignedAlerts + a.assignedCases}</span>
      </div>`).join("");
  
    // ---------- Recent alerts table ----------
    const recent = alerts.slice(0, 8);
    document.getElementById("recentAlertsBody").innerHTML = recent.map((a) => `
      <tr>
        <td><span class="priority-pill p-${a.priority}">${a.priority}</span></td>
        <td><a href="alert-details.html?id=${a.id}" style="color:var(--text);font-weight:600;text-decoration:none;">${XDRUtils.escapeHtml(a.title)}</a></td>
        <td>${a.host}</td>
        <td><span class="badge ${a.status === "closed" ? "badge-success" : a.status === "investigating" ? "badge-warning" : "badge-info"}">${a.status}</span></td>
      </tr>`).join("");
  
    // ---------- Active investigations list ----------
    document.getElementById("activeCasesList").innerHTML = activeInvestigations.slice(0, 6).map((c) => `
      <div class="queue-item">
        <span class="priority-pill p-${c.priority}">${c.priority}</span>
        <a href="case-details.html?id=${c.id}" class="qi-title" style="color:var(--text);text-decoration:none;">${XDRUtils.escapeHtml(c.title)}</a>
        <span class="avatar avatar-sm" title="${c.owner}">${c.ownerInitials}</span>
      </div>`).join("") || `<div class="empty-state"><i class="bi bi-inbox"></i><h3>No active investigations</h3><p>All cases are currently resolved.</p></div>`;
  })();
  