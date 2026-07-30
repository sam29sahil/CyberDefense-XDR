/* ==========================================================================
   incident-dashboard.js — page module for app/incident-dashboard.html
   Depends on: INCIDENTS_DATA, TIMELINE_DATA, XDR_CHART_DEFAULTS,
   XDR_PALETTE, xdrGradient (core/charts.js), XDRUtils
   ========================================================================== */

   (function () {
    const incidents = INCIDENTS_DATA;
    const STATUS_LABEL = { open: "Open", in_progress: "In Progress", resolved: "Resolved", closed: "Closed" };
  
    const openIncidents = incidents.filter((i) => i.status === "open" || i.status === "in_progress");
    const resolvedIncidents = incidents.filter((i) => i.status === "resolved" || i.status === "closed");
    const criticalIncidents = incidents.filter((i) => i.severity === "critical" && i.status !== "closed");
  
    function hoursBetween(a, b) { return (new Date(b) - new Date(a)) / 3600000; }
    const avgResponseHrs = resolvedIncidents.length
      ? Math.round(resolvedIncidents.reduce((s, i) => s + hoursBetween(i.createdAt, i.updatedAt), 0) / resolvedIncidents.length * 10) / 10
      : 0;
  
    const kpis = [
      { label: "Open Incidents", value: openIncidents.length, accent: "accent-primary", icon: "bi-folder2-open", sub: `${incidents.length} total tracked` },
      { label: "Resolved", value: resolvedIncidents.length, accent: "accent-success", icon: "bi-check-circle", sub: "resolved or closed" },
      { label: "Critical", value: criticalIncidents.length, accent: "accent-danger", icon: "bi-exclamation-octagon", sub: "unresolved" },
      { label: "Avg Response", value: `${avgResponseHrs}h`, accent: "accent-warning", icon: "bi-stopwatch", sub: "creation to last update" },
    ];
    document.getElementById("kpiRow").innerHTML = kpis.map((k) => `
      <div class="col-lg-3 col-md-6 col-6">
        <div class="card stat-card ${k.accent} h-100">
          <div class="eyebrow"><i class="bi ${k.icon}"></i> ${k.label}</div>
          <div class="stat-value">${k.value}</div>
          <span class="stat-delta text-muted">${k.sub}</span>
        </div>
      </div>`).join("");
  
    // ---------- Incident Trend — last 14 days ----------
    const days = [];
    const now = new Date("2026-07-24T09:58:00Z");
    for (let i = 13; i >= 0; i--) days.push(new Date(now.getTime() - i * 86400000).toISOString().slice(0, 10));
    const counts = days.map((day) => incidents.filter((inc) => inc.createdAt.startsWith(day)).length);
  
    const ctx = document.getElementById("incidentTrendChart").getContext("2d");
    new Chart(ctx, {
      type: "line",
      data: {
        labels: days.map((d) => d.slice(5)),
        datasets: [{
          label: "Incidents opened", data: counts,
          borderColor: XDR_PALETTE.activity[0], backgroundColor: xdrGradient(ctx, XDR_PALETTE.activity[0]),
          fill: true, tension: 0.35, pointRadius: 0, borderWidth: 2,
        }],
      },
      options: XDR_CHART_DEFAULTS,
    });
  
    // ---------- Priority distribution ----------
    const prioOrder = ["P1", "P2", "P3", "P4"];
    const sevByPrio = { P1: "critical", P2: "high", P3: "medium", P4: "low" };
    const prioCounts = prioOrder.map((p) => incidents.filter((i) => i.priority === p).length);
    new Chart(document.getElementById("priorityChart"), {
      type: "doughnut",
      data: {
        labels: prioOrder,
        datasets: [{ data: prioCounts, backgroundColor: prioOrder.map((p) => XDR_PALETTE.severity[sevByPrio[p]]), borderWidth: 0 }],
      },
      options: {
        responsive: true, maintainAspectRatio: false, cutout: "68%",
        plugins: { legend: { display: true, position: "bottom", labels: { usePointStyle: true, boxWidth: 8, boxHeight: 8 } } },
      },
    });
  
    // ---------- Resolution time by category ----------
    const categories = [...new Set(incidents.map((i) => i.category))];
    const resTimeByCat = categories.map((c) => {
      const items = incidents.filter((i) => i.category === c && (i.status === "resolved" || i.status === "closed"));
      if (!items.length) return 0;
      return Math.round(items.reduce((s, i) => s + hoursBetween(i.createdAt, i.updatedAt), 0) / items.length * 10) / 10;
    });
    new Chart(document.getElementById("resolutionChart"), {
      type: "bar",
      data: { labels: categories, datasets: [{ data: resTimeByCat, backgroundColor: XDR_PALETTE.activity[2], borderRadius: 3 }] },
      options: { ...XDR_CHART_DEFAULTS, indexAxis: "y", plugins: { legend: { display: false } } },
    });
  
    // ---------- Recent incidents table ----------
    const recent = incidents.slice().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 8);
    document.getElementById("recentIncidentsBody").innerHTML = recent.map((i) => `
      <tr>
        <td><a href="incident-details.html?id=${i.id}" style="color:var(--text);font-weight:600;text-decoration:none;">${XDRUtils.escapeHtml(i.title)}</a>
          <div class="text-xs text-muted">${i.category}</div></td>
        <td>${XDRUtils.severityBadge(i.severity)}</td>
        <td><span class="status-pill st-${i.status}"><span class="dot"></span>${STATUS_LABEL[i.status]}</span></td>
        <td>${i.assignedAnalyst}</td>
      </tr>`).join("");
  })();
  