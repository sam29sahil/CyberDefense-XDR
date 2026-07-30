/* ==========================================================================
   threat-dashboard.js — page module for app/threat-dashboard.html
   Depends on: IOCS_DATA, CAMPAIGNS_DATA, FEEDS_DATA, ACTORS_DATA,
   XDR_CHART_DEFAULTS, XDR_PALETTE, xdrGradient, XDRUtils
   ========================================================================== */

   (function () {
    const iocs = IOCS_DATA;
    const campaigns = CAMPAIGNS_DATA;
    const feeds = FEEDS_DATA;
    const actors = ACTORS_DATA;
  
    const activeIocs = iocs.filter((i) => i.status === "active");
    const criticalIocs = iocs.filter((i) => i.threatLevel === "critical");
    const now = new Date("2026-07-24T09:58:00Z");
    const addedToday = iocs.filter((i) => i.firstSeen.startsWith(now.toISOString().slice(0, 10)));
    const activeCampaigns = campaigns.filter((c) => c.status === "active");
  
    const kpis = [
      { label: "Active IOCs", value: activeIocs.length, accent: "accent-primary", icon: "bi-radar", sub: `${iocs.length} total tracked` },
      { label: "Critical IOCs", value: criticalIocs.length, accent: "accent-danger", icon: "bi-exclamation-octagon", sub: "highest threat level" },
      { label: "Active Campaigns", value: activeCampaigns.length, accent: "accent-warning", icon: "bi-flag", sub: `${campaigns.length} tracked total` },
      { label: "Threat Actors Tracked", value: actors.length, accent: "accent-info", icon: "bi-person-badge", sub: "attributed groups" },
      { label: "Feed Sources", value: feeds.filter((f) => f.status === "active").length, accent: "accent-success", icon: "bi-broadcast", sub: `${feeds.length} configured` },
      { label: "IOCs Added Today", value: addedToday.length, accent: "accent-primary", icon: "bi-plus-circle", sub: "in the last 24 hours" },
    ];
    document.getElementById("kpiRow").innerHTML = kpis.map((k) => `
      <div class="col-lg-2 col-md-4 col-6">
        <div class="card stat-card ${k.accent} h-100">
          <div class="eyebrow"><i class="bi ${k.icon}"></i> ${k.label}</div>
          <div class="stat-value">${k.value}</div>
          <span class="stat-delta text-muted">${k.sub}</span>
        </div>
      </div>`).join("");
  
    // ---------- IOC trend (14 days) ----------
    const days = [];
    for (let i = 13; i >= 0; i--) days.push(new Date(now.getTime() - i * 86400000).toISOString().slice(0, 10));
    const counts = days.map((day) => iocs.filter((i) => i.firstSeen.startsWith(day)).length);
  
    const ctx = document.getElementById("iocTrendChart").getContext("2d");
    new Chart(ctx, {
      type: "line",
      data: {
        labels: days.map((d) => d.slice(5)),
        datasets: [{ label: "New IOCs", data: counts, borderColor: XDR_PALETTE.activity[1], backgroundColor: xdrGradient(ctx, XDR_PALETTE.activity[1]), fill: true, tension: 0.35, pointRadius: 0, borderWidth: 2 }],
      },
      options: XDR_CHART_DEFAULTS,
    });
  
    // ---------- IOC type distribution ----------
    const types = ["ip", "domain", "hash", "url"];
    const typeCounts = types.map((t) => iocs.filter((i) => i.type === t).length);
    new Chart(document.getElementById("iocTypeChart"), {
      type: "doughnut",
      data: {
        labels: types.map((t) => t.toUpperCase()),
        datasets: [{ data: typeCounts, backgroundColor: [XDR_PALETTE.activity[0], XDR_PALETTE.activity[1], XDR_PALETTE.activity[2], XDR_PALETTE.activity[3]], borderWidth: 0 }],
      },
      options: {
        responsive: true, maintainAspectRatio: false, cutout: "68%",
        plugins: { legend: { display: true, position: "bottom", labels: { usePointStyle: true, boxWidth: 8, boxHeight: 8 } } },
      },
    });
  
    // ---------- Latest indicators ----------
    const latest = iocs.slice().sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen)).slice(0, 8);
    document.getElementById("latestIocsBody").innerHTML = latest.map((i) => `
      <tr>
        <td><a href="ioc-details.html?id=${i.id}" class="ioc-value" style="text-decoration:none;">${XDRUtils.escapeHtml(i.value)}</a></td>
        <td><span class="ioc-type-chip">${i.type}</span></td>
        <td>${XDRUtils.severityBadge(i.threatLevel)}</td>
        <td class="text-sm text-muted">${XDRUtils.formatTime(i.lastSeen)}</td>
      </tr>`).join("");
  
    // ---------- Most active actors ----------
    const topActors = actors.slice().sort((a, b) => b.campaignCount - a.campaignCount).slice(0, 5);
    document.getElementById("topActorsList").innerHTML = topActors.map((a) => `
      <div class="mini-status-row">
        <span class="d-flex align-items-center gap-2">
          <span class="actor-avatar" style="width:28px;height:28px;font-size:12px;">${a.name.slice(0, 2).toUpperCase()}</span>
          <span style="font-weight:600;">${a.name}</span>
        </span>
        <span class="badge badge-neutral">${a.campaignCount} campaigns</span>
      </div>`).join("");
  
    // ---------- Active campaigns grid ----------
    document.getElementById("activeCampaignsGrid").innerHTML = activeCampaigns.slice(0, 4).map((c) => `
      <div class="col-lg-3 col-md-6">
        <div class="campaign-card">
          <div><span class="campaign-status-dot ${c.status}"></span><strong>${c.name}</strong></div>
          <p class="text-muted text-sm mb-0">Attributed to ${c.actorName}</p>
          <span class="text-xs text-muted">${c.iocCount} IOCs linked</span>
        </div>
      </div>`).join("");
  })();
  