/* ==========================================================================
   detection-dashboard.js — page module for app/detection-dashboard.html
   Depends on: DETECTION_RULES_DATA, DETECTION_HISTORY_DATA (data/*),
   XDR_CHART_DEFAULTS, XDR_PALETTE, xdrGradient (core/charts.js), XDRUtils
   ========================================================================== */

   (function () {
    const rules = DETECTION_RULES_DATA;
    const history = DETECTION_HISTORY_DATA;
  
    const activeRules = rules.filter((r) => r.status === "active");
    const disabledRules = rules.filter((r) => r.status === "disabled");
    const testingRules = rules.filter((r) => r.status === "testing");
    const criticalRules = rules.filter((r) => r.severity === "critical" && r.status !== "disabled");
    const recentDetections = history.filter((h) => (Date.now() - new Date(h.ts).getTime()) < 24 * 3600000);
    const falsePositives = history.filter((h) => h.status === "false_positive");
    const topRule = rules.slice().sort((a, b) => b.triggers30d - a.triggers30d)[0];
  
    // ---------- KPI cards ----------
    const kpis = [
      { label: "Active Rules", value: activeRules.length, accent: "accent-success", icon: "bi-check-circle", sub: `of ${rules.length} total` },
      { label: "Disabled Rules", value: disabledRules.length, accent: "", icon: "bi-slash-circle", sub: `${testingRules.length} in testing` },
      { label: "Recent Detections", value: recentDetections.length, accent: "accent-primary", icon: "bi-radar", sub: "last 24 hours" },
      { label: "False Positives", value: falsePositives.length, accent: "accent-warning", icon: "bi-flag", sub: `${history.length ? Math.round(falsePositives.length / history.length * 100) : 0}% of all events` },
      { label: "Critical Rules", value: criticalRules.length, accent: "accent-danger", icon: "bi-skull", sub: "active or testing" },
      { label: "Top Triggered Rule", value: topRule ? topRule.triggers30d : 0, accent: "accent-info", icon: "bi-graph-up-arrow", sub: topRule ? topRule.name : "—", isText: false },
    ];
    document.getElementById("kpiRow").innerHTML = kpis.map((k) => `
      <div class="col-lg-2 col-md-4 col-6">
        <div class="card stat-card ${k.accent} h-100">
          <div class="eyebrow"><i class="bi ${k.icon}"></i> ${k.label}</div>
          <div class="stat-value">${k.value}</div>
          <span class="stat-delta text-muted text-truncate d-block" title="${XDRUtils.escapeHtml(k.sub)}">${XDRUtils.escapeHtml(k.sub)}</span>
        </div>
      </div>`).join("");
  
    // ---------- Detection Trend — last 14 days, critical/high ----------
    const days = [];
    const now = new Date("2026-07-24T09:58:00Z");
    for (let i = 13; i >= 0; i--) {
      const d = new Date(now.getTime() - i * 86400000);
      days.push(d.toISOString().slice(0, 10));
    }
    const critByDay = days.map((day) => history.filter((h) => h.ts.startsWith(day) && h.severity === "critical").length);
    const highByDay = days.map((day) => history.filter((h) => h.ts.startsWith(day) && h.severity === "high").length);
  
    const trendCtx = document.getElementById("detectionTrendChart").getContext("2d");
    new Chart(trendCtx, {
      type: "line",
      data: {
        labels: days.map((d) => d.slice(5)),
        datasets: [
          { label: "Critical", data: critByDay, borderColor: XDR_PALETTE.severity.critical, backgroundColor: xdrGradient(trendCtx, XDR_PALETTE.severity.critical), fill: true, tension: 0.35, pointRadius: 0, borderWidth: 2 },
          { label: "High", data: highByDay, borderColor: XDR_PALETTE.severity.high, backgroundColor: xdrGradient(trendCtx, XDR_PALETTE.severity.high), fill: true, tension: 0.35, pointRadius: 0, borderWidth: 2 },
        ],
      },
      options: XDR_CHART_DEFAULTS,
    });
  
    // ---------- Rule Severity Distribution ----------
    const sevOrder = ["critical", "high", "medium", "low"];
    const sevCounts = sevOrder.map((s) => rules.filter((r) => r.severity === s).length);
    new Chart(document.getElementById("ruleSeverityChart"), {
      type: "doughnut",
      data: {
        labels: sevOrder.map((s) => s[0].toUpperCase() + s.slice(1)),
        datasets: [{ data: sevCounts, backgroundColor: sevOrder.map((s) => XDR_PALETTE.severity[s]), borderWidth: 0 }],
      },
      options: {
        responsive: true, maintainAspectRatio: false, cutout: "68%",
        plugins: { legend: { display: true, position: "bottom", labels: { usePointStyle: true, boxWidth: 8, boxHeight: 8 } } },
      },
    });
  
    // ---------- MITRE / Category Coverage Radar ----------
    const categories = [...new Set(rules.map((r) => r.category))];
    const coverage = categories.map((c) => rules.filter((r) => r.category === c && r.status !== "disabled").length);
    new Chart(document.getElementById("mitreCoverageChart"), {
      type: "radar",
      data: {
        labels: categories,
        datasets: [{
          label: "Active rule coverage",
          data: coverage,
          backgroundColor: "rgba(139,92,246,.18)",
          borderColor: XDR_PALETTE.activity[2],
          pointBackgroundColor: XDR_PALETTE.activity[2],
          borderWidth: 2,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          r: {
            angleLines: { color: "var(--border-subtle)" },
            grid: { color: "rgba(148,163,184,.12)" },
            pointLabels: { color: "var(--text-muted)", font: { size: 10 } },
            ticks: { display: false, beginAtZero: true },
          },
        },
      },
    });
  
    // ---------- Top triggered rules list ----------
    const topRules = rules.slice().sort((a, b) => b.triggers30d - a.triggers30d).slice(0, 6);
    document.getElementById("topRulesList").innerHTML = topRules.map((r, i) => `
      <div class="rule-rank-row">
        <span class="rule-rank-badge">${i + 1}</span>
        <a href="rule-details.html?id=${r.id}" class="rr-name">${XDRUtils.escapeHtml(r.name)}</a>
        ${XDRUtils.severityBadge(r.severity)}
        <span class="rr-count">${r.triggers30d}</span>
      </div>`).join("");
  
    // ---------- Rule categories grid ----------
    document.getElementById("categoryGrid").innerHTML = categories.map((c) => {
      const catRules = rules.filter((r) => r.category === c);
      const activeCount = catRules.filter((r) => r.status === "active").length;
      return `
      <div class="col-lg-3 col-md-4 col-6">
        <a href="detection-rules.html" class="card stat-card d-block h-100" style="text-decoration:none;">
          <div class="eyebrow">${c}</div>
          <div class="stat-value fs-inherit-lg">${catRules.length} <span class="text-muted text-sm">rules</span></div>
          <span class="stat-delta text-success">${activeCount} active</span>
        </a>
      </div>`;
    }).join("");
  })();
  