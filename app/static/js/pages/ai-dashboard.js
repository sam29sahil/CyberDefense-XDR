/* ==========================================================================
   ai-dashboard.js — page module for app/ai-dashboard.html
   Depends on: AI_INSIGHTS_DATA, RECOMMENDATIONS_DATA, RISK_TREND_14D,
   SUGGESTED_QUESTIONS, AI_CONVERSATIONS_DATA (data/ai-data.js),
   XDR_CHART_DEFAULTS, XDR_PALETTE, xdrGradient
   ========================================================================== */

   (function () {
    const INSIGHT_ICON = { warning: "bi-exclamation-triangle", info: "bi-info-circle", success: "bi-check-circle" };
  
    const kpis = [
      { label: "Insights Generated (7d)", value: AI_INSIGHTS_DATA.length, accent: "accent-primary", icon: "bi-lightbulb" },
      { label: "Open Recommendations", value: RECOMMENDATIONS_DATA.filter((r) => r.status === "new" || r.status === "in_progress").length, accent: "accent-warning", icon: "bi-clipboard-check" },
      { label: "Avg Confidence", value: `${Math.round(AI_INSIGHTS_DATA.reduce((s, i) => s + i.confidence, 0) / AI_INSIGHTS_DATA.length)}%`, accent: "accent-success", icon: "bi-graph-up" },
      { label: "Conversations This Week", value: AI_CONVERSATIONS_DATA.length, accent: "accent-info", icon: "bi-chat-dots" },
    ];
    document.getElementById("kpiRow").innerHTML = kpis.map((k) => `
      <div class="col-lg-3 col-md-6 col-6">
        <div class="card stat-card ${k.accent} h-100">
          <div class="eyebrow"><i class="bi ${k.icon}"></i> ${k.label}</div>
          <div class="stat-value">${k.value}</div>
        </div>
      </div>`).join("");
  
    // ---------- Insights feed ----------
    document.getElementById("insightsList").innerHTML = AI_INSIGHTS_DATA.map((i) => `
      <div class="insight-card">
        <span class="insight-icon ${i.type}"><i class="bi ${INSIGHT_ICON[i.type]}"></i></span>
        <div class="flex-grow-1">
          <div class="d-flex justify-content-between gap-2">
            <strong>${i.title}</strong>
            <span class="insight-confidence">${i.confidence}% confidence</span>
          </div>
          <p class="text-muted text-sm mb-1">${i.text}</p>
          <span class="text-xs text-muted">${XDRUtils.formatTime(i.ts)}</span>
        </div>
      </div>`).join("");
  
    // ---------- Risk trend chart ----------
    const days = [];
    const now = new Date("2026-07-24T09:58:00Z");
    for (let i = 13; i >= 0; i--) days.push(new Date(now.getTime() - i * 86400000).toISOString().slice(5, 10));
    const ctx = document.getElementById("riskTrendChart").getContext("2d");
    new Chart(ctx, {
      type: "line",
      data: { labels: days, datasets: [{ label: "Composite risk", data: RISK_TREND_14D, borderColor: XDR_PALETTE.activity[2], backgroundColor: xdrGradient(ctx, XDR_PALETTE.activity[2]), fill: true, tension: 0.35, pointRadius: 0, borderWidth: 2 }] },
      options: XDR_CHART_DEFAULTS,
    });
  
    // ---------- Top recommendations preview ----------
    const topRecs = RECOMMENDATIONS_DATA.filter((r) => r.status === "new").slice(0, 3);
    document.getElementById("recPreviewList").innerHTML = topRecs.map((r) => `
      <div class="d-flex gap-2 mb-3">
        <span class="rec-priority-rail ${r.priority}"></span>
        <div>
          <a href="recommendations.html" style="color:var(--text);font-weight:600;text-decoration:none;">${r.title}</a>
          <div class="text-xs text-muted">${r.category}</div>
        </div>
      </div>`).join("");
  
    // ---------- Suggested questions ----------
    document.getElementById("suggestedList").innerHTML = SUGGESTED_QUESTIONS.map((q) => `<span class="chat-suggestion-chip">${q}</span>`).join("");
    document.querySelectorAll(".chat-suggestion-chip").forEach((chip) => {
      chip.addEventListener("click", () => { window.location.href = `chat.html?q=${encodeURIComponent(chip.textContent)}`; });
    });
  })();
  