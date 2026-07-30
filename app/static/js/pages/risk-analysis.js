/* ==========================================================================
   risk-analysis.js — page module for app/risk-analysis.html
   Depends on: RISK_FACTORS_DATA, RISK_TREND_14D (data/ai-data.js),
   XDR_CHART_DEFAULTS, XDR_PALETTE, xdrGradient
   ========================================================================== */

   (function () {
    const compositeScore = Math.round(RISK_FACTORS_DATA.reduce((s, f) => s + f.score, 0) / RISK_FACTORS_DATA.length);
    const level = compositeScore >= 70 ? "High" : compositeScore >= 45 ? "Elevated" : "Moderate";
    const levelColor = compositeScore >= 70 ? XDR_PALETTE.severity.critical : compositeScore >= 45 ? XDR_PALETTE.severity.high : XDR_PALETTE.severity.medium;
  
    document.getElementById("gaugeScore").textContent = compositeScore;
    document.getElementById("gaugeLabel").textContent = `${level} Risk`;
  
    new Chart(document.getElementById("riskGaugeChart"), {
      type: "doughnut",
      data: { datasets: [{ data: [compositeScore, 100 - compositeScore], backgroundColor: [levelColor, "rgba(148,163,184,.14)"], borderWidth: 0 }] },
      options: { responsive: true, maintainAspectRatio: false, cutout: "78%", circumference: 270, rotation: 225, plugins: { legend: { display: false }, tooltip: { enabled: false } } },
    });
  
    // ---------- Trend chart ----------
    const days = [];
    const now = new Date("2026-07-24T09:58:00Z");
    for (let i = 13; i >= 0; i--) days.push(new Date(now.getTime() - i * 86400000).toISOString().slice(5, 10));
    const ctx = document.getElementById("riskTrendChart").getContext("2d");
    new Chart(ctx, {
      type: "line",
      data: { labels: days, datasets: [{ label: "Composite risk score", data: RISK_TREND_14D, borderColor: levelColor, backgroundColor: xdrGradient(ctx, levelColor), fill: true, tension: 0.35, pointRadius: 0, borderWidth: 2 }] },
      options: XDR_CHART_DEFAULTS,
    });
  
    // ---------- Risk factor breakdown ----------
    const TREND_ICON = { up: "bi-arrow-up-right", down: "bi-arrow-down-right", flat: "bi-arrow-right" };
    document.getElementById("riskFactorsList").innerHTML = RISK_FACTORS_DATA.map((f) => {
      const color = f.score >= 70 ? XDR_PALETTE.severity.critical : f.score >= 45 ? XDR_PALETTE.severity.high : XDR_PALETTE.severity.low;
      return `
      <div class="risk-factor-row">
        <div class="d-flex justify-content-between text-sm mb-1">
          <span>${f.name} <i class="bi ${TREND_ICON[f.trend]} risk-trend-icon ${f.trend}"></i></span>
          <span class="text-muted">${f.score}/100</span>
        </div>
        <div class="risk-factor-bar"><div class="risk-factor-fill" style="width:${f.score}%;background:${color};"></div></div>
        <p class="text-muted text-xs mt-1 mb-0">${f.description}</p>
      </div>`;
    }).join("");
  
    // ---------- Narrative ----------
    const topFactor = RISK_FACTORS_DATA.slice().sort((a, b) => b.score - a.score)[0];
    const improving = RISK_FACTORS_DATA.filter((f) => f.trend === "down").map((f) => f.name);
    document.getElementById("riskNarrative").textContent =
      `Composite risk currently sits at ${compositeScore}/100 (${level.toLowerCase()}), primarily driven by ${topFactor.name.toLowerCase()} at ${topFactor.score}/100. ` +
      (improving.length ? `Improving trends were observed in ${improving.join(" and ")}, suggesting recent remediation efforts are having a measurable effect. ` : "") +
      `Continued focus on the highest-scoring factors is recommended to reduce overall exposure over the next reporting period.`;
  })();
  