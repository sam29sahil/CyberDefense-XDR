/* ==========================================================================
   dashboard.js — page module for app/dashboard.html
   Renders the recent alerts table and all Chart.js visualizations.
   Depends on: app.js, core/charts.js (window.XDR_PALETTE, XDR_CHART_DEFAULTS)
   ========================================================================== */

   document.addEventListener("DOMContentLoaded", function () {
    // ---- Recent alerts table ----
    const alerts = [
      { sev: "critical", title: "Active exploitation attempt — CVE-2026-1120", asset: "WEB-PROD-03", time: "2 min ago" },
      { sev: "critical", title: "Data exfiltration pattern detected", asset: "DB-PROD-01", time: "14 min ago" },
      { sev: "high", title: "Suspicious PowerShell execution (encoded)", asset: "FIN-WK-014", time: "38 min ago" },
      { sev: "medium", title: "Brute-force attempt — 40 failed logins", asset: "VPN-GATE-02", time: "1h ago" },
      { sev: "low", title: "New admin account created", asset: "AD-DC-01", time: "3h ago" },
    ];
  
    const tbody = document.getElementById("recentAlertsBody");
    if (tbody) {
      tbody.innerHTML = alerts.map(a => `
        <tr>
          <td>${XDRUtils.severityBadge(a.sev)}</td>
          <td>${XDRUtils.escapeHtml(a.title)}</td>
          <td><span class="cell-mono">${XDRUtils.escapeHtml(a.asset)}</span></td>
          <td class="text-muted text-sm">${XDRUtils.escapeHtml(a.time)}</td>
        </tr>`).join("");
    }
  
    if (typeof Chart === "undefined") return;
  
    // ---- Risk gauge (doughnut used as gauge) ----
    const riskGaugeEl = document.getElementById("riskGauge");
    if (riskGaugeEl) {
      new Chart(riskGaugeEl, {
        type: "doughnut",
        data: {
          datasets: [{
            data: [42, 58],
            backgroundColor: [XDRUtils.cssVar("--warning"), XDRUtils.cssVar("--border-subtle")],
            borderWidth: 0,
          }],
        },
        options: { cutout: "78%", plugins: { legend: { display: false }, tooltip: { enabled: false } } },
      });
    }
  
    // ---- Attack timeline (stacked bar, severity palette) ----
    const timelineEl = document.getElementById("attackTimelineChart");
    if (timelineEl) {
      const hours = Array.from({ length: 12 }, (_, i) => `${(i * 2).toString().padStart(2, "0")}:00`);
      new Chart(timelineEl, {
        type: "bar",
        data: {
          labels: hours,
          datasets: [
            { label: "Critical", data: [0, 1, 0, 2, 1, 3, 2, 1, 0, 1, 2, 1], backgroundColor: XDR_PALETTE.severity.critical, stack: "s" },
            { label: "High", data: [1, 2, 1, 3, 2, 4, 3, 2, 1, 2, 3, 2], backgroundColor: XDR_PALETTE.severity.high, stack: "s" },
            { label: "Medium", data: [2, 3, 3, 4, 3, 5, 4, 3, 2, 3, 4, 3], backgroundColor: XDR_PALETTE.severity.medium, stack: "s" },
          ],
        },
        options: {
          ...XDR_CHART_DEFAULTS,
          scales: {
            x: { ...XDR_CHART_DEFAULTS.scales.x, stacked: true },
            y: { ...XDR_CHART_DEFAULTS.scales.y, stacked: true },
          },
        },
      });
    }
  
    // ---- Alerts by category (donut, activity palette) ----
    const categoryEl = document.getElementById("alertCategoryChart");
    if (categoryEl) {
      new Chart(categoryEl, {
        type: "doughnut",
        data: {
          labels: ["Malware", "Intrusion", "Policy Violation", "Phishing", "Anomaly"],
          datasets: [{
            data: [28, 22, 18, 17, 15],
            backgroundColor: [XDR_PALETTE.activity[0], XDR_PALETTE.activity[1], XDR_PALETTE.activity[2], XDR_PALETTE.activity[3], "#475569"],
            borderWidth: 0,
          }],
        },
        options: { plugins: { legend: { display: true, position: "right" } }, cutout: "62%" },
      });
    }
  
    // ---- Top assets by risk (horizontal bar) ----
    const topAssetsEl = document.getElementById("topAssetsChart");
    if (topAssetsEl) {
      new Chart(topAssetsEl, {
        type: "bar",
        data: {
          labels: ["DB-PROD-01", "WEB-PROD-03", "AD-DC-01", "FIN-WK-014", "VPN-GATE-02"],
          datasets: [{ label: "Risk score", data: [92, 86, 74, 61, 58], backgroundColor: XDR_PALETTE.activity[0], borderRadius: 4 }],
        },
        options: {
          ...XDR_CHART_DEFAULTS,
          indexAxis: "y",
          scales: {
            x: { ...XDR_CHART_DEFAULTS.scales.y },
            y: { grid: { display: false }, ticks: { color: XDRUtils.cssVar("--text-muted") } },
          },
        },
      });
    }
  });
  