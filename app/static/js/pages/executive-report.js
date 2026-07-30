/* ==========================================================================
   executive-report.js — page module for app/executive-report.html
   Synthesizes an executive-level view from static, hand-authored figures
   consistent with the rest of the platform's dummy datasets.
   ========================================================================== */

   (function () {
    const now = new Date("2026-07-24T09:58:00Z");
    const periodStart = new Date(now.getTime() - 30 * 86400000);
    document.getElementById("repPeriod").textContent = `${periodStart.toISOString().slice(0, 10)} — ${now.toISOString().slice(0, 10)}`;
    document.getElementById("repGenerated").textContent = XDRUtils.formatTime(now.toISOString());
  
    const kpis = [
      { num: "1,284", lbl: "Alerts Triaged" },
      { num: "20", lbl: "Incidents Opened" },
      { num: "94%", lbl: "SLA Compliance" },
      { num: "3.2h", lbl: "Avg Response Time" },
      { num: "16", lbl: "Critical Vulns Open" },
    ];
    document.getElementById("execKpiStrip").innerHTML = kpis.map((k) => `
      <div class="kpi-block"><div class="num">${k.num}</div><div class="lbl">${k.lbl}</div></div>`).join("");
  
    const findings = [
      "Detection coverage expanded to 35 active rules mapped across 12 MITRE ATT&CK categories.",
      "Ransomware and phishing remained the most frequently observed incident categories this period.",
      "Median incident resolution time improved to 3.2 hours, down from 4.8 hours last period.",
      "16 critical vulnerabilities remain open across finance and identity infrastructure, prioritized for patching.",
      "No confirmed data exfiltration events were identified during the reporting period.",
    ];
    document.getElementById("execFindingsList").innerHTML = findings.map((f) => `<li>${f}</li>`).join("");
  
    const incidentSummary = [
      ["Ransomware", 1, 1, 18.4],
      ["Data Breach", 0, 2, 12.1],
      ["Phishing", 1, 1, 4.6],
      ["Account Compromise", 1, 1, 6.2],
      ["Cloud Misconfiguration", 0, 2, 9.8],
    ];
    document.getElementById("execIncidentTable").innerHTML = incidentSummary.map((row) => `
      <tr><td>${row[0]}</td><td>${row[1]}</td><td>${row[2]}</td><td>${row[3]}</td></tr>`).join("");
  
    const recs = [
      "Prioritize patching of critical vulnerabilities on finance and identity infrastructure within 14 days.",
      "Continue phishing awareness training given recurring initial-access attempts via email.",
      "Extend detection coverage for cloud misconfiguration categories given recent findings.",
      "Review analyst staffing during peak alert-volume hours to sustain current SLA performance.",
    ];
    document.getElementById("execRecsList").innerHTML = recs.map((r) => `<li>${r}</li>`).join("");
  
    document.getElementById("exportBtn").addEventListener("click", () => {
      if (window.showToast) window.showToast({ type: "success", title: "Export queued", msg: "Executive Summary PDF will be ready shortly." });
    });
  })();
  