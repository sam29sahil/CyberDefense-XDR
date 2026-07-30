/* ==========================================================================
   technical-report.js — page module for app/technical-report.html
   Depends on: DETECTION_RULES_DATA, LOGS_DATA, VULNERABILITIES_DATA
   ========================================================================== */

   (function () {
    const now = new Date("2026-07-24T09:58:00Z");
    const periodStart = new Date(now.getTime() - 30 * 86400000);
    document.getElementById("repPeriod").textContent = `${periodStart.toISOString().slice(0, 10)} — ${now.toISOString().slice(0, 10)}`;
    document.getElementById("repGenerated").textContent = XDRUtils.formatTime(now.toISOString());
  
    // ---------- Detection engine summary by category ----------
    const categories = [...new Set(DETECTION_RULES_DATA.map((r) => r.category))];
    document.getElementById("techDetectionTable").innerHTML = categories.map((c) => {
      const rules = DETECTION_RULES_DATA.filter((r) => r.category === c);
      const active = rules.filter((r) => r.status === "active").length;
      const triggers = rules.reduce((s, r) => s + r.triggers30d, 0);
      const avgFp = rules.length ? Math.round(rules.reduce((s, r) => s + r.falsePositiveRate, 0) / rules.length * 100) : 0;
      return `<tr><td>${c}</td><td>${active}</td><td>${triggers}</td><td>${avgFp}%</td></tr>`;
    }).join("");
  
    // ---------- Top vulnerabilities by CVSS ----------
    const topVulns = VULNERABILITIES_DATA.slice().sort((a, b) => b.cvssScore - a.cvssScore).slice(0, 10);
    document.getElementById("techVulnTable").innerHTML = topVulns.map((v) => `
      <tr><td>${v.cve} — ${v.title}</td><td>${v.severity}</td><td>${v.cvssScore}</td><td>${v.affectedAssets.length}</td><td>${v.status}</td></tr>`).join("");
  
    // ---------- SIEM ingest sample ----------
    const sourceCounts = {};
    LOGS_DATA.forEach((r) => { sourceCounts[r.source] = sourceCounts[r.source] || { count: 0, category: r.category }; sourceCounts[r.source].count++; });
    document.getElementById("techSiemTable").innerHTML = Object.entries(sourceCounts)
      .sort((a, b) => b[1].count - a[1].count)
      .map(([name, v]) => `<tr><td>${name}</td><td>${v.count}</td><td>${v.category}</td></tr>`).join("");
  
    document.getElementById("exportBtn").addEventListener("click", () => {
      if (window.showToast) window.showToast({ type: "success", title: "Export queued", msg: "Technical Report PDF will be ready shortly." });
    });
  })();
  