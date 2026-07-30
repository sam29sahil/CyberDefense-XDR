/* ==========================================================================
   scan-details.js — page module for app/scan-details.html
   Depends on: SCANS_DATA, VULNERABILITIES_DATA, XDR_PALETTE
   ========================================================================== */

   (function () {
    const STATUS_LABEL = { completed: "Completed", running: "Running", queued: "Queued" };
    const params = new URLSearchParams(window.location.search);
    const id = params.get("id");
    const scan = SCANS_DATA.find((s) => s.id === id) || SCANS_DATA[0];
    const findings = VULNERABILITIES_DATA.filter((v) => scan.findingIds.includes(v.id))
      .map((v) => ({ ...v, host: scan.targets[Math.floor(Math.random() * scan.targets.length)] }));
  
    document.getElementById("breadcrumbScanId").textContent = scan.name;
    document.getElementById("scanName").textContent = scan.name;
    document.getElementById("scanStatusPill").innerHTML = `<span class="status-pill st-${scan.status}"><span class="dot"></span>${STATUS_LABEL[scan.status]}</span>`;
    document.getElementById("scanMeta").textContent = `${scan.type} · started ${XDRUtils.formatTime(scan.startedAt)}${scan.durationMin ? ` · ${scan.durationMin} min duration` : ""} · initiated by ${scan.initiatedBy}`;
  
    const gaugeColor = scan.riskScore >= 70 ? "var(--danger)" : scan.riskScore >= 40 ? "var(--warning)" : "var(--success)";
    const gauge = document.getElementById("riskGauge");
    gauge.style.setProperty("--pct", scan.riskScore);
    gauge.style.setProperty("--gauge-color", gaugeColor);
    document.getElementById("riskGaugeValue").textContent = scan.riskScore;
  
    // ---------- Severity chart ----------
    const sevOrder = ["critical", "high", "medium", "low"];
    const sevCounts = sevOrder.map((s) => scan.findingsSummary[s] || 0);
    new Chart(document.getElementById("scanSeverityChart"), {
      type: "doughnut",
      data: { labels: sevOrder.map((s) => s[0].toUpperCase() + s.slice(1)), datasets: [{ data: sevCounts, backgroundColor: sevOrder.map((s) => XDR_PALETTE.severity[s]), borderWidth: 0 }] },
      options: { responsive: true, maintainAspectRatio: false, cutout: "68%", plugins: { legend: { display: true, position: "bottom", labels: { usePointStyle: true, boxWidth: 8, boxHeight: 8 } } } },
    });
  
    // ---------- Targets list ----------
    document.getElementById("scanTargetsList").innerHTML = scan.targets.map((t) => `
      <div class="info-row"><span><i class="bi bi-hdd-network text-muted"></i> ${t}</span><span class="text-xs text-muted">scanned</span></div>`).join("");
  
    // ---------- Findings table ----------
    function renderFindings(list) {
      document.getElementById("findingsBody").innerHTML = list.length
        ? list.map((v) => `
            <tr>
              <td><a href="vulnerability-details.html?id=${v.id}" style="color:var(--text);font-weight:600;text-decoration:none;">${v.title}</a>
                <div class="text-xs text-muted">${v.cve}</div></td>
              <td style="font-weight:600;">${v.host}</td>
              <td><span class="cvss-badge cvss-${v.severity}">${v.cvssScore}</span></td>
              <td class="text-sm cell-mono">${v.port}/${v.service}</td>
              <td><span class="status-pill st-${v.status}"><span class="dot"></span>${v.status.replace("_", " ")}</span></td>
              <td><a href="vulnerability-details.html?id=${v.id}" class="btn btn-icon btn-ghost btn-sm"><i class="bi bi-eye"></i></a></td>
            </tr>`).join("")
        : `<tr><td colspan="6"><div class="empty-state"><i class="bi bi-inbox"></i><h3>No findings match this filter</h3></div></td></tr>`;
    }
    renderFindings(findings);
  
    document.getElementById("filterSev").addEventListener("change", (e) => {
      const sev = e.target.value;
      renderFindings(sev ? findings.filter((v) => v.severity === sev) : findings);
    });
  
    document.getElementById("exportReportBtn").addEventListener("click", () => {
      const header = "id,cve,title,severity,cvssScore,host,port,service,status\n";
      const body = findings.map((v) => [v.id, v.cve, `"${v.title.replace(/"/g, '""')}"`, v.severity, v.cvssScore, v.host, v.port, v.service, v.status].join(",")).join("\n");
      const blob = new Blob([header + body], { type: "text/csv" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = `${scan.id}-report.csv`;
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
      if (window.showToast) window.showToast({ type: "success", title: "Report exported", msg: `${scan.id}-report.csv downloaded.` });
    });
  })();
  