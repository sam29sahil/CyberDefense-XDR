/* ==========================================================================
   scan-details.js — page module for app/scan-details.html
   Depends on: SCANS_DATA, VULNERABILITIES_DATA (fallbacks), XDR_PALETTE
   ========================================================================== */

(function () {
  const STATUS_LABEL = { completed: "Completed", running: "Running", queued: "Queued", failed: "Failed" };
  const params = new URLSearchParams(window.location.search);
  const scanId = window.SCAN_ID || params.get("id");

  let scanSeverityChartInstance = null;

  function renderScanDetails(scan, findings) {
    const breadcrumb = document.getElementById("breadcrumbScanId");
    const scanName = document.getElementById("scanName");
    const scanStatusPill = document.getElementById("scanStatusPill");
    const scanProfileBadge = document.getElementById("scanProfileBadge");
    const toolsUsedBadges = document.getElementById("toolsUsedBadges");
    const scanMeta = document.getElementById("scanMeta");

    if (breadcrumb) breadcrumb.textContent = scan.name;
    if (scanName) scanName.textContent = scan.name;
    if (scanProfileBadge) {
      scanProfileBadge.textContent = (scan.profile || "STANDARD").toUpperCase();
    }
    if (scanStatusPill) {
      scanStatusPill.innerHTML = `<span class="status-pill st-${scan.status}"><span class="dot"></span>${STATUS_LABEL[scan.status] || scan.status}</span>`;
    }

    // Render tools used badges
    if (toolsUsedBadges) {
      const tools = scan.toolsUsed || ["nmap"];
      toolsUsedBadges.innerHTML = tools.map((tool) => {
        const t = String(tool).toLowerCase();
        const icon = t === "whatweb" ? "bi-code-slash" : t === "nikto" ? "bi-lightning-charge" : t === "nuclei" ? "bi-radioactive" : "bi-hdd-network";
        return `<span class="badge bg-secondary-subtle text-light border text-xs"><i class="bi ${icon} me-1 text-primary"></i>${tool}</span>`;
      }).join("");
    }

    if (scanMeta) {
      const timeStr = window.XDRUtils && XDRUtils.formatTime ? XDRUtils.formatTime(scan.startedAt) : (scan.startedAt?.slice(0, 16).replace("T", " ") || "—");
      scanMeta.textContent = `${scan.type} · started ${timeStr}${scan.durationMin ? ` · ${scan.durationMin} min duration` : ""} · initiated by ${scan.initiatedBy || "Analyst"}`;
    }

    const gaugeColor = scan.riskScore >= 70 ? "var(--danger)" : scan.riskScore >= 40 ? "var(--warning)" : "var(--success)";
    const gauge = document.getElementById("riskGauge");
    if (gauge) {
      gauge.style.setProperty("--pct", scan.riskScore || 0);
      gauge.style.setProperty("--gauge-color", gaugeColor);
    }
    const gaugeVal = document.getElementById("riskGaugeValue");
    if (gaugeVal) gaugeVal.textContent = scan.riskScore || 0;

    // Severity chart
    const sevCanvas = document.getElementById("scanSeverityChart");
    if (sevCanvas) {
      const sevOrder = ["critical", "high", "medium", "low"];
      const summary = scan.findingsSummary || {};
      const sevCounts = sevOrder.map((s) => summary[s] || 0);

      if (scanSeverityChartInstance) scanSeverityChartInstance.destroy();

      scanSeverityChartInstance = new Chart(sevCanvas, {
        type: "doughnut",
        data: {
          labels: sevOrder.map((s) => s[0].toUpperCase() + s.slice(1)),
          datasets: [{
            data: sevCounts,
            backgroundColor: sevOrder.map((s) => XDR_PALETTE.severity[s]),
            borderWidth: 0,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: "68%",
          plugins: {
            legend: {
              display: true,
              position: "bottom",
              labels: { usePointStyle: true, boxWidth: 8, boxHeight: 8 },
            },
          },
        },
      });
    }

    // Targets list & DNS resolution
    const targetsList = document.getElementById("scanTargetsList");
    if (targetsList) {
      const tgts = scan.targets || [];
      targetsList.innerHTML = tgts.length ? tgts.map((t) => `
        <div class="info-row">
          <span><i class="bi bi-hdd-network text-muted"></i> ${t}</span>
          <span class="text-xs text-muted">in scope</span>
        </div>`).join("") : `<p class="text-muted text-sm mb-0">No targets specified.</p>`;
    }

    const dnsBox = document.getElementById("dnsResolutionBox");
    const dnsContent = document.getElementById("dnsResolutionContent");
    if (dnsBox && dnsContent && scan.dnsData && Object.keys(scan.dnsData).length > 0) {
      dnsBox.style.display = "block";
      dnsContent.innerHTML = Object.entries(scan.dnsData).map(([target, records]) => {
        const ips = [...(records.ipv4 || []), ...(records.ipv6 || [])];
        return ips.map((ip) => `<span class="badge bg-secondary text-light cell-mono text-xs">${target} → ${ip}</span>`).join("");
      }).join("");
    }

    // Web Technologies section
    const webTechRow = document.getElementById("webTechRow");
    const webTechContent = document.getElementById("webTechContent");
    if (webTechRow && webTechContent) {
      const webTechs = scan.webTechnologies || [];
      if (webTechs.length > 0) {
        webTechRow.style.display = "block";
        webTechContent.innerHTML = `
          <div class="d-flex flex-wrap gap-2">
            ${webTechs.map((wt) => {
              const name = typeof wt === "string" ? wt : (wt.name || wt.plugin || JSON.stringify(wt));
              const ver = wt.version ? ` v${wt.version}` : "";
              return `<span class="badge bg-dark border text-light p-2"><i class="bi bi-code-slash text-info me-1"></i>${name}${ver}</span>`;
            }).join("")}
          </div>`;
      } else {
        webTechRow.style.display = "none";
      }
    }

    // Discovered Services & Exposure Observations table
    const servicesWrap = document.getElementById("servicesWrap");
    const servicesBody = document.getElementById("servicesBody");
    const servicesBadge = document.getElementById("servicesCountBadge");
    const servList = scan.serviceObservations || [];

    if (servicesWrap && servicesBody) {
      if (servList.length > 0) {
        servicesWrap.style.display = "block";
        if (servicesBadge) servicesBadge.textContent = servList.length;
        servicesBody.innerHTML = servList.map((s) => {
          const statePill = s.state === "open"
            ? `<span class="badge bg-success-subtle text-success">open</span>`
            : `<span class="badge bg-secondary-subtle text-secondary">${s.state || "unknown"}</span>`;
          const prodVer = [s.product, s.version].filter(Boolean).join(" ") || s.extrainfo || "—";
          return `
            <tr>
              <td class="cell-mono" style="font-weight:600;">${s.port}/${s.protocol || "tcp"}</td>
              <td><span class="badge bg-dark border text-light">${s.service || "unknown"}</span></td>
              <td>${prodVer}</td>
              <td>${statePill}</td>
              <td>${s.host || "—"}</td>
              <td><span class="badge bg-secondary-subtle text-secondary text-xs">${(s.tool || "nmap").toUpperCase()}</span></td>
            </tr>`;
        }).join("");
      } else {
        servicesWrap.style.display = "none";
      }
    }

    // Findings table
    let allFindings = findings || [];

    function renderFindings(list) {
      const findingsBody = document.getElementById("findingsBody");
      if (!findingsBody) return;

      findingsBody.innerHTML = list.length
        ? list.map((v) => {
            const cveLabel = v.cve ? v.cve : "";
            const subLabel = [cveLabel, v.cwe].filter(Boolean).join(" · ") || "—";
            return `
            <tr>
              <td>
                <a href="/scanner/vulnerabilities/${v.id}" style="color:var(--text);font-weight:600;text-decoration:none;">${v.title}</a>
                <div class="text-xs text-muted">${subLabel}</div>
              </td>
              <td style="font-weight:600;">${v.host || (v.affectedAssets && v.affectedAssets[0]) || "target"}</td>
              <td><span class="badge bg-secondary-subtle text-secondary text-xs">${(v.tool || "nmap").toUpperCase()}</span></td>
              <td><span class="cvss-badge cvss-${v.severity}">${v.cvssScore !== null && v.cvssScore !== undefined ? v.cvssScore : "—"}</span></td>
              <td class="text-sm cell-mono">${v.port || "—"}/${v.service || "—"}</td>
              <td><span class="status-pill st-${v.status}"><span class="dot"></span>${(v.status || "").replace("_", " ")}</span></td>
              <td><a href="/scanner/vulnerabilities/${v.id}" class="btn btn-icon btn-ghost btn-sm" title="View details"><i class="bi bi-eye"></i></a></td>
            </tr>`;
          }).join("")
        : `<tr><td colspan="7"><div class="empty-state py-4"><i class="bi bi-shield-check text-success"></i><h3>No vulnerability findings recorded matching filter criteria</h3></div></td></tr>`;
    }

    renderFindings(allFindings);

    function applyFilters() {
      const sev = document.getElementById("filterSev")?.value || "";
      const tool = document.getElementById("filterTool")?.value || "";
      let filtered = allFindings;
      if (sev) filtered = filtered.filter((v) => v.severity === sev);
      if (tool) filtered = filtered.filter((v) => (v.tool || "nmap").toLowerCase() === tool.toLowerCase());
      renderFindings(filtered);
    }

    const filterSev = document.getElementById("filterSev");
    if (filterSev) filterSev.addEventListener("change", applyFilters);
    const filterTool = document.getElementById("filterTool");
    if (filterTool) filterTool.addEventListener("change", applyFilters);

    // Export report
    const exportBtn = document.getElementById("exportReportBtn");
    if (exportBtn) {
      exportBtn.onclick = () => {
        const header = "id,cve,title,severity,cvssScore,host,port,service,status\n";
        const body = findings.map((v) => [
          v.id,
          v.cve,
          `"${(v.title || "").replace(/"/g, '""')}"`,
          v.severity,
          v.cvssScore,
          v.host || (v.affectedAssets && v.affectedAssets[0]) || "",
          v.port || "",
          v.service || "",
          v.status,
        ].join(",")).join("\n");

        const blob = new Blob([header + body], { type: "text/csv" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `${scan.id}-report.csv`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        if (window.showToast) window.showToast({ type: "success", title: "Report exported", msg: `${scan.id}-report.csv downloaded.` });
      };
    }
  }

  // Load from API
  if (scanId) {
    fetch(`/scanner/api/scans/${scanId}`)
      .then((res) => (res.ok ? res.json() : Promise.reject(res)))
      .then((data) => {
        if (data && data.scan) {
          renderScanDetails(data.scan, data.findings || []);
        } else {
          fallbackRender();
        }
      })
      .catch(() => {
        fallbackRender();
      });
  } else {
    fallbackRender();
  }

  function fallbackRender() {
    const scans = typeof SCANS_DATA !== "undefined" ? SCANS_DATA : [];
    const vulns = typeof VULNERABILITIES_DATA !== "undefined" ? VULNERABILITIES_DATA : [];
    const scan = scans.find((s) => s.id === scanId) || scans[0] || {
      id: "SCAN-DEMO",
      name: "Local Infrastructure Scan",
      type: "Quick Scan",
      status: "completed",
      startedAt: new Date().toISOString(),
      durationMin: 2,
      initiatedBy: "Security Analyst",
      targets: ["127.0.0.1"],
      findingsSummary: { critical: 0, high: 0, medium: 0, low: 0 },
      findingIds: [],
      riskScore: 10,
    };
    const findings = vulns.filter((v) => (scan.findingIds || []).includes(v.id));
    renderScanDetails(scan, findings);
  }
})();