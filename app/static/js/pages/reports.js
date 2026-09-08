/**
 * CyberDefense XDR
 * Security Reports Dashboard & Generation Logic
 */

document.addEventListener("DOMContentLoaded", () => {
  let currentPage = 1;
  const pageSize = 20;

  // DOM Elements
  const tableBody = document.getElementById("reportsTableBody");
  const paginationInfo = document.getElementById("paginationInfo");
  const paginationControls = document.getElementById("paginationControls");
  const searchInput = document.getElementById("historySearch");
  const filterType = document.getElementById("filterType");
  const filterFormat = document.getElementById("filterFormat");
  const btnRefresh = document.getElementById("btnRefreshHistory");

  // KPI Elements
  const kpiTotal = document.getElementById("kpiTotalReports");
  const kpiRecent = document.getElementById("kpiRecentReports");
  const kpiPdf = document.getElementById("kpiPdfReports");
  const kpiCsv = document.getElementById("kpiCsvReports");

  // Modal Elements
  const generateModalEl = document.getElementById("generateReportModal");
  const generateModal = generateModalEl ? new bootstrap.Modal(generateModalEl) : null;
  const generateForm = document.getElementById("reportGenerateForm");
  const generateProgress = document.getElementById("generateProgress");
  const btnSubmitGenerate = document.getElementById("btnSubmitGenerate");
  const datePresetSelect = document.getElementById("genDatePreset");
  const customDateRow = document.getElementById("customDateRow");

  // Format type labels
  const TYPE_NAMES = {
    executive_summary: "Executive Summary",
    soc_operations: "SOC Operations",
    vulnerability_assessment: "Vulnerability Assessment",
    incident_response: "Incident Response",
    alert_detection: "Alert & Detection",
    network_ids: "Network IDS",
    asset_risk: "Asset Risk",
    threat_intel: "Threat Intelligence",
  };

  // Helper for quick launch modal opening
  window.openGenerateModal = function(typeKey) {
    const typeSelect = document.getElementById("genReportType");
    if (typeSelect && typeKey) {
      typeSelect.value = typeKey;
    }
    if (generateModal) {
      generateModal.show();
    }
  };

  // Toggle Custom Date range pickers
  if (datePresetSelect) {
    datePresetSelect.addEventListener("change", () => {
      if (datePresetSelect.value === "custom") {
        customDateRow.classList.remove("d-none");
      } else {
        customDateRow.classList.add("d-none");
      }
    });
  }

  // Fetch and render report history
  async function loadHistory(page = 1) {
    currentPage = page;
    const typeVal = filterType ? filterType.value : "all";
    const formatVal = filterFormat ? filterFormat.value : "all";
    const searchVal = searchInput ? searchInput.value.trim() : "";

    const params = new URLSearchParams({
      page: currentPage,
      per_page: pageSize,
    });
    if (typeVal && typeVal !== "all") params.append("type", typeVal);
    if (formatVal && formatVal !== "all") params.append("format", formatVal);
    if (searchVal) params.append("search", searchVal);

    try {
      const res = await fetch(`/reports/api/history?${params.toString()}`);
      if (!res.ok) throw new Error(`HTTP Error ${res.status}`);
      const data = await res.json();

      renderTable(data.reports || []);
      renderPagination(data.total, data.page, data.pages);
      updateKpis(data.reports || [], data.total);
    } catch (err) {
      console.error("Failed to load report history:", err);
      if (tableBody) {
        tableBody.innerHTML = `
          <tr>
            <td colspan="9" class="text-center py-4 text-danger small">
              <i class="bi bi-exclamation-triangle me-2"></i>Failed to load reports: ${err.message}
            </td>
          </tr>
        `;
      }
    }
  }

  // Update top KPI cards
  function updateKpis(reports, totalCount) {
    if (kpiTotal) kpiTotal.textContent = totalCount || 0;

    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    let recentCount = 0;
    let pdfCount = 0;
    let csvCount = 0;

    reports.forEach((r) => {
      if (r.format === "pdf") pdfCount++;
      if (r.format === "csv") csvCount++;
      if (r.created_at && new Date(r.created_at) >= thirtyDaysAgo) recentCount++;
    });

    if (kpiRecent) kpiRecent.textContent = recentCount;
    if (kpiPdf) kpiPdf.textContent = pdfCount;
    if (kpiCsv) kpiCsv.textContent = csvCount;
  }

  // Render HTML table rows
  function renderTable(reports) {
    if (!tableBody) return;
    if (!reports || reports.length === 0) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="9" class="text-center py-4 text-muted small">
            No generated reports found matching the criteria. Click "Generate Report" to create one.
          </td>
        </tr>
      `;
      return;
    }

    tableBody.innerHTML = reports.map((r) => {
      const typeLabel = TYPE_NAMES[r.report_type] || r.report_type;
      const formatBadgeClass = r.format === "pdf" ? "format-badge-pdf" : "format-badge-csv";
      const statusBadgeClass = r.status === "completed" ? "bg-success-subtle text-success" : "bg-danger-subtle text-danger";
      
      let dateScope = "All Time";
      if (r.date_from && r.date_to) {
        dateScope = `${r.date_from.substring(0, 10)} to ${r.date_to.substring(0, 10)}`;
      } else if (r.date_from) {
        dateScope = `Since ${r.date_from.substring(0, 10)}`;
      }

      const createdDate = r.created_at ? r.created_at.substring(0, 19).replace("T", " ") : "—";

      return `
        <tr>
          <td>
            <a href="/reports/${r.report_id}" class="cell-mono text-decoration-none fw-semibold text-primary">
              ${r.report_id}
            </a>
          </td>
          <td>
            <div class="fw-semibold text-truncate" style="max-width: 260px;" title="${r.title}">${r.title}</div>
            <span class="badge bg-secondary-subtle text-muted text-xs">${typeLabel}</span>
          </td>
          <td><span class="badge ${formatBadgeClass} text-uppercase">${r.format}</span></td>
          <td class="small text-muted cell-mono">${dateScope}</td>
          <td class="small">${r.generated_by || "SOC Analyst"}</td>
          <td class="small text-muted cell-mono">${createdDate}</td>
          <td><span class="badge ${statusBadgeClass}">${r.status}</span></td>
          <td class="text-end">
            <div class="btn-group btn-group-sm">
              <a href="/reports/${r.report_id}" class="btn btn-outline-secondary" title="View Details">
                <i class="bi bi-eye"></i>
              </a>
              <a href="/reports/api/${r.report_id}/download" class="btn btn-outline-primary" title="Download File">
                <i class="bi bi-download"></i>
              </a>
              <button type="button" class="btn btn-outline-danger btn-delete-report" data-id="${r.report_id}" title="Delete Report">
                <i class="bi bi-trash"></i>
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join("");

    // Bind delete buttons
    document.querySelectorAll(".btn-delete-report").forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        e.preventDefault();
        const reportId = btn.getAttribute("data-id");
        if (!confirm(`Are you sure you want to permanently delete report ${reportId}?`)) {
          return;
        }

        try {
          const delRes = await fetch(`/reports/api/${reportId}`, { method: "DELETE" });
          const delData = await delRes.json();
          if (delData.success) {
            loadHistory(currentPage);
          } else {
            alert(`Failed to delete report: ${delData.error || "Unknown error"}`);
          }
        } catch (err) {
          alert(`Network error deleting report: ${err.message}`);
        }
      });
    });
  }

  // Render pagination controls
  function renderPagination(total, page, pages) {
    if (!paginationInfo || !paginationControls) return;

    const startIdx = total === 0 ? 0 : (page - 1) * pageSize + 1;
    const endIdx = Math.min(page * pageSize, total);
    paginationInfo.textContent = `Showing ${startIdx} to ${endIdx} of ${total} reports`;

    if (pages <= 1) {
      paginationControls.innerHTML = "";
      return;
    }

    let items = `
      <li class="page-item ${page === 1 ? "disabled" : ""}">
        <a class="page-link" href="#" data-page="${page - 1}">&laquo;</a>
      </li>
    `;

    for (let p = 1; p <= pages; p++) {
      if (p === 1 || p === pages || (p >= page - 1 && p <= page + 1)) {
        items += `
          <li class="page-item ${p === page ? "active" : ""}">
            <a class="page-link" href="#" data-page="${p}">${p}</a>
          </li>
        `;
      } else if (p === page - 2 || p === page + 2) {
        items += `<li class="page-item disabled"><span class="page-link">...</span></li>`;
      }
    }

    items += `
      <li class="page-item ${page === pages ? "disabled" : ""}">
        <a class="page-link" href="#" data-page="${page + 1}">&raquo;</a>
      </li>
    `;

    paginationControls.innerHTML = items;
    paginationControls.querySelectorAll(".page-link[data-page]").forEach((link) => {
      link.addEventListener("click", (e) => {
        e.preventDefault();
        const targetPage = parseInt(link.getAttribute("data-page"), 10);
        if (targetPage >= 1 && targetPage <= pages && targetPage !== page) {
          loadHistory(targetPage);
        }
      });
    });
  }

  // Handle Generate Submission
  if (btnSubmitGenerate) {
    btnSubmitGenerate.addEventListener("click", async () => {
      const typeSelect = document.getElementById("genReportType");
      const formatSelect = document.getElementById("genFormat");
      const titleInput = document.getElementById("genTitle");
      const descInput = document.getElementById("genDescription");
      const severityFilter = document.getElementById("genFilterSeverity");
      const datePreset = document.getElementById("genDatePreset");
      const dateFromInput = document.getElementById("genDateFrom");
      const dateToInput = document.getElementById("genDateTo");

      const payload = {
        report_type: typeSelect.value,
        format: formatSelect.value,
        title: titleInput.value.trim() || undefined,
        description: descInput.value.trim() || undefined,
        date_range_preset: datePreset.value,
        date_from: datePreset.value === "custom" && dateFromInput.value ? dateFromInput.value : undefined,
        date_to: datePreset.value === "custom" && dateToInput.value ? dateToInput.value : undefined,
        filters: {
          severity: severityFilter.value !== "all" ? severityFilter.value : undefined,
        },
      };

      // Show Progress Spinner
      generateForm.classList.add("d-none");
      generateProgress.classList.remove("d-none");
      btnSubmitGenerate.disabled = true;

      try {
        const res = await fetch("/reports/api/generate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });

        const data = await res.json();
        if (res.ok && data.success) {
          generateModal.hide();
          generateForm.reset();
          customDateRow.classList.add("d-none");
          loadHistory(1);
          window.location.href = `/reports/${data.report.report_id}`;
        } else {
          alert(`Failed to generate report: ${data.error || "Server error"}`);
        }
      } catch (err) {
        alert(`Error generating report: ${err.message}`);
      } finally {
        generateForm.classList.remove("d-none");
        generateProgress.classList.add("d-none");
        btnSubmitGenerate.disabled = false;
      }
    });
  }

  // Filter events
  if (filterType) filterType.addEventListener("change", () => loadHistory(1));
  if (filterFormat) filterFormat.addEventListener("change", () => loadHistory(1));
  if (btnRefresh) btnRefresh.addEventListener("click", () => loadHistory(currentPage));

  let searchTimeout = null;
  if (searchInput) {
    searchInput.addEventListener("input", () => {
      clearTimeout(searchTimeout);
      searchTimeout = setTimeout(() => loadHistory(1), 300);
    });
  }

  // Initial load
  loadHistory(1);
});
