/**
 * CyberDefense XDR
 * Audit Logs Page Controller
 * Handles asynchronous fetching, dynamic filtering, real-time metrics,
 * CSV export parameter synchronization, and inspection modal navigation.
 */

document.addEventListener("DOMContentLoaded", () => {
  // State
  let currentPage = 1;
  let perPage = 20;
  let totalLogs = 0;
  let totalPages = 1;
  let searchDebounceTimer = null;

  // Filter elements
  const filterSearch = document.getElementById("filterSearch");
  const filterCategory = document.getElementById("filterCategory");
  const filterSeverity = document.getElementById("filterSeverity");
  const filterResult = document.getElementById("filterResult");
  const filterPerPage = document.getElementById("filterPerPage");
  const btnResetFilters = document.getElementById("btnResetFilters");
  const btnRefreshLogs = document.getElementById("btnRefreshLogs");
  const btnExportCsv = document.getElementById("btnExportCsv");

  // Table elements
  const tableBody = document.getElementById("auditTableBody");
  const paginationSummary = document.getElementById("paginationSummary");
  const pageIndicator = document.getElementById("pageIndicator");
  const btnPrevPage = document.getElementById("btnPrevPage");
  const btnNextPage = document.getElementById("btnNextPage");

  // Metric elements
  const statTotal = document.getElementById("statTotal");
  const statToday = document.getElementById("statToday");
  const statAuthFails = document.getElementById("statAuthFails");
  const statAccessDenials = document.getElementById("statAccessDenials");
  const statAdminActions = document.getElementById("statAdminActions");
  const statSoarActions = document.getElementById("statSoarActions");

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function getQueryFilters() {
    const filters = {};
    if (filterSearch && filterSearch.value.trim()) {
      filters.search = filterSearch.value.trim();
    }
    if (filterCategory && filterCategory.value) {
      filters.category = filterCategory.value;
    }
    if (filterSeverity && filterSeverity.value) {
      filters.severity = filterSeverity.value;
    }
    if (filterResult && filterResult.value) {
      filters.result = filterResult.value;
    }
    return filters;
  }

  function updateExportLink(params) {
    if (!btnExportCsv) return;
    const exportParams = new URLSearchParams(params);
    exportParams.delete("page");
    exportParams.delete("per_page");
    btnExportCsv.href = `/audit-logs/api/export?${exportParams.toString()}`;
  }

  async function loadStats() {
    try {
      const res = await fetch("/audit-logs/api/stats");
      if (!res.ok) return;
      const data = await res.json();
      if (data.success && data.data) {
        const s = data.data;
        if (statTotal) statTotal.textContent = s.total_events || 0;
        if (statToday) statToday.textContent = s.events_today || 0;
        if (statAuthFails) statAuthFails.textContent = s.authentication_failures || 0;
        if (statAccessDenials) statAccessDenials.textContent = s.authorization_denials || 0;
        if (statAdminActions) statAdminActions.textContent = s.admin_actions || 0;
        if (statSoarActions) statSoarActions.textContent = s.soar_actions || 0;
      }
    } catch (err) {
      console.warn("Unable to refresh audit stats:", err);
    }
  }

  async function loadLogs(page = 1) {
    currentPage = page;
    if (filterPerPage) {
      perPage = parseInt(filterPerPage.value, 10) || 20;
    }

    tableBody.innerHTML = `
      <tr>
        <td colspan="9" class="text-center py-5 text-muted">
          <div class="spinner-border spinner-border-sm text-primary me-2" role="status"></div>
          Loading compliance audit trails...
        </td>
      </tr>
    `;

    const filters = getQueryFilters();
    const params = new URLSearchParams({
      page: currentPage,
      per_page: perPage,
      ...filters,
    });

    updateExportLink(filters);

    try {
      const res = await fetch(`/audit-logs/api?${params.toString()}`);
      if (!res.ok) {
        throw new Error(`Server returned HTTP ${res.status}`);
      }
      const json = await res.json();
      if (!json.success) {
        throw new Error(json.error || "Failed to load audit records");
      }

      const items = json.data || [];
      const pagination = json.pagination || {};
      totalLogs = pagination.total || 0;
      totalPages = pagination.pages || 1;

      renderRows(items);
      renderPagination(pagination);
    } catch (err) {
      console.error("Audit load error:", err);
      tableBody.innerHTML = `
        <tr>
          <td colspan="9" class="text-center py-4 text-danger">
            <i class="bi bi-exclamation-triangle-fill me-2"></i>Failed to load audit records: ${escapeHtml(err.message)}
          </td>
        </tr>
      `;
      if (paginationSummary) paginationSummary.textContent = "Error loading records";
      if (btnPrevPage) btnPrevPage.disabled = true;
      if (btnNextPage) btnNextPage.disabled = true;
    }
  }

  function getResultBadge(result) {
    const r = (result || "success").toLowerCase();
    if (r === "success") {
      return `<span class="badge badge-success-soft"><i class="bi bi-check-circle me-1"></i>SUCCESS</span>`;
    }
    if (r === "denied") {
      return `<span class="badge badge-warning-soft"><i class="bi bi-shield-x me-1"></i>DENIED</span>`;
    }
    if (r === "failure" || r === "error") {
      return `<span class="badge badge-danger-soft"><i class="bi bi-x-circle me-1"></i>${r.toUpperCase()}</span>`;
    }
    return `<span class="badge badge-secondary-soft">${escapeHtml(r.toUpperCase())}</span>`;
  }

  function getSeverityBadge(severity) {
    const s = (severity || "low").toLowerCase();
    if (s === "critical") {
      return `<span class="badge bg-danger text-light">CRITICAL</span>`;
    }
    if (s === "high") {
      return `<span class="badge bg-danger-subtle text-danger">HIGH</span>`;
    }
    if (s === "medium") {
      return `<span class="badge bg-warning-subtle text-warning">MEDIUM</span>`;
    }
    return `<span class="badge bg-secondary-subtle text-light">LOW</span>`;
  }

  function renderRows(items) {
    if (!items.length) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="9" class="text-center py-5 text-muted">
            <i class="bi bi-journal-x fs-1 d-block mb-2 text-secondary"></i>
            No audit records found matching your filter criteria.
          </td>
        </tr>
      `;
      return;
    }

    const rowsHtml = items.map((log) => {
      const ts = log.timestamp || "";
      const formattedTs = ts.replace("T", " ").replace(/\.\d+/, "").substring(0, 19);
      const actorName = log.actor || "System";
      const actorRole = log.actor_role ? `<span class="badge bg-dark border border-secondary text-secondary ms-1 small">${escapeHtml(log.actor_role)}</span>` : "";
      const resourceStr = log.resource_type ? `${escapeHtml(log.resource_type)}${log.resource_id ? ` #${escapeHtml(log.resource_id)}` : ""}` : "System";

      return `
        <tr>
          <td class="code-font text-muted small text-nowrap">${escapeHtml(formattedTs)}</td>
          <td>
            <div class="d-flex align-items-center">
              <i class="bi bi-person-circle text-secondary me-2"></i>
              <span class="text-light fw-medium small">${escapeHtml(actorName)}</span>
              ${actorRole}
            </div>
          </td>
          <td>
            <span class="font-monospace text-info small">${escapeHtml(log.action || "EVENT")}</span>
          </td>
          <td>
            <span class="badge badge-purple-soft small">${escapeHtml(log.category || "General")}</span>
          </td>
          <td class="text-truncate small text-secondary" style="max-width: 180px;" title="${escapeHtml(resourceStr)}">
            ${escapeHtml(resourceStr)}
          </td>
          <td class="code-font small text-muted text-nowrap">${escapeHtml(log.source_ip || "127.0.0.1")}</td>
          <td>${getResultBadge(log.result)}</td>
          <td>${getSeverityBadge(log.severity)}</td>
          <td class="text-end">
            <a href="/audit-logs/details/${encodeURIComponent(log.audit_id)}" class="btn btn-outline-secondary btn-sm py-0 px-2" title="Inspect Record">
              <i class="bi bi-search"></i>
            </a>
          </td>
        </tr>
      `;
    }).join("");

    tableBody.innerHTML = rowsHtml;
  }

  function renderPagination(p) {
    const total = p.total || 0;
    const page = p.page || 1;
    const pages = p.pages || 1;
    const start = total === 0 ? 0 : (page - 1) * perPage + 1;
    const end = Math.min(page * perPage, total);

    if (paginationSummary) {
      paginationSummary.textContent = `Showing ${start} to ${end} of ${total} events`;
    }
    if (pageIndicator) {
      pageIndicator.textContent = `Page ${page} of ${pages}`;
    }
    if (btnPrevPage) {
      btnPrevPage.disabled = page <= 1;
    }
    if (btnNextPage) {
      btnNextPage.disabled = page >= pages;
    }
  }

  // Event Listeners
  if (filterSearch) {
    filterSearch.addEventListener("input", () => {
      clearTimeout(searchDebounceTimer);
      searchDebounceTimer = setTimeout(() => {
        loadLogs(1);
      }, 300);
    });
  }

  if (filterCategory) {
    filterCategory.addEventListener("change", () => loadLogs(1));
  }
  if (filterSeverity) {
    filterSeverity.addEventListener("change", () => loadLogs(1));
  }
  if (filterResult) {
    filterResult.addEventListener("change", () => loadLogs(1));
  }
  if (filterPerPage) {
    filterPerPage.addEventListener("change", () => loadLogs(1));
  }

  if (btnResetFilters) {
    btnResetFilters.addEventListener("click", () => {
      if (filterSearch) filterSearch.value = "";
      if (filterCategory) filterCategory.value = "";
      if (filterSeverity) filterSeverity.value = "";
      if (filterResult) filterResult.value = "";
      if (filterPerPage) filterPerPage.value = "20";
      loadLogs(1);
    });
  }

  if (btnRefreshLogs) {
    btnRefreshLogs.addEventListener("click", () => {
      loadLogs(currentPage);
      loadStats();
      if (typeof window.showToast === "function") {
        window.showToast("Audit logs and statistics refreshed", "info");
      }
    });
  }

  if (btnPrevPage) {
    btnPrevPage.addEventListener("click", () => {
      if (currentPage > 1) {
        loadLogs(currentPage - 1);
      }
    });
  }

  if (btnNextPage) {
    btnNextPage.addEventListener("click", () => {
      if (currentPage < totalPages) {
        loadLogs(currentPage + 1);
      }
    });
  }

  // Initial load
  loadLogs(1);
  loadStats();
});

