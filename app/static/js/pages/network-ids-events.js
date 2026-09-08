/* ==========================================================================
   network-ids-events.js — Network IDS Events Explorer Controller
   ========================================================================== */

(function () {
  "use strict";

  let currentPage = 1;
  let totalPages = 1;
  let totalCount = 0;
  const perPage = 25;

  function escapeHtml(val) {
    if (val === null || val === undefined) return "";
    return String(val)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function getFilterParams() {
    const search = document.getElementById("searchQuery")?.value?.trim() || "";
    const eventType = document.getElementById("filterEventType")?.value || "";
    const severity = document.getElementById("filterSeverity")?.value || "";
    const protocol = document.getElementById("filterProtocol")?.value || "";
    const alertOnly = document.getElementById("checkAlertsOnly")?.checked ? "true" : "";

    const params = new URLSearchParams();
    params.set("page", currentPage);
    params.set("per_page", perPage);

    if (search) params.set("q", search);
    if (eventType) params.set("event_type", eventType);
    if (severity) params.set("severity", severity);
    if (protocol) params.set("protocol", protocol);
    if (alertOnly === "true") params.set("alert_only", "true");

    return params;
  }

  async function loadEvents() {
    const tbody = document.getElementById("eventsTableBody");
    const infoEl = document.getElementById("paginationInfo");
    const btnPrev = document.getElementById("btnPrevPage");
    const btnNext = document.getElementById("btnNextPage");

    if (tbody) {
      tbody.innerHTML = `<tr><td colspan="10" class="text-center text-muted py-4"><span class="spinner-border spinner-border-sm me-2"></span>Loading network events...</td></tr>`;
    }

    try {
      const params = getFilterParams();
      const res = await fetch(`/network-ids/api/events?${params.toString()}`, { cache: "no-store" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      if (!data.success) {
        if (tbody) tbody.innerHTML = `<tr><td colspan="10" class="text-center text-danger py-4">Failed to load events: ${escapeHtml(data.message)}</td></tr>`;
        return;
      }

      const events = data.events || [];
      const pagination = data.pagination || {};
      totalCount = pagination.total || 0;
      totalPages = pagination.pages || 1;
      currentPage = pagination.page || 1;

      // Update Pagination Info & buttons
      if (infoEl) {
        const start = totalCount === 0 ? 0 : (currentPage - 1) * perPage + 1;
        const end = Math.min(currentPage * perPage, totalCount);
        infoEl.textContent = `Showing ${start}-${end} of ${totalCount.toLocaleString()} events`;
      }
      if (btnPrev) btnPrev.disabled = currentPage <= 1;
      if (btnNext) btnNext.disabled = currentPage >= totalPages;

      // Render Rows
      if (!tbody) return;

      if (events.length === 0) {
        tbody.innerHTML = `<tr><td colspan="10" class="text-center text-muted py-4"><i class="bi bi-inbox fs-3 d-block mb-1"></i>No network events match your filter criteria</td></tr>`;
        return;
      }

      tbody.innerHTML = events.map(e => {
        const isDiag = e.classification === 'diagnostic' || e.is_diagnostic || (e.signature_id === 2200074);
        const sevClass = e.severity ? `badge-sev-${e.severity.toLowerCase()}` : "badge-neutral";
        const ts = e.timestamp ? new Date(e.timestamp).toLocaleString() : "—";
        const src = e.src_ip ? `${escapeHtml(e.src_ip)}${e.src_port ? ':' + e.src_port : ''}` : "—";
        const dest = e.dest_ip ? `${escapeHtml(e.dest_ip)}${e.dest_port ? ':' + e.dest_port : ''}` : "—";
        const sig = e.signature || (e.event_type === 'dns' ? 'DNS Query' : (e.event_type === 'http' ? 'HTTP Request' : 'Network Flow'));
        const action = e.action || 'allowed';
        const actionBadge = `<span class="badge bg-${action === 'blocked' ? 'danger' : 'success'}-subtle text-${action === 'blocked' ? 'danger' : 'success'}">${escapeHtml(action.toUpperCase())}</span>`;

        const typeBadge = isDiag
          ? `<span class="badge bg-info-subtle text-info text-xs fw-semibold" title="NIC Checksum / Offload Diagnostic"><i class="bi bi-gear-wide-connected me-1"></i>DIAGNOSTIC</span>`
          : `<span class="badge bg-secondary text-xs">${escapeHtml((e.event_type || 'flow').toUpperCase())}</span>`;

        const sevBadge = isDiag
          ? `<span class="badge bg-secondary text-light text-xs" title="Diagnostic Telemetry - Non-threat">INFO (DIAG)</span>`
          : `<span class="badge ${sevClass}">${escapeHtml((e.severity || 'info').toUpperCase())}</span>`;

        return `<tr>
          <td class="cell-mono text-xs text-nowrap">${ts}</td>
          <td>${typeBadge}</td>
          <td>${sevBadge}</td>
          <td class="cell-mono text-xs">${src}</td>
          <td class="cell-mono text-xs">${dest}</td>
          <td><span class="badge bg-dark border text-xs">${escapeHtml(e.protocol || 'IP')}</span></td>
          <td class="fw-semibold text-truncate" style="max-width: 240px;" title="${escapeHtml(sig)}">${escapeHtml(sig)}</td>
          <td class="text-muted text-xs text-truncate" style="max-width: 140px;">${escapeHtml(e.category || '—')}</td>
          <td>${actionBadge}</td>
          <td class="text-end">
            <a href="/network-ids/events/${e.id}" class="btn btn-secondary btn-sm py-0 px-2" title="Inspect Event"><i class="bi bi-eye"></i> Details</a>
          </td>
        </tr>`;
      }).join("");

    } catch (err) {
      if (tbody) {
        tbody.innerHTML = `<tr><td colspan="10" class="text-center text-danger py-4">Error fetching events: ${escapeHtml(String(err))}</td></tr>`;
      }
    }
  }

  function bindEvents() {
    const searchInput = document.getElementById("searchQuery");
    const eventTypeSel = document.getElementById("filterEventType");
    const severitySel = document.getElementById("filterSeverity");
    const protocolSel = document.getElementById("filterProtocol");
    const alertsOnlyCheck = document.getElementById("checkAlertsOnly");
    const btnReset = document.getElementById("btnResetFilters");
    const btnRefresh = document.getElementById("btnRefreshEvents");
    const btnPrev = document.getElementById("btnPrevPage");
    const btnNext = document.getElementById("btnNextPage");

    // Pre-populate filters from URL query parameters if present
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get("alert_only") === "true") {
      if (alertsOnlyCheck) alertsOnlyCheck.checked = true;
      if (eventTypeSel) eventTypeSel.value = "alert";
    }
    if (urlParams.get("severity") && severitySel) {
      severitySel.value = urlParams.get("severity");
    }
    if (urlParams.get("event_type") && eventTypeSel) {
      eventTypeSel.value = urlParams.get("event_type");
    }
    if (urlParams.get("q") && searchInput) {
      searchInput.value = urlParams.get("q");
    }

    let debounceTimer = null;
    if (searchInput) {
      searchInput.addEventListener("input", () => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
          currentPage = 1;
          loadEvents();
        }, 300);
      });
    }

    if (eventTypeSel) {
      eventTypeSel.addEventListener("change", () => {
        currentPage = 1;
        loadEvents();
      });
    }

    if (severitySel) {
      severitySel.addEventListener("change", () => {
        currentPage = 1;
        loadEvents();
      });
    }

    if (protocolSel) {
      protocolSel.addEventListener("change", () => {
        currentPage = 1;
        loadEvents();
      });
    }

    if (alertsOnlyCheck) {
      alertsOnlyCheck.addEventListener("change", () => {
        currentPage = 1;
        loadEvents();
      });
    }

    if (btnReset) {
      btnReset.addEventListener("click", () => {
        if (searchInput) searchInput.value = "";
        if (eventTypeSel) eventTypeSel.value = "";
        if (severitySel) severitySel.value = "";
        if (protocolSel) protocolSel.value = "";
        if (alertsOnlyCheck) alertsOnlyCheck.checked = false;
        currentPage = 1;
        loadEvents();
      });
    }

    if (btnRefresh) {
      btnRefresh.addEventListener("click", () => {
        loadEvents();
      });
    }

    if (btnPrev) {
      btnPrev.addEventListener("click", () => {
        if (currentPage > 1) {
          currentPage--;
          loadEvents();
        }
      });
    }

    if (btnNext) {
      btnNext.addEventListener("click", () => {
        if (currentPage < totalPages) {
          currentPage++;
          loadEvents();
        }
      });
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    bindEvents();
    loadEvents();
  });
})();

