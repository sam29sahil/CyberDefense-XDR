/**
 * CyberDefense XDR
 * Notification Center Controller
 */

(function () {
  let currentPage = 1;
  const perPage = 15;
  let searchTimeout = null;

  const listContainer = document.getElementById("notifListContainer");
  const resultCounter = document.getElementById("notifResultCounter");
  const pageIndicator = document.getElementById("notifPageIndicator");
  const paginationNav = document.getElementById("notifPaginationNav");

  const statUnread = document.getElementById("statUnread");
  const statTotal = document.getElementById("statTotal");
  const statCritical = document.getElementById("statCritical");
  const statSystem = document.getElementById("statSystem");

  const filterCategory = document.getElementById("filterCategory");
  const filterSeverity = document.getElementById("filterSeverity");
  const filterReadStatus = document.getElementById("filterReadStatus");
  const notifSearch = document.getElementById("notifSearch");

  function getSeverityBadgeClass(sev) {
    switch ((sev || "").toLowerCase()) {
      case "critical": return "badge-critical-soft";
      case "high": return "badge-high-soft";
      case "medium": return "badge-medium-soft";
      case "low": return "badge-low-soft";
      default: return "badge-info-soft";
    }
  }

  function getCategoryIcon(cat) {
    switch ((cat || "").toUpperCase()) {
      case "ALERT": return "bi-bell";
      case "INCIDENT": return "bi-shield-exclamation";
      case "IDS": return "bi-diagram-3";
      case "SCANNER": return "bi-search";
      case "SOAR": return "bi-lightning-charge";
      case "SECURITY": return "bi-shield-lock";
      default: return "bi-info-circle";
    }
  }

  async function loadStats() {
    try {
      const res = await fetch("/notifications/api/stats");
      if (res.ok) {
        const data = await res.json();
        if (data.success && data.stats) {
          if (statUnread) statUnread.textContent = data.stats.unread_count || 0;
          if (statTotal) statTotal.textContent = data.stats.total_active || 0;
          if (statCritical) statCritical.textContent = data.stats.critical_high_count || 0;
          if (statSystem) statSystem.textContent = data.stats.system_count || 0;
        }
      }
    } catch (e) {
      console.error("Failed to load notification stats:", e);
    }
  }

  async function loadNotifications(page = 1) {
    currentPage = page;
    if (listContainer) {
      listContainer.innerHTML = `
        <div class="text-center text-muted py-5">
          <div class="spinner-border spinner-border-sm text-primary mb-2" role="status"></div>
          <div>Loading notifications...</div>
        </div>`;
    }

    const params = new URLSearchParams({
      page: currentPage,
      per_page: perPage,
    });

    if (filterCategory && filterCategory.value) params.append("category", filterCategory.value);
    if (filterSeverity && filterSeverity.value) params.append("severity", filterSeverity.value);
    if (filterReadStatus && filterReadStatus.value !== "") params.append("is_read", filterReadStatus.value);
    if (notifSearch && notifSearch.value.trim()) params.append("search", notifSearch.value.trim());

    try {
      const res = await fetch(`/notifications/api?${params.toString()}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      if (!data.success) throw new Error(data.error || "Failed to load notifications");

      renderNotifications(data.notifications || []);
      renderPagination(data.page, data.pages, data.total);
      loadStats();
    } catch (err) {
      if (listContainer) {
        listContainer.innerHTML = `
          <div class="text-center text-danger py-4">
            <i class="bi bi-exclamation-triangle fs-3 d-block mb-2"></i>
            Failed to load notifications: ${err.message}
          </div>`;
      }
    }
  }

  function renderNotifications(items) {
    if (!listContainer) return;

    if (!items || items.length === 0) {
      listContainer.innerHTML = `
        <div class="text-center text-muted py-5">
          <i class="bi bi-inbox fs-2 d-block mb-2 text-secondary"></i>
          <div>No notifications found.</div>
          <div class="small">Your inbox is clear of matching alerts.</div>
        </div>`;
      return;
    }

    let html = "";
    items.forEach((item) => {
      const unreadClass = item.is_read ? "" : `unread sev-${item.severity}`;
      const sevBadge = getSeverityBadgeClass(item.severity);
      const catIcon = getCategoryIcon(item.category);
      const formattedDate = item.created_at ? new Date(item.created_at).toLocaleString() : "";
      const dedupBadge = item.occurrence_count > 1 
        ? `<span class="badge bg-secondary-subtle text-light border border-secondary ms-1">×${item.occurrence_count}</span>` 
        : "";

      html += `
        <div class="notif-item p-3 d-flex flex-column flex-md-row align-items-start justify-content-between gap-3 ${unreadClass}" data-id="${item.notification_id}">
          <div class="d-flex align-items-start gap-3 flex-grow-1">
            <div class="fs-4 text-muted pt-1">
              <i class="bi ${catIcon}"></i>
            </div>
            <div class="flex-grow-1">
              <div class="d-flex flex-wrap align-items-center gap-2 mb-1">
                <span class="badge ${sevBadge} text-uppercase px-2 py-0" style="font-size:0.7rem;">${item.severity}</span>
                <span class="badge bg-secondary-subtle text-light border border-secondary px-2 py-0" style="font-size:0.7rem;">${item.category}</span>
                ${dedupBadge}
                <a href="/notifications/details/${item.notification_id}" class="fw-semibold text-light text-decoration-none mb-0">
                  ${escapeHtml(item.title)}
                </a>
              </div>
              <p class="text-muted small mb-2 text-break" style="line-height:1.4;">${escapeHtml(item.message)}</p>
              <div class="d-flex flex-wrap align-items-center gap-3 text-muted small" style="font-size:0.75rem;">
                <span><i class="bi bi-clock me-1"></i>${formattedDate}</span>
                <span><i class="bi bi-geo me-1"></i>${escapeHtml(item.source)}</span>
                ${item.resource_id ? `<span class="code-font text-secondary">#${escapeHtml(item.resource_id)}</span>` : ""}
              </div>
            </div>
          </div>
          <div class="d-flex align-items-center gap-2 align-self-end align-self-md-center flex-shrink-0">
            ${item.action_url ? `
              <a href="${item.action_url}" class="btn btn-outline-primary btn-sm py-1 px-2" style="font-size:0.8rem;" title="Navigate to resource">
                <i class="bi bi-arrow-right-short"></i>Open
              </a>` : ""}
            ${!item.is_read ? `
              <button class="btn btn-outline-secondary btn-sm py-1 px-2 btn-mark-read" data-id="${item.notification_id}" style="font-size:0.8rem;" title="Mark as read">
                <i class="bi bi-check2"></i>
              </button>` : ""}
            <button class="btn btn-outline-danger btn-sm py-1 px-2 btn-dismiss-notif" data-id="${item.notification_id}" style="font-size:0.8rem;" title="Dismiss">
              <i class="bi bi-x-lg"></i>
            </button>
          </div>
        </div>`;
    });

    listContainer.innerHTML = html;

    // Attach listeners to row action buttons
    listContainer.querySelectorAll(".btn-mark-read").forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        e.stopPropagation();
        const id = btn.getAttribute("data-id");
        await markNotificationRead(id);
      });
    });

    listContainer.querySelectorAll(".btn-dismiss-notif").forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        e.stopPropagation();
        const id = btn.getAttribute("data-id");
        await dismissNotification(id);
      });
    });
  }

  function renderPagination(page, pages, total) {
    if (resultCounter) {
      resultCounter.textContent = `Total: ${total} records`;
    }
    if (pageIndicator) {
      pageIndicator.textContent = `Page ${page || 1} of ${Math.max(1, pages || 1)}`;
    }
    if (!paginationNav) return;

    if (!pages || pages <= 1) {
      paginationNav.innerHTML = "";
      return;
    }

    let navHtml = "";
    navHtml += `<li class="page-item ${page <= 1 ? "disabled" : ""}">
      <button class="page-link" data-page="${page - 1}">&laquo;</button>
    </li>`;

    for (let i = 1; i <= pages; i++) {
      if (i === 1 || i === pages || (i >= page - 2 && i <= page + 2)) {
        navHtml += `<li class="page-item ${i === page ? "active" : ""}">
          <button class="page-link" data-page="${i}">${i}</button>
        </li>`;
      } else if (i === page - 3 || i === page + 3) {
        navHtml += `<li class="page-item disabled"><span class="page-link">...</span></li>`;
      }
    }

    navHtml += `<li class="page-item ${page >= pages ? "disabled" : ""}">
      <button class="page-link" data-page="${page + 1}">&raquo;</button>
    </li>`;

    paginationNav.innerHTML = navHtml;

    paginationNav.querySelectorAll(".page-link").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.preventDefault();
        const target = parseInt(btn.getAttribute("data-page"), 10);
        if (target && target >= 1 && target <= pages && target !== page) {
          loadNotifications(target);
        }
      });
    });
  }

  async function markNotificationRead(id) {
    try {
      const res = await fetch(`/notifications/api/${id}/read`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      if (res.ok) {
        loadNotifications(currentPage);
      }
    } catch (err) {
      console.error("Failed to mark as read:", err);
    }
  }

  async function dismissNotification(id) {
    try {
      const res = await fetch(`/notifications/api/${id}/dismiss`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      if (res.ok) {
        loadNotifications(currentPage);
      }
    } catch (err) {
      console.error("Failed to dismiss notification:", err);
    }
  }

  async function markAllRead() {
    try {
      const res = await fetch("/notifications/api/read-all", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      if (res.ok) {
        loadNotifications(currentPage);
      }
    } catch (err) {
      console.error("Failed to mark all as read:", err);
    }
  }

  // Preferences Modal Handling
  async function loadPreferences() {
    try {
      const res = await fetch("/notifications/api/preferences");
      if (res.ok) {
        const data = await res.json();
        if (data.success && data.preferences) {
          const p = data.preferences;
          const prefEmail = document.getElementById("prefEmail");
          const prefWebhook = document.getElementById("prefWebhook");
          const prefMinSeverity = document.getElementById("prefMinSeverity");
          const prefQuietEnabled = document.getElementById("prefQuietEnabled");
          const prefQuietFrom = document.getElementById("prefQuietFrom");
          const prefQuietTo = document.getElementById("prefQuietTo");

          if (prefEmail) prefEmail.checked = !!p.email_enabled;
          if (prefWebhook) prefWebhook.checked = !!p.webhook_enabled;
          if (prefMinSeverity) prefMinSeverity.value = p.min_severity || "medium";
          if (prefQuietEnabled) prefQuietEnabled.checked = !!p.quiet_hours_enabled;
          if (prefQuietFrom) prefQuietFrom.value = p.quiet_hours_from || "20:00";
          if (prefQuietTo) prefQuietTo.value = p.quiet_hours_to || "07:00";
        }
      }
    } catch (e) {
      console.error("Failed to load preferences:", e);
    }
  }

  async function savePreferences() {
    const payload = {
      email_enabled: document.getElementById("prefEmail")?.checked ?? true,
      webhook_enabled: document.getElementById("prefWebhook")?.checked ?? false,
      min_severity: document.getElementById("prefMinSeverity")?.value || "medium",
      quiet_hours_enabled: document.getElementById("prefQuietEnabled")?.checked ?? false,
      quiet_hours_from: document.getElementById("prefQuietFrom")?.value || "20:00",
      quiet_hours_to: document.getElementById("prefQuietTo")?.value || "07:00",
    };

    try {
      const res = await fetch("/notifications/api/preferences", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        const modalEl = document.getElementById("preferencesModal");
        if (modalEl && window.bootstrap) {
          const modal = bootstrap.Modal.getInstance(modalEl);
          if (modal) modal.hide();
        }
        loadStats();
      }
    } catch (err) {
      console.error("Failed to save preferences:", err);
    }
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function init() {
    loadNotifications(1);

    document.getElementById("btnRefreshNotifs")?.addEventListener("click", () => loadNotifications(currentPage));
    document.getElementById("btnMarkAllRead")?.addEventListener("click", markAllRead);
    document.getElementById("btnSavePreferences")?.addEventListener("click", savePreferences);
    document.getElementById("btnOpenPreferences")?.addEventListener("click", loadPreferences);

    filterCategory?.addEventListener("change", () => loadNotifications(1));
    filterSeverity?.addEventListener("change", () => loadNotifications(1));
    filterReadStatus?.addEventListener("change", () => loadNotifications(1));

    notifSearch?.addEventListener("input", () => {
      clearTimeout(searchTimeout);
      searchTimeout = setTimeout(() => loadNotifications(1), 350);
    });

    document.getElementById("btnResetFilters")?.addEventListener("click", () => {
      if (filterCategory) filterCategory.value = "";
      if (filterSeverity) filterSeverity.value = "";
      if (filterReadStatus) filterReadStatus.value = "";
      if (notifSearch) notifSearch.value = "";
      loadNotifications(1);
    });
  }

  document.addEventListener("DOMContentLoaded", init);
})();

