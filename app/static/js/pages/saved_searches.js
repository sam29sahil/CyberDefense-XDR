/* ==========================================================================
   saved-searches.js — page module for app/templates/siem/saved_searches.html
   Integrates with backend /siem/api/saved-searches.
   ========================================================================== */

(function () {
  let data = typeof SAVED_SEARCHES_DATA !== "undefined" ? SAVED_SEARCHES_DATA.map((s) => ({ ...s })) : [];

  function renderStats() {
    const totalEl = document.getElementById("statTotal");
    const sharedEl = document.getElementById("statShared");
    const alertEl = document.getElementById("statAlerting");
    const pinEl = document.getElementById("statPinned");

    if (totalEl) totalEl.textContent = data.length;
    if (sharedEl) sharedEl.textContent = data.filter((s) => s.scope === "Team").length;
    if (alertEl) alertEl.textContent = data.filter((s) => s.alerting).length;
    if (pinEl) pinEl.textContent = data.filter((s) => s.pinned).length;
  }

  const columns = [
    {
      key: "name",
      label: "Search",
      sortable: true,
      render: (r) => `<div style="font-weight:600;color:var(--text);">${r.pinned ? '<i class="bi bi-bookmark-star-fill text-warning" style="font-size:11px;"></i> ' : ""}${XDRUtils.escapeHtml(r.name)}</div>
        <div class="text-xs text-muted" style="margin-top:2px;">${XDRUtils.escapeHtml(r.description || "")}</div>
        <code class="saved-search-query" style="margin-top:6px;">${XDRUtils.escapeHtml(r.query || "")}</code>`,
    },
    {
      key: "owner",
      label: "Owner",
      sortable: true,
      render: (r) => XDRUtils.escapeHtml(r.owner || "Analyst"),
    },
    {
      key: "scope",
      label: "Scope",
      sortable: true,
      render: (r) => `<span class="badge ${r.scope === "Team" ? "badge-info" : "badge-neutral"}">${r.scope}</span>`,
    },
    {
      key: "alerting",
      label: "Alerting",
      sortable: true,
      render: (r) => r.alerting
        ? `<span class="badge badge-warning"><i class="bi bi-bell-fill"></i> On</span>`
        : `<span class="badge badge-neutral">Off</span>`,
    },
    {
      key: "hits",
      label: "Last Run",
      sortable: true,
      render: (r) => `<div class="text-sm">${r.hits || 0} hits</div><div class="text-xs text-muted">${r.lastRun || "recently"}</div>`,
    },
    {
      key: "actions",
      label: "",
      sortable: false,
      render: (r) => `<div class="row-actions">
          <a href="/siem/log-explorer?query=${encodeURIComponent(r.query)}" class="btn btn-icon btn-ghost btn-sm" title="Run in Log Explorer"><i class="bi bi-play-fill"></i></a>
          <button class="btn btn-icon btn-ghost btn-sm pin-btn" data-id="${r.id}" title="${r.pinned ? "Unpin" : "Pin to dashboard"}"><i class="bi bi-bookmark${r.pinned ? "-star-fill" : ""}"></i></button>
          <button class="btn btn-icon btn-ghost btn-sm delete-btn" data-id="${r.id}" title="Delete"><i class="bi bi-trash"></i></button>
        </div>`,
    },
  ];

  const table = new XDRTable({
    tableEl: document.getElementById("searchesTable"),
    searchInput: document.getElementById("searchFilter"),
    paginationEl: document.getElementById("searchesPagination"),
    data,
    pageSize: 8,
    searchKeys: ["name", "owner", "query", "description"],
    columns,
  });

  function wireRowActions() {
    document.querySelectorAll(".pin-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const sid = btn.dataset.id;
        const row = data.find((s) => s.id === sid);
        if (!row) return;

        // Optimistic UI update
        row.pinned = !row.pinned;
        renderStats();
        table.render();

        fetch(`/siem/api/saved-searches/${encodeURIComponent(sid)}/pin`, { method: "POST" })
          .then((res) => res.json())
          .then((resp) => {
            if (window.showToast) {
              window.showToast({
                type: "success",
                title: resp.pinned ? "Pinned to dashboard" : "Unpinned",
                msg: row.name,
              });
            }
          })
          .catch(() => {
            // Revert on error
            row.pinned = !row.pinned;
            renderStats();
            table.render();
          });
      });
    });

    document.querySelectorAll(".delete-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const sid = btn.dataset.id;
        const row = data.find((s) => s.id === sid);
        if (!row) return;

        document.getElementById("deleteSearchName").textContent = row.name;
        document.getElementById("confirmDeleteBtn").dataset.id = sid;
        if (window.xdrOpenModal) window.xdrOpenModal("deleteSearchModal");
      });
    });
  }

  const confirmDeleteBtn = document.getElementById("confirmDeleteBtn");
  if (confirmDeleteBtn) {
    confirmDeleteBtn.addEventListener("click", () => {
      const sid = confirmDeleteBtn.dataset.id;
      const row = data.find((s) => s.id === sid);

      fetch(`/siem/api/saved-searches/${encodeURIComponent(sid)}`, { method: "DELETE" })
        .then((res) => res.json())
        .then((resp) => {
          if (resp.success) {
            data = data.filter((s) => s.id !== sid);
            table.data = data;
            renderStats();
            table.render();
            if (window.showToast && row) {
              window.showToast({ type: "danger", title: "Search deleted", msg: row.name });
            }
          }
        })
        .catch(() => {
          if (window.showToast) window.showToast({ type: "warning", title: "Could not delete search" });
        });
    });
  }

  function applyFilters() {
    const scope = document.getElementById("filterScope")?.value || "";
    const alerting = document.getElementById("filterAlerting")?.value || "";
    table.setFilter((row) =>
      (!scope || row.scope === scope) &&
      (!alerting || (alerting === "on" ? row.alerting : !row.alerting))
    );
    wireRowActions();
  }

  ["filterScope", "filterAlerting"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener("change", applyFilters);
  });

  const clearBtn = document.getElementById("clearFilters");
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      const searchEl = document.getElementById("searchFilter");
      if (searchEl) searchEl.value = "";
      const scopeEl = document.getElementById("filterScope");
      if (scopeEl) scopeEl.value = "";
      const alertEl = document.getElementById("filterAlerting");
      if (alertEl) alertEl.value = "";
      table.state.query = "";
      table.setFilter(null);
    });
  }

  table.onRowsChange = wireRowActions;

  // Load from backend API
  function loadSearches() {
    fetch("/siem/api/saved-searches")
      .then((res) => res.json())
      .then((payload) => {
        if (payload && payload.success && Array.isArray(payload.data) && payload.data.length > 0) {
          data = payload.data;
          table.data = data;
          renderStats();
          table.render();
        } else {
          renderStats();
          wireRowActions();
        }
      })
      .catch(() => {
        renderStats();
        wireRowActions();
      });
  }

  loadSearches();
})();