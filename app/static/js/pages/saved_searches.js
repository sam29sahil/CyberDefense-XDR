/* ==========================================================================
   saved-searches.js — page module for app/saved-searches.html
   Depends on: SAVED_SEARCHES_DATA (data/saved-searches-data.js),
   XDRTable (core/datatable.js), modal-helpers.js
   ========================================================================== */

   (function () {
    // In-memory copy so delete/toggle actions can mutate without touching the source data module.
    let data = SAVED_SEARCHES_DATA.map((s) => ({ ...s }));
  
    function renderStats() {
      document.getElementById("statTotal").textContent = data.length;
      document.getElementById("statShared").textContent = data.filter((s) => s.scope === "Team").length;
      document.getElementById("statAlerting").textContent = data.filter((s) => s.alerting).length;
      document.getElementById("statPinned").textContent = data.filter((s) => s.pinned).length;
    }
  
    const columns = [
      { key: "name", label: "Search", sortable: true,
        render: (r) => `<div style="font-weight:600;color:var(--text);">${r.pinned ? '<i class="bi bi-bookmark-star-fill text-warning" style="font-size:11px;"></i> ' : ""}${r.name}</div>
          <div class="text-xs text-muted" style="margin-top:2px;">${r.description}</div>
          <code class="saved-search-query" style="margin-top:6px;">${XDRUtils.escapeHtml(r.query)}</code>` },
      { key: "owner", label: "Owner", sortable: true },
      { key: "scope", label: "Scope", sortable: true,
        render: (r) => `<span class="badge ${r.scope === "Team" ? "badge-info" : "badge-neutral"}">${r.scope}</span>` },
      { key: "alerting", label: "Alerting", sortable: true,
        render: (r) => r.alerting ? `<span class="badge badge-warning"><i class="bi bi-bell-fill"></i> On</span>` : `<span class="badge badge-neutral">Off</span>` },
      { key: "hits", label: "Last Run", sortable: true,
        render: (r) => `<div class="text-sm">${r.hits} hits</div><div class="text-xs text-muted">${r.lastRun}</div>` },
      { key: "actions", label: "", sortable: false,
        render: (r) => `<div class="row-actions">
            <a href="log-explorer.html" class="btn btn-icon btn-ghost btn-sm" title="Run in Log Explorer"><i class="bi bi-play-fill"></i></a>
            <button class="btn btn-icon btn-ghost btn-sm pin-btn" data-id="${r.id}" title="${r.pinned ? "Unpin" : "Pin to dashboard"}"><i class="bi bi-bookmark${r.pinned ? "-star-fill" : ""}"></i></button>
            <button class="btn btn-icon btn-ghost btn-sm delete-btn" data-id="${r.id}" title="Delete"><i class="bi bi-trash"></i></button>
          </div>` },
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
          const row = data.find((s) => s.id === btn.dataset.id);
          row.pinned = !row.pinned;
          renderStats();
          table.render();
          if (window.showToast) window.showToast({ type: "success", title: row.pinned ? "Pinned to dashboard" : "Unpinned", msg: row.name });
        });
      });
      document.querySelectorAll(".delete-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
          const row = data.find((s) => s.id === btn.dataset.id);
          document.getElementById("deleteSearchName").textContent = row.name;
          document.getElementById("confirmDeleteBtn").dataset.id = row.id;
          window.xdrOpenModal("deleteSearchModal");
        });
      });
    }
  
    document.getElementById("confirmDeleteBtn").addEventListener("click", () => {
      const id = document.getElementById("confirmDeleteBtn").dataset.id;
      const row = data.find((s) => s.id === id);
      data = data.filter((s) => s.id !== id);
      table.data = data;
      renderStats();
      table.render();
      if (window.showToast && row) window.showToast({ type: "danger", title: "Search deleted", msg: row.name });
    });
  
    function applyFilters() {
      const scope = document.getElementById("filterScope").value;
      const alerting = document.getElementById("filterAlerting").value;
      table.setFilter((row) =>
        (!scope || row.scope === scope) &&
        (!alerting || (alerting === "on" ? row.alerting : !row.alerting))
      );
      wireRowActions();
    }
  
    ["filterScope", "filterAlerting"].forEach((id) => document.getElementById(id).addEventListener("change", applyFilters));
    document.getElementById("clearFilters").addEventListener("click", () => {
      document.getElementById("searchFilter").value = "";
      document.getElementById("filterScope").value = "";
      document.getElementById("filterAlerting").value = "";
      table.state.query = "";
      table.setFilter(null);
    });
  
    table.onRowsChange = wireRowActions;
    renderStats();
    wireRowActions();
  })();
  