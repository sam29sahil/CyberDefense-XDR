/* ==========================================================================
   ioc-feed.js — page module for app/ioc-feed.html
   Depends on: IOCS_DATA (data/threat-data.js), XDRTable
   ========================================================================== */

   (function () {
    let data = IOCS_DATA.map((i) => ({ ...i }));
  
    function renderSummary() {
      document.getElementById("iocCountSummary").textContent =
        `${data.length} indicators · ${data.filter((i) => i.status === "active").length} active · ${data.filter((i) => i.status === "blocked").length} blocked`;
    }
  
    const columns = [
      { key: "value", label: "Indicator", sortable: true,
        render: (r) => `<a href="ioc-details.html?id=${r.id}" class="ioc-value" style="text-decoration:none;">${XDRUtils.escapeHtml(r.value)}</a>
          <div class="text-xs text-muted" style="margin-top:2px;">${r.tags.join(", ")}</div>` },
      { key: "type", label: "Type", sortable: true, render: (r) => `<span class="ioc-type-chip">${r.type}</span>` },
      { key: "threatLevel", label: "Threat Level", sortable: true, render: (r) => XDRUtils.severityBadge(r.threatLevel) },
      { key: "confidence", label: "Confidence", sortable: true,
        render: (r) => { const c = r.confidence.toLowerCase(); return `<span class="confidence-dots conf-${c}"><span></span><span></span><span></span></span> <span class="text-sm">${r.confidence}</span>`; } },
      { key: "source", label: "Source", sortable: true, render: (r) => `<span class="text-sm">${r.source}</span>` },
      { key: "sightings", label: "Sightings", sortable: true, render: (r) => `<span class="cell-mono">${r.sightings}</span>` },
      { key: "status", label: "Status", sortable: true,
        render: (r) => `<span class="badge ${r.status === "active" ? "badge-warning" : r.status === "blocked" ? "badge-danger" : r.status === "whitelisted" ? "badge-success" : "badge-neutral"}">${r.status}</span>` },
      { key: "actions", label: "", sortable: false,
        render: (r) => `<div class="row-actions">
            <a href="ioc-details.html?id=${r.id}" class="btn btn-icon btn-ghost btn-sm" title="View"><i class="bi bi-eye"></i></a>
            <button class="btn btn-icon btn-ghost btn-sm block-btn" data-id="${r.id}" title="${r.status === "blocked" ? "Unblock" : "Block"}"><i class="bi bi-slash-circle"></i></button>
          </div>` },
    ];
  
    const table = new XDRTable({
      tableEl: document.getElementById("iocTable"),
      searchInput: document.getElementById("iocSearch"),
      paginationEl: document.getElementById("iocPagination"),
      data,
      pageSize: 12,
      searchKeys: ["value", "source", "tags"],
      columns,
      onRowsChange: wireRowActions,
    });
    table.state.sortKey = "lastSeen";
    table.state.sortDir = -1;
  
    function wireRowActions() {
      document.querySelectorAll(".block-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
          const row = data.find((i) => i.id === btn.dataset.id);
          row.status = row.status === "blocked" ? "active" : "blocked";
          renderSummary();
          table.render();
          if (window.showToast) window.showToast({ type: row.status === "blocked" ? "danger" : "success", title: row.status === "blocked" ? "Indicator blocked" : "Indicator unblocked", msg: row.value });
        });
      });
    }
  
    function applyFilters() {
      const type = document.getElementById("filterType").value;
      const level = document.getElementById("filterLevel").value;
      const status = document.getElementById("filterStatus").value;
      table.setFilter((row) =>
        (!type || row.type === type) &&
        (!level || row.threatLevel === level) &&
        (!status || row.status === status)
      );
    }
    ["filterType", "filterLevel", "filterStatus"].forEach((id) => document.getElementById(id).addEventListener("change", applyFilters));
    document.getElementById("clearFilters").addEventListener("click", () => {
      document.getElementById("iocSearch").value = "";
      ["filterType", "filterLevel", "filterStatus"].forEach((id) => document.getElementById(id).value = "");
      table.state.query = "";
      table.setFilter(null);
    });
  
    renderSummary();
  })();
  