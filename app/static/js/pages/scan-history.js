/* ==========================================================================
   scan-history.js — page module for app/scan-history.html
   Depends on: SCANS_DATA (data/scan-data.js), XDRTable
   ========================================================================== */

   (function () {
    const data = SCANS_DATA;
    const STATUS_LABEL = { completed: "Completed", running: "Running", queued: "Queued" };
  
    document.getElementById("scanCountSummary").textContent = `${data.length} scans · ${data.filter((s) => s.status === "completed").length} completed`;
  
    const columns = [
      { key: "name", label: "Scan", sortable: true,
        render: (r) => `<a href="scan-details.html?id=${r.id}" style="color:var(--text);font-weight:600;text-decoration:none;">${r.name}</a>
          <div class="text-xs text-muted">${r.targets.length} targets · initiated by ${r.initiatedBy}</div>` },
      { key: "type", label: "Type", sortable: true },
      { key: "status", label: "Status", sortable: true, render: (r) => `<span class="status-pill st-${r.status}"><span class="dot"></span>${STATUS_LABEL[r.status]}</span>` },
      { key: "startedAt", label: "Started", sortable: true, render: (r) => XDRUtils.formatTime(r.startedAt) },
      { key: "durationMin", label: "Duration", sortable: true, render: (r) => r.durationMin ? `${r.durationMin} min` : "—" },
      { key: "findingIds", label: "Findings", sortable: false, render: (r) => r.findingIds.length },
      { key: "riskScore", label: "Risk Score", sortable: true, render: (r) => `<span class="cell-mono">${r.riskScore}</span>` },
      { key: "actions", label: "", sortable: false,
        render: (r) => `<div class="row-actions"><a href="scan-details.html?id=${r.id}" class="btn btn-icon btn-ghost btn-sm" title="View"><i class="bi bi-eye"></i></a></div>` },
    ];
  
    const table = new XDRTable({
      tableEl: document.getElementById("scansTable"),
      searchInput: document.getElementById("scanSearch"),
      paginationEl: document.getElementById("scansPagination"),
      data, pageSize: 10,
      searchKeys: ["name", "type", "initiatedBy"],
      columns,
    });
    table.state.sortKey = "startedAt";
    table.state.sortDir = -1;
  
    function applyFilters() {
      const status = document.getElementById("filterStatus").value;
      const type = document.getElementById("filterType").value;
      table.setFilter((row) => (!status || row.status === status) && (!type || row.type === type));
    }
    ["filterStatus", "filterType"].forEach((id) => document.getElementById(id).addEventListener("change", applyFilters));
    document.getElementById("clearFilters").addEventListener("click", () => {
      document.getElementById("scanSearch").value = "";
      document.getElementById("filterStatus").value = "";
      document.getElementById("filterType").value = "";
      table.state.query = "";
      table.setFilter(null);
    });
  })();
  