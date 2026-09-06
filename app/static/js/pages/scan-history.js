/* ==========================================================================
   scan-history.js — page module for app/scan-history.html
   Depends on: SCANS_DATA (data/scan-data.js fallback), XDRTable
   ========================================================================== */

(function () {
  const STATUS_LABEL = { completed: "Completed", running: "Running", queued: "Queued", failed: "Failed" };

  function initTable(scans) {
    const summary = document.getElementById("scanCountSummary");
    if (summary) {
      const completedCount = scans.filter((s) => s.status === "completed").length;
      summary.textContent = `${scans.length} scan${scans.length === 1 ? "" : "s"} · ${completedCount} completed`;
    }

    const columns = [
      {
        key: "name",
        label: "Scan",
        sortable: true,
        render: (r) => `
          <a href="/scanner/details/${r.id}" style="color:var(--text);font-weight:600;text-decoration:none;">${r.name}</a>
          <div class="text-xs text-muted">${(r.targets || []).length} targets · initiated by ${r.initiatedBy || "Analyst"}</div>`,
      },
      { key: "type", label: "Type", sortable: true },
      {
        key: "status",
        label: "Status",
        sortable: true,
        render: (r) => `<span class="status-pill st-${r.status}"><span class="dot"></span>${STATUS_LABEL[r.status] || r.status}</span>`,
      },
      {
        key: "startedAt",
        label: "Started",
        sortable: true,
        render: (r) => (window.XDRUtils && XDRUtils.formatTime ? XDRUtils.formatTime(r.startedAt) : r.startedAt?.slice(0, 16).replace("T", " ") || "—"),
      },
      {
        key: "durationMin",
        label: "Duration",
        sortable: true,
        render: (r) => (r.durationMin ? `${r.durationMin} min` : "—"),
      },
      {
        key: "findingIds",
        label: "Findings",
        sortable: false,
        render: (r) => (r.findingIds ? r.findingIds.length : (r.findingsSummary?.critical || 0) + (r.findingsSummary?.high || 0) + (r.findingsSummary?.medium || 0) + (r.findingsSummary?.low || 0)),
      },
      {
        key: "riskScore",
        label: "Risk Score",
        sortable: true,
        render: (r) => `<span class="cell-mono">${r.riskScore || 0}</span>`,
      },
      {
        key: "actions",
        label: "",
        sortable: false,
        render: (r) => `
          <div class="row-actions">
            <a href="/scanner/details/${r.id}" class="btn btn-icon btn-ghost btn-sm" title="View"><i class="bi bi-eye"></i></a>
          </div>`,
      },
    ];

    const table = new XDRTable({
      tableEl: document.getElementById("scansTable"),
      searchInput: document.getElementById("scanSearch"),
      paginationEl: document.getElementById("scansPagination"),
      data: scans,
      pageSize: 10,
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

    ["filterStatus", "filterType"].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.addEventListener("change", applyFilters);
    });

    const clearBtn = document.getElementById("clearFilters");
    if (clearBtn) {
      clearBtn.addEventListener("click", () => {
        document.getElementById("scanSearch").value = "";
        document.getElementById("filterStatus").value = "";
        document.getElementById("filterType").value = "";
        table.state.query = "";
        table.setFilter(null);
      });
    }
  }

  // Load scans from API
  fetch("/scanner/api/scans")
    .then((res) => (res.ok ? res.json() : Promise.reject(res)))
    .then((data) => {
      if (data && Array.isArray(data.scans)) {
        initTable(data.scans);
      } else {
        initTable(typeof SCANS_DATA !== "undefined" ? SCANS_DATA : []);
      }
    })
    .catch(() => {
      initTable(typeof SCANS_DATA !== "undefined" ? SCANS_DATA : []);
    });
})();