/* ==========================================================================
   assets.js — page module for Asset Management (app/assets.html)
   Depends on: ASSETS_DATA (data/assets-data.js), XDRTable (core/datatable.js)
   ========================================================================== */

   (function () {
    const TYPE_ICON = {
      "Server": "bi-hdd-rack", "Database": "bi-database", "Workstation": "bi-pc-display",
      "Firewall": "bi-bricks", "Router": "bi-router", "Domain Controller": "bi-diagram-2",
      "Mail Gateway": "bi-envelope", "Container Host": "bi-boxes", "Load Balancer": "bi-signpost-split",
    };
  
    function statusDot(status) {
      return `<span class="d-flex align-items-center gap-2">
        <span class="dot dot-${status} ${status === 'online' ? 'dot-pulse' : ''}"></span>
        ${status === 'online' ? 'Online' : 'Offline'}
      </span>`;
    }
  
    const columns = [
      { key: "select", label: `<input type="checkbox" id="selectAll" class="form-check-input">`, sortable: false,
        render: (r) => `<input type="checkbox" class="form-check-input row-check" data-id="${r.id}">` },
      { key: "name", label: "Asset", sortable: true,
        render: (r) => `<a href="asset-details.html?id=${r.id}" class="d-flex align-items-center gap-2" style="color:var(--text);font-weight:600;">
            <i class="bi ${TYPE_ICON[r.type] || 'bi-hdd'} text-muted"></i> ${r.name}
          </a>
          <div class="text-xs text-muted" style="margin-left:22px;">${r.type} · ${r.env}</div>` },
      { key: "ip", label: "IP Address", sortable: true, render: (r) => `<span class="cell-mono">${r.ip}</span>` },
      { key: "os", label: "OS / Platform", sortable: false, render: (r) => `<span class="text-sm">${r.os}</span>` },
      { key: "owner", label: "Owner", sortable: true },
      { key: "status", label: "Status", sortable: true, render: (r) => statusDot(r.status) },
      { key: "risk", label: "Risk", sortable: true,
        render: (r) => `<div class="d-flex align-items-center gap-2" style="min-width:110px;">
            <div class="xdr-progress" style="flex:1;"><div class="xdr-progress-bar bar-${r.sev === 'critical' || r.sev === 'high' ? 'danger' : r.sev === 'medium' ? 'warning' : 'success'}" style="width:${r.risk}%"></div></div>
            <span class="text-xs text-muted">${r.risk}</span>
          </div>` },
      { key: "sev", label: "Severity", sortable: true, render: (r) => XDRUtils.severityBadge(r.sev) },
      { key: "actions", label: "", sortable: false,
        render: (r) => `<div class="row-actions">
            <a href="asset-details.html?id=${r.id}" class="btn btn-icon btn-ghost btn-sm" title="View details"><i class="bi bi-eye"></i></a>
            <button class="btn btn-icon btn-ghost btn-sm" title="Scan now"><i class="bi bi-search"></i></button>
          </div>` },
    ];
  
    const table = new XDRTable({
      tableEl: document.getElementById("assetsTable"),
      searchInput: document.getElementById("assetSearch"),
      paginationEl: document.getElementById("assetsPagination"),
      data: ASSETS_DATA,
      pageSize: 8,
      searchKeys: ["name", "ip", "owner"],
      columns,
    });
  
    function applyFilters() {
      const type = document.getElementById("filterType").value;
      const sev = document.getElementById("filterSev").value;
      const status = document.getElementById("filterStatus").value;
      table.setFilter((row) =>
        (!type || row.type === type) &&
        (!sev || row.sev === sev) &&
        (!status || row.status === status)
      );
      wireRowChecks();
    }
  
    ["filterType", "filterSev", "filterStatus"].forEach((id) =>
      document.getElementById(id).addEventListener("change", applyFilters)
    );
  
    document.getElementById("clearFilters").addEventListener("click", () => {
      document.getElementById("assetSearch").value = "";
      document.getElementById("filterType").value = "";
      document.getElementById("filterSev").value = "";
      document.getElementById("filterStatus").value = "";
      table.state.query = "";
      table.setFilter(null);
    });
  
    // Bulk select — re-wired after every render since rows are re-created
    function wireRowChecks() {
      const bulkBar = document.getElementById("bulkBar");
      const bulkCount = document.getElementById("bulkCount");
      const rowChecks = () => document.querySelectorAll(".row-check");
  
      function updateBulkBar() {
        const checked = document.querySelectorAll(".row-check:checked").length;
        bulkCount.textContent = checked;
        bulkBar.classList.toggle("active", checked > 0);
      }
  
      rowChecks().forEach((cb) => cb.addEventListener("change", updateBulkBar));
  
      const selectAll = document.getElementById("selectAll");
      if (selectAll) {
        selectAll.addEventListener("change", () => {
          rowChecks().forEach((cb) => (cb.checked = selectAll.checked));
          updateBulkBar();
        });
      }
    }
  
    table.onRowsChange = wireRowChecks;
    wireRowChecks();
  })();
  