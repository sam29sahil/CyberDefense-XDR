/* ==========================================================================
   activity.js — page module for app/activity.html
   Depends on: ACTIVITY_DATA (data/users-data.js), XDRTable
   ========================================================================== */

   (function () {
    const data = ACTIVITY_DATA;
    document.getElementById("activitySummary").textContent =
      `${data.length} events · ${data.filter((a) => a.result === "failed").length} failed`;
  
    const columns = [
      { key: "ts", label: "Time", sortable: true, render: (r) => `<span class="cell-mono text-sm">${r.ts.replace("T", " ").replace("Z", "")}</span>` },
      { key: "userName", label: "User", sortable: true },
      { key: "label", label: "Action", sortable: true, render: (r) => `<span class="badge badge-neutral">${r.action}</span> ${r.label}` },
      { key: "resource", label: "Resource", sortable: true, render: (r) => `<span class="text-sm">${r.resource}</span>` },
      { key: "ip", label: "IP Address", sortable: true, render: (r) => `<span class="activity-ip">${r.ip}</span>` },
      { key: "result", label: "Result", sortable: true, render: (r) => `<span class="badge ${r.result === "success" ? "badge-success" : "badge-danger"}">${r.result}</span>` },
    ];
  
    const table = new XDRTable({
      tableEl: document.getElementById("activityTable"),
      searchInput: document.getElementById("activitySearch"),
      paginationEl: document.getElementById("activityPagination"),
      data,
      pageSize: 15,
      searchKeys: ["userName", "label", "resource", "action"],
      columns,
    });
    table.state.sortKey = "ts";
    table.state.sortDir = -1;
  
    function applyFilters() {
      const action = document.getElementById("filterAction").value;
      const result = document.getElementById("filterResult").value;
      table.setFilter((row) => (!action || row.action === action) && (!result || row.result === result));
    }
    ["filterAction", "filterResult"].forEach((id) => document.getElementById(id).addEventListener("change", applyFilters));
    document.getElementById("clearFilters").addEventListener("click", () => {
      document.getElementById("activitySearch").value = "";
      ["filterAction", "filterResult"].forEach((id) => document.getElementById(id).value = "");
      table.state.query = "";
      table.setFilter(null);
    });
  
    document.getElementById("exportBtn").addEventListener("click", () => {
      const header = "id,ts,userName,action,resource,ip,result\n";
      const body = data.map((r) => [r.id, r.ts, `"${r.userName}"`, r.action, `"${r.resource.replace(/"/g, '""')}"`, r.ip, r.result].join(",")).join("\n");
      const blob = new Blob([header + body], { type: "text/csv" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = "user-activity-export.csv";
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
      if (window.showToast) window.showToast({ type: "success", title: "Export ready", msg: "user-activity-export.csv downloaded." });
    });
  })();
  