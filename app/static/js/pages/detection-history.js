/* ==========================================================================
   detection-history.js — page module for app/detection-history.html
   Depends on: DETECTION_HISTORY_DATA (data/detection-history-data.js),
   XDRTable (core/datatable.js)
   ========================================================================== */

   (function () {
    const data = DETECTION_HISTORY_DATA;
  
    document.getElementById("historyCountSummary").textContent = `${data.length} events across all active rules`;
    document.getElementById("statCritHigh").textContent = data.filter((h) => h.severity === "critical" || h.severity === "high").length;
    document.getElementById("statNew").textContent = data.filter((h) => h.status === "new").length;
    document.getElementById("statInvestigating").textContent = data.filter((h) => h.status === "investigating").length;
    document.getElementById("statResolved").textContent = data.filter((h) => h.status === "resolved").length;
  
    const sourceSel = document.getElementById("filterSource");
    [...new Set(data.map((h) => h.source))].sort().forEach((s) => sourceSel.insertAdjacentHTML("beforeend", `<option value="${s}">${s}</option>`));
  
    const STATUS_BADGE = {
      new: "badge-info", investigating: "badge-warning", resolved: "badge-success", false_positive: "badge-neutral",
    };
  
    const columns = [
      { key: "ts", label: "Time", sortable: true, render: (r) => `<span class="cell-mono">${r.ts.replace("T", " ").replace("Z", "")}</span>` },
      { key: "source", label: "Source", sortable: true },
      { key: "ruleName", label: "Rule", sortable: true,
        render: (r) => `<a href="rule-details.html?id=${r.ruleId}" style="color:var(--text);font-weight:600;text-decoration:none;">${XDRUtils.escapeHtml(r.ruleName)}</a>
          <div class="text-xs text-muted" style="margin-top:2px;"><span class="mitre-chip">${r.mitreId}</span></div>` },
      { key: "severity", label: "Severity", sortable: true, render: (r) => XDRUtils.severityBadge(r.severity) },
      { key: "host", label: "Hostname", sortable: true, render: (r) => `<span style="font-weight:600;">${r.host}</span>` },
      { key: "status", label: "Status", sortable: true,
        render: (r) => `<span class="badge ${STATUS_BADGE[r.status]}">${r.status.replace("_", " ")}</span>` },
    ];
  
    const table = new XDRTable({
      tableEl: document.getElementById("historyTable"),
      searchInput: document.getElementById("historySearch"),
      paginationEl: document.getElementById("historyPagination"),
      data,
      pageSize: 12,
      searchKeys: ["ruleName", "host", "source", "mitreId"],
      columns,
    });
    table.state.sortKey = "ts";
    table.state.sortDir = -1;
  
    function applyFilters() {
      const sev = document.getElementById("filterSev").value;
      const status = document.getElementById("filterStatus").value;
      const source = document.getElementById("filterSource").value;
      table.setFilter((row) =>
        (!sev || row.severity === sev) &&
        (!status || row.status === status) &&
        (!source || row.source === source)
      );
    }
    ["filterSev", "filterStatus", "filterSource"].forEach((id) => document.getElementById(id).addEventListener("change", applyFilters));
    document.getElementById("clearFilters").addEventListener("click", () => {
      document.getElementById("historySearch").value = "";
      ["filterSev", "filterStatus", "filterSource"].forEach((id) => document.getElementById(id).value = "");
      table.state.query = "";
      table.setFilter(null);
    });
  
    document.getElementById("exportBtn").addEventListener("click", () => {
      const header = "id,ts,ruleId,ruleName,severity,source,host,status,mitreId\n";
      const body = data.map((r) => [r.id, r.ts, r.ruleId, `"${r.ruleName.replace(/"/g, '""')}"`, r.severity, r.source, r.host, r.status, r.mitreId].join(",")).join("\n");
      const blob = new Blob([header + body], { type: "text/csv" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = "detection-history-export.csv";
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
      if (window.showToast) window.showToast({ type: "success", title: "Export ready", msg: "detection-history-export.csv downloaded." });
    });
  })();
  