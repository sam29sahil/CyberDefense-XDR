/* ==========================================================================
   investigations.js — page module for app/investigations.html
   Depends on: CASES_DATA (data/cases-data.js), XDRTable (core/datatable.js)
   ========================================================================== */

   (function () {
    const data = CASES_DATA;
    const now = new Date("2026-07-24T09:58:00Z");
  
    const STATUS_LABEL = { open: "Open", in_progress: "In Progress", pending_review: "Pending Review", closed: "Closed" };
    const STATUS_BADGE = { open: "badge-info", in_progress: "badge-warning", pending_review: "badge-neutral", closed: "badge-success" };
  
    function slaState(c) {
      if (c.status === "closed") return "ok";
      const hoursLeft = (new Date(c.slaDue).getTime() - now.getTime()) / 3600000;
      if (hoursLeft < 0) return "breach";
      if (hoursLeft < 4) return "warn";
      return "ok";
    }
    function slaLabel(c) {
      if (c.status === "closed") return "Met";
      const hoursLeft = Math.round((new Date(c.slaDue).getTime() - now.getTime()) / 3600000);
      return hoursLeft < 0 ? `${Math.abs(hoursLeft)}h overdue` : `${hoursLeft}h left`;
    }
  
    document.getElementById("caseCountSummary").textContent = `${data.length} cases`;
    document.getElementById("statOpen").textContent = data.filter((c) => c.status === "open").length;
    document.getElementById("statProgress").textContent = data.filter((c) => c.status === "in_progress").length;
    document.getElementById("statSlaRisk").textContent = data.filter((c) => slaState(c) !== "ok").length;
    document.getElementById("statClosed").textContent = data.filter((c) => c.status === "closed").length;
  
    const ownerSel = document.getElementById("filterOwner");
    [...new Set(data.map((c) => c.owner))].sort().forEach((o) => ownerSel.insertAdjacentHTML("beforeend", `<option value="${o}">${o}</option>`));
  
    const columns = [
      { key: "title", label: "Case", sortable: true,
        render: (r) => `<a href="case-details.html?id=${r.id}" style="color:var(--text);font-weight:600;text-decoration:none;">${XDRUtils.escapeHtml(r.title)}</a>
          <div class="text-xs text-muted" style="margin-top:2px;">${r.id} · ${r.relatedAlerts.length} related alerts</div>` },
      { key: "priority", label: "Priority", sortable: true, render: (r) => `<span class="priority-pill p-${r.priority}">${r.priority}</span>` },
      { key: "status", label: "Status", sortable: true, render: (r) => `<span class="badge ${STATUS_BADGE[r.status]}">${STATUS_LABEL[r.status]}</span>` },
      { key: "slaDue", label: "SLA", sortable: true, render: (r) => `<span class="sla-badge sla-${slaState(r)}"><i class="bi bi-stopwatch"></i> ${slaLabel(r)}</span>` },
      { key: "owner", label: "Owner", sortable: true,
        render: (r) => `<div class="avatar-row"><span class="avatar avatar-sm">${r.ownerInitials}</span><span class="text-sm">${r.owner}</span></div>` },
      { key: "createdAt", label: "Created", sortable: true, render: (r) => XDRUtils.formatTime(r.createdAt) },
    ];
  
    const table = new XDRTable({
      tableEl: document.getElementById("casesTable"),
      searchInput: document.getElementById("caseSearch"),
      paginationEl: document.getElementById("casesPagination"),
      data,
      pageSize: 10,
      searchKeys: ["title", "owner", "id"],
      columns,
    });
  
    function applyFilters() {
      const priority = document.getElementById("filterPriority").value;
      const status = document.getElementById("filterStatus").value;
      const owner = document.getElementById("filterOwner").value;
      table.setFilter((row) =>
        (!priority || row.priority === priority) &&
        (!status || row.status === status) &&
        (!owner || row.owner === owner)
      );
    }
    ["filterPriority", "filterStatus", "filterOwner"].forEach((id) => document.getElementById(id).addEventListener("change", applyFilters));
    document.getElementById("clearFilters").addEventListener("click", () => {
      document.getElementById("caseSearch").value = "";
      ["filterPriority", "filterStatus", "filterOwner"].forEach((id) => document.getElementById(id).value = "");
      table.state.query = "";
      table.setFilter(null);
    });
  })();
  