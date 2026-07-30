/* ==========================================================================
   incident-list.js — page module for app/incident-list.html
   Depends on: INCIDENTS_DATA (data/incident-data.js), XDRTable
   ========================================================================== */

   (function () {
    let data = INCIDENTS_DATA.map((i) => ({ ...i }));
    const STATUS_LABEL = { open: "Open", in_progress: "In Progress", resolved: "Resolved", closed: "Closed" };
  
    function renderSummary() {
      document.getElementById("incidentCountSummary").textContent =
        `${data.length} incidents · ${data.filter((i) => i.status === "open" || i.status === "in_progress").length} open`;
    }
  
    const categories = [...new Set(INCIDENTS_DATA.map((i) => i.category))].sort();
    const categorySel = document.getElementById("filterCategory");
    categories.forEach((c) => categorySel.insertAdjacentHTML("beforeend", `<option value="${c}">${c}</option>`));
    const newCatSel = document.getElementById("newIncCategory");
    newCatSel.innerHTML = categories.map((c) => `<option>${c}</option>`).join("");
  
    const columns = [
      { key: "title", label: "Incident", sortable: true,
        render: (r) => `<a href="incident-details.html?id=${r.id}" style="color:var(--text);font-weight:600;text-decoration:none;">${XDRUtils.escapeHtml(r.title)}</a>
          <div class="text-xs text-muted" style="margin-top:2px;">${r.category} · ${r.id}</div>` },
      { key: "severity", label: "Severity", sortable: true, render: (r) => XDRUtils.severityBadge(r.severity) },
      { key: "status", label: "Status", sortable: true, render: (r) => `<span class="status-pill st-${r.status}"><span class="dot"></span>${STATUS_LABEL[r.status]}</span>` },
      { key: "affectedAssets", label: "Assets", sortable: false, render: (r) => `<span class="text-sm">${r.affectedAssets.length} affected</span>` },
      { key: "assignedAnalyst", label: "Assigned", sortable: true },
      { key: "dueDate", label: "Due", sortable: true, render: (r) => XDRUtils.formatTime(r.dueDate) },
      { key: "actions", label: "", sortable: false,
        render: (r) => `<div class="row-actions"><a href="incident-details.html?id=${r.id}" class="btn btn-icon btn-ghost btn-sm" title="View"><i class="bi bi-eye"></i></a></div>` },
    ];
  
    const table = new XDRTable({
      tableEl: document.getElementById("incidentsTable"),
      searchInput: document.getElementById("incidentSearch"),
      paginationEl: document.getElementById("incidentsPagination"),
      data,
      pageSize: 10,
      searchKeys: ["title", "category", "id"],
      columns,
    });
    table.state.sortKey = "createdAt";
    table.state.sortDir = -1;
  
    function applyFilters() {
      const sev = document.getElementById("filterSev").value;
      const status = document.getElementById("filterStatus").value;
      const category = document.getElementById("filterCategory").value;
      table.setFilter((row) =>
        (!sev || row.severity === sev) &&
        (!status || row.status === status) &&
        (!category || row.category === category)
      );
    }
    ["filterSev", "filterStatus", "filterCategory"].forEach((id) => document.getElementById(id).addEventListener("change", applyFilters));
    document.getElementById("clearFilters").addEventListener("click", () => {
      document.getElementById("incidentSearch").value = "";
      ["filterSev", "filterStatus", "filterCategory"].forEach((id) => document.getElementById(id).value = "");
      table.state.query = "";
      table.setFilter(null);
    });
  
    document.getElementById("createIncidentConfirm").addEventListener("click", () => {
      const title = document.getElementById("newIncTitle").value.trim();
      if (!title) {
        if (window.showToast) window.showToast({ type: "warning", title: "Title required", msg: "Give the incident a short descriptive title." });
        return;
      }
      const sev = document.getElementById("newIncSeverity").value;
      const prioMap = { critical: "P1", high: "P2", medium: "P3", low: "P4" };
      const now = new Date().toISOString();
      const newInc = {
        id: `INC-${Math.floor(Math.random() * 9000 + 1000)}`, title,
        description: document.getElementById("newIncDesc").value.trim() || "No description provided.",
        category: document.getElementById("newIncCategory").value,
        severity: sev, priority: prioMap[sev], status: "open",
        createdAt: now, updatedAt: now,
        dueDate: new Date(Date.now() + 3 * 86400000).toISOString(),
        assignedAnalyst: "Unassigned", assignedTeam: "SOC Tier 2",
        affectedAssets: [], relatedAlerts: [], relatedVulnerabilities: [], relatedIOCs: [], evidence: [],
        resolutionNotes: "", mitigation: "", lessonsLearned: "", recoverySteps: [],
      };
      data.unshift(newInc);
      table.data = data;
      renderSummary();
      table.render();
      document.getElementById("newIncTitle").value = "";
      document.getElementById("newIncDesc").value = "";
      if (window.showToast) window.showToast({ type: "success", title: "Incident created", msg: `${newInc.id} — ${title}` });
    });
  
    renderSummary();
  })();
  