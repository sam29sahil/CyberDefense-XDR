/* ==========================================================================
   alerts.js — page module for app/alerts.html
   Depends on: ALERTS_DATA, ANALYSTS_DATA, XDRTable (core/datatable.js)
   ========================================================================== */

   (function () {
    let data = ALERTS_DATA.map((a) => ({ ...a }));
  
    const STATUS_BADGE = { open: "badge-info", investigating: "badge-warning", closed: "badge-success" };
  
    function renderSummary() {
      document.getElementById("alertCountSummary").textContent =
        `${data.length} alerts · ${data.filter((a) => a.status === "open").length} open · ${data.filter((a) => a.status === "investigating").length} investigating`;
    }
  
    const analystSel = document.getElementById("filterAnalyst");
    ANALYSTS_DATA.forEach((a) => analystSel.insertAdjacentHTML("beforeend", `<option value="${a.name}">${a.name}</option>`));
    const assignSel = document.getElementById("assignAnalystSelect");
    ANALYSTS_DATA.forEach((a) => assignSel.insertAdjacentHTML("beforeend", `<option value="${a.name}" data-initials="${a.initials}">${a.name} — ${a.tier}</option>`));
  
    const columns = [
      { key: "priority", label: "Priority", sortable: true, render: (r) => `<span class="priority-pill p-${r.priority}">${r.priority}</span>` },
      { key: "title", label: "Alert", sortable: true,
        render: (r) => `<a href="alert-details.html?id=${r.id}" style="color:var(--text);font-weight:600;text-decoration:none;">${XDRUtils.escapeHtml(r.title)}</a>
          <div class="text-xs text-muted" style="margin-top:2px;">${r.host} · ${r.asset}</div>` },
      { key: "severity", label: "Severity", sortable: true, render: (r) => XDRUtils.severityBadge(r.severity) },
      { key: "status", label: "Status", sortable: true, render: (r) => `<span class="badge ${STATUS_BADGE[r.status]}">${r.status}</span>` },
      { key: "source", label: "Source", sortable: true },
      { key: "assignedAnalyst", label: "Assigned", sortable: true,
        render: (r) => r.assignedAnalyst
          ? `<div class="avatar-row"><span class="avatar avatar-sm">${r.assignedInitials}</span><span class="text-sm">${r.assignedAnalyst}</span></div>`
          : `<span class="text-muted text-sm">Unassigned</span>` },
      { key: "ts", label: "Time", sortable: true, render: (r) => `<span class="cell-mono text-sm">${XDRUtils.formatTime(r.ts)}</span>` },
      { key: "actions", label: "", sortable: false,
        render: (r) => `<div class="row-actions">
            <a href="alert-details.html?id=${r.id}" class="btn btn-icon btn-ghost btn-sm" title="View"><i class="bi bi-eye"></i></a>
            <button class="btn btn-icon btn-ghost btn-sm assign-btn" data-id="${r.id}" title="Assign"><i class="bi bi-person-plus"></i></button>
            <button class="btn btn-icon btn-ghost btn-sm investigate-btn" data-id="${r.id}" title="Investigate" ${r.status === "closed" ? "disabled" : ""}><i class="bi bi-search"></i></button>
            <button class="btn btn-icon btn-ghost btn-sm close-btn" data-id="${r.id}" title="Close" ${r.status === "closed" ? "disabled" : ""}><i class="bi bi-check-circle"></i></button>
          </div>` },
    ];
  
    const table = new XDRTable({
      tableEl: document.getElementById("alertsTable"),
      searchInput: document.getElementById("alertSearch"),
      paginationEl: document.getElementById("alertsPagination"),
      data,
      pageSize: 10,
      searchKeys: ["title", "host", "asset", "id"],
      columns,
      onRowsChange: wireRowActions,
    });
    table.state.sortKey = "ts";
    table.state.sortDir = -1;
  
    let activeAlertId = null;
  
    function wireRowActions() {
      document.querySelectorAll(".assign-btn").forEach((btn) => btn.addEventListener("click", () => {
        const row = data.find((a) => a.id === btn.dataset.id);
        activeAlertId = row.id;
        document.getElementById("assignAlertTitle").textContent = row.title;
        assignSel.value = row.assignedAnalyst || ANALYSTS_DATA[0].name;
        window.xdrOpenModal("assignModal");
      }));
      document.querySelectorAll(".investigate-btn").forEach((btn) => btn.addEventListener("click", () => {
        const row = data.find((a) => a.id === btn.dataset.id);
        if (row.status === "open") row.status = "investigating";
        table.render();
        if (window.showToast) window.showToast({ type: "info", title: "Investigation started", msg: row.title });
        setTimeout(() => { window.location.href = `alert-details.html?id=${row.id}`; }, 500);
      }));
      document.querySelectorAll(".close-btn").forEach((btn) => btn.addEventListener("click", () => {
        const row = data.find((a) => a.id === btn.dataset.id);
        activeAlertId = row.id;
        document.getElementById("closeAlertTitle").textContent = row.title;
        window.xdrOpenModal("closeAlertModal");
      }));
    }
  
    document.getElementById("confirmAssignBtn").addEventListener("click", () => {
      const row = data.find((a) => a.id === activeAlertId);
      if (!row) return;
      const opt = assignSel.options[assignSel.selectedIndex];
      row.assignedAnalyst = assignSel.value;
      row.assignedInitials = opt.dataset.initials;
      if (row.status === "open") row.status = "investigating";
      table.render();
      if (window.showToast) window.showToast({ type: "success", title: "Alert assigned", msg: `${row.title} → ${row.assignedAnalyst}` });
    });
  
    document.getElementById("confirmCloseBtn").addEventListener("click", () => {
      const row = data.find((a) => a.id === activeAlertId);
      if (!row) return;
      row.status = "closed";
      table.render();
      renderSummary();
      if (window.showToast) window.showToast({ type: "danger", title: "Alert closed", msg: `${row.title} — ${document.getElementById("closeResolutionSelect").value}` });
      document.getElementById("closeNotes").value = "";
    });
  
    function applyFilters() {
      const priority = document.getElementById("filterPriority").value;
      const sev = document.getElementById("filterSev").value;
      const status = document.getElementById("filterStatus").value;
      const analyst = document.getElementById("filterAnalyst").value;
      table.setFilter((row) =>
        (!priority || row.priority === priority) &&
        (!sev || row.severity === sev) &&
        (!status || row.status === status) &&
        (!analyst || (analyst === "unassigned" ? !row.assignedAnalyst : row.assignedAnalyst === analyst))
      );
    }
    ["filterPriority", "filterSev", "filterStatus", "filterAnalyst"].forEach((id) => document.getElementById(id).addEventListener("change", applyFilters));
    document.getElementById("clearFilters").addEventListener("click", () => {
      document.getElementById("alertSearch").value = "";
      ["filterPriority", "filterSev", "filterStatus", "filterAnalyst"].forEach((id) => document.getElementById(id).value = "");
      table.state.query = "";
      table.setFilter(null);
    });
  
    document.getElementById("exportBtn").addEventListener("click", () => {
      const header = "id,ts,priority,severity,status,title,host,asset,source,assignedAnalyst\n";
      const body = data.map((r) => [r.id, r.ts, r.priority, r.severity, r.status, `"${r.title.replace(/"/g, '""')}"`, r.host, r.asset, r.source, r.assignedAnalyst || ""].join(",")).join("\n");
      const blob = new Blob([header + body], { type: "text/csv" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = "alert-center-export.csv";
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
      if (window.showToast) window.showToast({ type: "success", title: "Export ready", msg: "alert-center-export.csv downloaded." });
    });
  
    renderSummary();
  })();
  