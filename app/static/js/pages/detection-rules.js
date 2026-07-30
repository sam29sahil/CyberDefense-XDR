/* ==========================================================================
   detection-rules.js — page module for app/detection-rules.html
   Depends on: DETECTION_RULES_DATA (data/detection-rules-data.js),
   XDRTable (core/datatable.js), modal-helpers.js
   ========================================================================== */

   (function () {
    let data = DETECTION_RULES_DATA.map((r) => ({ ...r }));
  
    const STATUS_LABEL = { active: "Active", disabled: "Disabled", testing: "Testing" };
  
    function renderSummary() {
      document.getElementById("ruleCountSummary").textContent =
        `${data.length} rules · ${data.filter((r) => r.status === "active").length} active · ${data.filter((r) => r.status === "disabled").length} disabled`;
    }
  
    const categorySel = document.getElementById("filterCategory");
    [...new Set(DETECTION_RULES_DATA.map((r) => r.category))].sort().forEach((c) =>
      categorySel.insertAdjacentHTML("beforeend", `<option value="${c}">${c}</option>`));
  
    const columns = [
      { key: "name", label: "Rule", sortable: true,
        render: (r) => `<a href="rule-details.html?id=${r.id}" style="color:var(--text);font-weight:600;text-decoration:none;">${XDRUtils.escapeHtml(r.name)}</a>
          <div class="text-xs text-muted" style="margin-top:2px;">${r.category}</div>` },
      { key: "severity", label: "Severity", sortable: true, render: (r) => XDRUtils.severityBadge(r.severity) },
      { key: "mitreId", label: "MITRE Technique", sortable: true,
        render: (r) => `<span class="mitre-chip">${r.mitreId} <span class="tname">${r.mitreName}</span></span>` },
      { key: "status", label: "Status", sortable: true,
        render: (r) => `<span class="status-pill st-${r.status}"><span class="dot"></span>${STATUS_LABEL[r.status]}</span>` },
      { key: "triggers30d", label: "Triggers (30d)", sortable: true, render: (r) => `<span class="cell-mono">${r.triggers30d}</span>` },
      { key: "createdAt", label: "Created", sortable: true, render: (r) => XDRUtils.formatTime(r.createdAt) },
      { key: "modifiedAt", label: "Modified", sortable: true, render: (r) => XDRUtils.formatTime(r.modifiedAt) },
      { key: "actions", label: "", sortable: false,
        render: (r) => `<div class="row-actions">
            <a href="rule-details.html?id=${r.id}" class="btn btn-icon btn-ghost btn-sm" title="View"><i class="bi bi-eye"></i></a>
            <a href="create-rule.html?id=${r.id}" class="btn btn-icon btn-ghost btn-sm" title="Edit"><i class="bi bi-pencil"></i></a>
            <button class="btn btn-icon btn-ghost btn-sm toggle-btn" data-id="${r.id}" title="${r.status === "disabled" ? "Enable" : "Disable"}"><i class="bi bi-power"></i></button>
            <button class="btn btn-icon btn-ghost btn-sm dup-btn" data-id="${r.id}" title="Duplicate"><i class="bi bi-copy"></i></button>
            <button class="btn btn-icon btn-ghost btn-sm delete-btn" data-id="${r.id}" title="Delete"><i class="bi bi-trash"></i></button>
          </div>` },
    ];
  
    const table = new XDRTable({
      tableEl: document.getElementById("rulesTable"),
      searchInput: document.getElementById("ruleSearch"),
      paginationEl: document.getElementById("rulesPagination"),
      data,
      pageSize: 10,
      searchKeys: ["name", "category", "mitreId", "mitreName"],
      columns,
      onRowsChange: wireRowActions,
    });
  
    function wireRowActions() {
      document.querySelectorAll(".toggle-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
          const row = data.find((r) => r.id === btn.dataset.id);
          row.status = row.status === "disabled" ? "active" : "disabled";
          renderSummary();
          table.render();
          if (window.showToast) window.showToast({ type: row.status === "active" ? "success" : "warning", title: row.status === "active" ? "Rule enabled" : "Rule disabled", msg: row.name });
        });
      });
      document.querySelectorAll(".dup-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
          const row = data.find((r) => r.id === btn.dataset.id);
          const clone = { ...row, id: `DET-${Math.floor(Math.random() * 9000 + 1000)}`, name: `${row.name} (Copy)`, status: "testing", triggers30d: 0 };
          data.unshift(clone);
          table.data = data;
          renderSummary();
          table.render();
          if (window.showToast) window.showToast({ type: "success", title: "Rule duplicated", msg: `${clone.name} created in Testing status.` });
        });
      });
      document.querySelectorAll(".delete-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
          const row = data.find((r) => r.id === btn.dataset.id);
          document.getElementById("deleteRuleName").textContent = row.name;
          document.getElementById("confirmDeleteRuleBtn").dataset.id = row.id;
          window.xdrOpenModal("deleteRuleModal");
        });
      });
    }
  
    document.getElementById("confirmDeleteRuleBtn").addEventListener("click", () => {
      const id = document.getElementById("confirmDeleteRuleBtn").dataset.id;
      const row = data.find((r) => r.id === id);
      data = data.filter((r) => r.id !== id);
      table.data = data;
      renderSummary();
      table.render();
      if (window.showToast && row) window.showToast({ type: "danger", title: "Rule deleted", msg: row.name });
    });
  
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
      document.getElementById("ruleSearch").value = "";
      ["filterSev", "filterStatus", "filterCategory"].forEach((id) => document.getElementById(id).value = "");
      table.state.query = "";
      table.setFilter(null);
    });
  
    renderSummary();
  })();
  