/* ==========================================================================
   users.js — page module for app/users.html
   Depends on: USERS_DATA, ROLES_DATA (data/users-data.js), XDRTable
   ========================================================================== */

   (function () {
    let data = USERS_DATA.map((u) => ({ ...u }));
    const STATUS_LABEL = { active: "Active", inactive: "Inactive", locked: "Locked" };
  
    function renderSummary() {
      document.getElementById("userCountSummary").textContent =
        `${data.length} users · ${data.filter((u) => u.status === "active").length} active · ${data.filter((u) => u.status === "locked").length} locked`;
    }
  
    const roleSel = document.getElementById("filterRole");
    ROLES_DATA.forEach((r) => roleSel.insertAdjacentHTML("beforeend", `<option value="${r.id}">${r.name}</option>`));
    const newUserRoleSel = document.getElementById("newUserRole");
    newUserRoleSel.innerHTML = ROLES_DATA.map((r) => `<option value="${r.id}">${r.name}</option>`).join("");
  
    function initials(name) { return name.split(" ").map((p) => p[0]).slice(0, 2).join("").toUpperCase(); }
  
    const columns = [
      { key: "name", label: "User", sortable: true,
        render: (r) => `<div class="d-flex align-items-center gap-2">
            <span class="user-avatar">${initials(r.name)}</span>
            <div><a href="user-details.html?id=${r.id}" style="color:var(--text);font-weight:600;text-decoration:none;">${XDRUtils.escapeHtml(r.name)}</a>
            <div class="text-xs text-muted">${r.email}</div></div>
          </div>` },
      { key: "roleName", label: "Role", sortable: true, render: (r) => `<span class="badge badge-neutral">${r.roleName}</span>` },
      { key: "department", label: "Department", sortable: true },
      { key: "status", label: "Status", sortable: true, render: (r) => `<span class="status-pill st-${r.status}"><span class="dot"></span>${STATUS_LABEL[r.status]}</span>` },
      { key: "mfaEnabled", label: "MFA", sortable: true, render: (r) => `<span class="mfa-badge ${r.mfaEnabled ? "on" : "off"}"><i class="bi bi-shield-${r.mfaEnabled ? "check" : "x"}"></i> ${r.mfaEnabled ? "On" : "Off"}</span>` },
      { key: "lastLogin", label: "Last Login", sortable: true, render: (r) => XDRUtils.formatTime(r.lastLogin) },
      { key: "actions", label: "", sortable: false,
        render: (r) => `<div class="row-actions">
            <a href="user-details.html?id=${r.id}" class="btn btn-icon btn-ghost btn-sm" title="View"><i class="bi bi-eye"></i></a>
            <button class="btn btn-icon btn-ghost btn-sm toggle-btn" data-id="${r.id}" title="${r.status === "locked" ? "Unlock" : "Lock"}"><i class="bi bi-${r.status === "locked" ? "unlock" : "lock"}"></i></button>
          </div>` },
    ];
  
    const table = new XDRTable({
      tableEl: document.getElementById("usersTable"),
      searchInput: document.getElementById("userSearch"),
      paginationEl: document.getElementById("usersPagination"),
      data,
      pageSize: 10,
      searchKeys: ["name", "email", "department"],
      columns,
      onRowsChange: wireRowActions,
    });
  
    function wireRowActions() {
      document.querySelectorAll(".toggle-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
          const row = data.find((u) => u.id === btn.dataset.id);
          row.status = row.status === "locked" ? "active" : "locked";
          renderSummary();
          table.render();
          if (window.showToast) window.showToast({ type: row.status === "locked" ? "danger" : "success", title: row.status === "locked" ? "User locked" : "User unlocked", msg: row.name });
        });
      });
    }
  
    function applyFilters() {
      const role = document.getElementById("filterRole").value;
      const status = document.getElementById("filterStatus").value;
      table.setFilter((row) => (!role || row.roleId === role) && (!status || row.status === status));
    }
    ["filterRole", "filterStatus"].forEach((id) => document.getElementById(id).addEventListener("change", applyFilters));
    document.getElementById("clearFilters").addEventListener("click", () => {
      document.getElementById("userSearch").value = "";
      ["filterRole", "filterStatus"].forEach((id) => document.getElementById(id).value = "");
      table.state.query = "";
      table.setFilter(null);
    });
  
    document.getElementById("addUserConfirm").addEventListener("click", () => {
      const name = document.getElementById("newUserName").value.trim();
      const email = document.getElementById("newUserEmail").value.trim();
      if (!name || !email) {
        if (window.showToast) window.showToast({ type: "warning", title: "Name and email required" });
        return;
      }
      const roleId = document.getElementById("newUserRole").value;
      const role = ROLES_DATA.find((r) => r.id === roleId);
      const now = new Date().toISOString();
      data.unshift({
        id: `USR-${Math.floor(Math.random() * 900 + 100)}`, name, email,
        roleId, roleName: role.name, department: document.getElementById("newUserDept").value,
        status: "active", mfaEnabled: false, lastLogin: now, createdAt: now, sessions: 0,
      });
      document.getElementById("newUserName").value = "";
      document.getElementById("newUserEmail").value = "";
      table.data = data;
      renderSummary();
      table.render();
      if (window.showToast) window.showToast({ type: "success", title: "User added", msg: name });
    });
  
    renderSummary();
  })();
  