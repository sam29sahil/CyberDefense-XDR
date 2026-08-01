/* ==========================================================================
   roles.js — page module for app/roles.html
   Depends on: ROLES_DATA, USERS_DATA (data/users-data.js), modal-helpers.js
   ========================================================================== */

   (function () {
    let roles = ROLES_DATA.map((r) => ({ ...r }));
    const ICONS = ["bi-shield-fill", "bi-person-badge", "bi-headset", "bi-binoculars", "bi-clipboard-check", "bi-eye"];
  
    function renderSummary() {
      document.getElementById("roleSummary").textContent = `${roles.length} roles · ${USERS_DATA.length} users assigned`;
    }
  
    function render() {
      document.getElementById("roleGrid").innerHTML = roles.map((r, i) => {
        const userCount = USERS_DATA.filter((u) => u.roleId === r.id).length;
        return `
        <div class="col-lg-4 col-md-6">
          <div class="role-card">
            <div class="d-flex align-items-center gap-3">
              <span class="role-icon-tile"><i class="bi ${ICONS[i % ICONS.length]}"></i></span>
              <div><h3 class="fs-inherit-md mb-0">${r.name}</h3><span class="text-xs text-muted">${userCount} user${userCount === 1 ? "" : "s"}</span></div>
            </div>
            <p class="text-muted text-sm mb-0">${r.description}</p>
            <div class="d-flex justify-content-between align-items-center mt-auto">
              <span class="badge badge-neutral">${r.permCount} permissions</span>
              <div class="row-actions">
                <a href="permissions.html" class="btn btn-icon btn-ghost btn-sm" title="Edit permissions"><i class="bi bi-shield-lock"></i></a>
                <button class="btn btn-icon btn-ghost btn-sm delete-role-btn" data-id="${r.id}" title="Delete role" ${userCount > 0 ? "disabled" : ""}><i class="bi bi-trash"></i></button>
              </div>
            </div>
          </div>
        </div>`;
      }).join("");
  
      document.querySelectorAll(".delete-role-btn").forEach((btn) => btn.addEventListener("click", () => {
        const role = roles.find((r) => r.id === btn.dataset.id);
        document.getElementById("deleteRoleName").textContent = role.name;
        document.getElementById("confirmDeleteRoleBtn").dataset.id = role.id;
        window.xdrOpenModal("deleteRoleModal");
      }));
    }
  
    document.getElementById("confirmDeleteRoleBtn").addEventListener("click", () => {
      const id = document.getElementById("confirmDeleteRoleBtn").dataset.id;
      const role = roles.find((r) => r.id === id);
      roles = roles.filter((r) => r.id !== id);
      render();
      renderSummary();
      if (window.showToast && role) window.showToast({ type: "danger", title: "Role deleted", msg: role.name });
    });
  
    document.getElementById("addRoleConfirm").addEventListener("click", () => {
      const name = document.getElementById("newRoleName").value.trim();
      if (!name) {
        if (window.showToast) window.showToast({ type: "warning", title: "Role name required" });
        return;
      }
      roles.push({
        id: `ROLE-${Math.floor(Math.random() * 900 + 100)}`, name,
        description: document.getElementById("newRoleDesc").value.trim() || "No description provided.",
        permCount: 0,
      });
      document.getElementById("newRoleName").value = "";
      document.getElementById("newRoleDesc").value = "";
      render();
      renderSummary();
      if (window.showToast) window.showToast({ type: "success", title: "Role created", msg: name });
    });
  
    renderSummary();
    render();
  })();
  