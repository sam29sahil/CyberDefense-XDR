/* ==========================================================================
   permissions.js — page module for app/permissions.html
   Depends on: ROLES_DATA (data/users-data.js)
   Permission categories are small and static, so the matrix definition
   lives inline here rather than in a separate data/*.js file.
   ========================================================================== */

   (function () {
    const CATEGORIES = [
      "View Dashboard", "Manage Alerts", "Manage Incidents", "Manage Detection Rules",
      "Manage Vulnerability Scans", "Manage Threat Intelligence", "Generate Reports",
      "Manage Users", "Manage Roles & Permissions", "View Audit Logs", "Manage Integrations", "System Settings",
    ];
  
    // Seed matrix: category -> { roleId: boolean }. Administrator has everything.
    const GRANTS = {
      "ROLE-1": CATEGORIES.map(() => true),
      "ROLE-2": [true, true, true, true, true, true, true, true, false, true, false, false],
      "ROLE-3": [true, true, true, false, false, false, true, false, false, false, false, false],
      "ROLE-4": [true, false, false, true, false, true, true, false, false, false, false, false],
      "ROLE-5": [true, false, false, false, false, false, true, false, false, true, false, false],
      "ROLE-6": [true, false, false, false, false, false, false, false, false, false, false, false],
    };
  
    const roles = ROLES_DATA;
    const matrix = {};
    CATEGORIES.forEach((cat, ci) => {
      matrix[cat] = {};
      roles.forEach((r) => { matrix[cat][r.id] = GRANTS[r.id] ? GRANTS[r.id][ci] : false; });
    });
  
    document.getElementById("permMatrixHead").innerHTML =
      `<th>Capability</th>` + roles.map((r) => `<th>${r.name}</th>`).join("");
  
    function render() {
      document.getElementById("permMatrixBody").innerHTML = CATEGORIES.map((cat) => `
        <tr><td>${cat}</td>${roles.map((r) => `
          <td><input type="checkbox" class="perm-check" data-cat="${cat}" data-role="${r.id}" ${matrix[cat][r.id] ? "checked" : ""} ${r.id === "ROLE-1" ? "disabled title='Administrator always has full access'" : ""}></td>`).join("")}</tr>`).join("");
  
      document.querySelectorAll(".perm-check").forEach((cb) => cb.addEventListener("change", (e) => {
        matrix[e.target.dataset.cat][e.target.dataset.role] = e.target.checked;
      }));
    }
    render();
  
    document.getElementById("saveChangesBtn").addEventListener("click", () => {
      if (window.showToast) window.showToast({ type: "success", title: "Permissions saved", msg: "Changes apply to all users with the affected roles." });
    });
  })();
  