/**
 * CyberDefense XDR
 * User Management & RBAC Interactive Controller
 * Real database-backed API integration for user provisioning, modifications,
 * granular role assignments, lock toggles, and safe deactivations.
 */

document.addEventListener("DOMContentLoaded", () => {
  // State
  let currentPage = 1;
  const perPage = 15;
  let currentSearch = "";
  let currentRole = "ALL";
  let currentStatus = "ALL";
  let totalUsers = 0;
  let totalPages = 1;
  let cachedUsers = [];

  // DOM Elements
  const tableBody = document.getElementById("usersTableBody");
  const statTotal = document.getElementById("statTotalUsers");
  const statActive = document.getElementById("statActiveUsers");
  const statLocked = document.getElementById("statLockedUsers");
  const statAdmin = document.getElementById("statAdminUsers");
  const paginationInfo = document.getElementById("paginationInfo");
  const paginationButtons = document.getElementById("paginationButtons");
  const searchInput = document.getElementById("userSearch");
  const roleSelect = document.getElementById("filterRole");
  const statusSelect = document.getElementById("filterStatus");
  const refreshBtn = document.getElementById("btnRefreshUsers");

  // Add User Form Elements
  const addUserForm = document.getElementById("addUserForm");
  const addUserError = document.getElementById("addUserErrorAlert");
  const addUserSpinner = document.getElementById("addUserSpinner");
  const addUserModalEl = document.getElementById("addUserModal");
  let addUserModal = null;
  if (addUserModalEl && typeof bootstrap !== "undefined") {
    addUserModal = new bootstrap.Modal(addUserModalEl);
  }

  // Edit User Form Elements
  const editUserForm = document.getElementById("editUserForm");
  const editUserError = document.getElementById("editUserErrorAlert");
  const editUserSpinner = document.getElementById("editUserSpinner");
  const editUserModalEl = document.getElementById("editUserModal");
  let editUserModal = null;
  if (editUserModalEl && typeof bootstrap !== "undefined") {
    editUserModal = new bootstrap.Modal(editUserModalEl);
  }

  // Delete User Modal Elements
  const deleteModalEl = document.getElementById("deleteUserModal");
  const deleteTargetName = document.getElementById("deleteUserTargetName");
  const deleteUserIdInput = document.getElementById("deleteUserId");
  const deleteConfirmBtn = document.getElementById("btnConfirmDeleteUser");
  const deleteSpinner = document.getElementById("deleteUserSpinner");
  let deleteModal = null;
  if (deleteModalEl && typeof bootstrap !== "undefined") {
    deleteModal = new bootstrap.Modal(deleteModalEl);
  }

  function getInitials(name) {
    if (!name) return "U";
    return name
      .split(" ")
      .map((n) => n[0])
      .slice(0, 2)
      .join("")
      .toUpperCase();
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // Fetch and render users
  async function loadUsers(page = 1) {
    currentPage = page;
    tableBody.innerHTML = `
      <tr>
        <td colspan="6" class="text-center py-4 text-muted">
          <div class="spinner-border spinner-border-sm text-primary me-2" role="status"></div>
          Retrieving directory identities...
        </td>
      </tr>
    `;

    try {
      const params = new URLSearchParams({
        page: currentPage,
        per_page: perPage,
      });
      if (currentSearch) params.set("search", currentSearch);
      if (currentRole && currentRole !== "ALL") params.set("role", currentRole);
      if (currentStatus && currentStatus !== "ALL") params.set("status", currentStatus);

      const res = await fetch(`/user-management/api/users?${params.toString()}`);
      if (!res.ok) {
        throw new Error(`Server returned HTTP ${res.status}`);
      }
      const data = await res.json();
      if (!data.success) {
        throw new Error(data.error || "Failed to load users");
      }

      cachedUsers = data.users || [];
      totalUsers = data.total || 0;
      totalPages = data.pages || 1;

      // Update telemetry counters
      if (data.stats) {
        statTotal.textContent = data.stats.total || 0;
        statActive.textContent = data.stats.active || 0;
        statLocked.textContent = (data.stats.locked || 0) + (data.stats.disabled || 0);
        statAdmin.textContent = data.stats.admins || 0;
      }

      renderTableRows(cachedUsers);
      renderPagination();
    } catch (err) {
      console.error("Error loading users:", err);
      tableBody.innerHTML = `
        <tr>
          <td colspan="6" class="text-center py-4 text-danger">
            <i class="bi bi-exclamation-octagon me-2"></i>Failed to load user accounts: ${escapeHtml(err.message)}
          </td>
        </tr>
      `;
    }
  }

  function renderTableRows(users) {
    if (!users.length) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="6" class="text-center py-5 text-muted">
            <i class="bi bi-people fs-1 d-block mb-2 text-secondary"></i>
            No users match the active criteria.
          </td>
        </tr>
      `;
      return;
    }

    const rows = users.map((u) => {
      const statusClass = `status-${u.status || "active"}`;
      const statusLabel = u.is_locked ? "Locked" : (u.status || "active").toUpperCase();
      const roleBadge = u.role_badge || "badge-secondary";

      return `
        <tr>
          <td>
            <div class="d-flex align-items-center gap-3">
              <div class="user-avatar text-primary fw-bold">${getInitials(u.full_name)}</div>
              <div>
                <a href="/user-management/users/${u.id}" class="text-light fw-bold text-decoration-none hover-underline">
                  ${escapeHtml(u.full_name)}
                </a>
                <div class="small text-muted">@${escapeHtml(u.username)}</div>
              </div>
            </div>
          </td>
          <td class="small text-muted cell-mono">${escapeHtml(u.email)}</td>
          <td>
            <span class="badge ${roleBadge} small">${escapeHtml(u.role_name || u.role)}</span>
          </td>
          <td>
            <span class="d-inline-flex align-items-center small">
              <span class="status-dot ${statusClass}"></span>
              <span class="text-light">${statusLabel}</span>
            </span>
          </td>
          <td class="small text-muted cell-mono">${u.last_login ? escapeHtml(u.last_login) : "Never"}</td>
          <td class="text-end">
            <div class="btn-group btn-group-sm">
              <a href="/user-management/users/${u.id}" class="btn btn-outline-secondary btn-sm" title="View Profile">
                <i class="bi bi-eye"></i>
              </a>
              <button type="button" class="btn btn-outline-secondary btn-sm btn-edit-user" data-id="${u.id}" title="Edit User">
                <i class="bi bi-pencil"></i>
              </button>
              <button type="button" class="btn btn-outline-secondary btn-sm btn-lock-toggle" data-id="${u.id}" data-status="${u.status}" title="${u.status === 'locked' ? 'Unlock Account' : 'Lock Account'}">
                <i class="bi bi-${u.status === 'locked' ? 'unlock' : 'lock'}"></i>
              </button>
              <button type="button" class="btn btn-outline-danger btn-sm btn-delete-user" data-id="${u.id}" data-name="${escapeHtml(u.full_name)}" title="Delete/Deactivate">
                <i class="bi bi-trash"></i>
              </button>
            </div>
          </td>
        </tr>
      `;
    });

    tableBody.innerHTML = rows.join("");
    wireActionButtons();
  }

  function renderPagination() {
    const startIdx = totalUsers === 0 ? 0 : (currentPage - 1) * perPage + 1;
    const endIdx = Math.min(currentPage * perPage, totalUsers);
    paginationInfo.textContent = `Showing ${startIdx} to ${endIdx} of ${totalUsers} users`;

    let html = "";
    if (totalPages > 1) {
      html += `
        <button class="btn btn-outline-secondary btn-sm ${currentPage === 1 ? "disabled" : ""}" data-page="${currentPage - 1}">
          <i class="bi bi-chevron-left"></i>
        </button>
      `;
      for (let p = 1; p <= totalPages; p++) {
        if (p === 1 || p === totalPages || (p >= currentPage - 1 && p <= currentPage + 1)) {
          html += `
            <button class="btn btn-sm ${p === currentPage ? "btn-primary" : "btn-outline-secondary"}" data-page="${p}">
              ${p}
            </button>
          `;
        } else if (p === currentPage - 2 || p === currentPage + 2) {
          html += `<span class="btn btn-sm btn-outline-secondary disabled">...</span>`;
        }
      }
      html += `
        <button class="btn btn-outline-secondary btn-sm ${currentPage === totalPages ? "disabled" : ""}" data-page="${currentPage + 1}">
          <i class="bi bi-chevron-right"></i>
        </button>
      `;
    }
    paginationButtons.innerHTML = html;

    paginationButtons.querySelectorAll("button[data-page]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const page = parseInt(btn.dataset.page, 10);
        if (page && page !== currentPage) {
          loadUsers(page);
        }
      });
    });
  }

  function wireActionButtons() {
    // Edit User Modal
    document.querySelectorAll(".btn-edit-user").forEach((btn) => {
      btn.addEventListener("click", () => {
        const userId = parseInt(btn.dataset.id, 10);
        const user = cachedUsers.find((u) => u.id === userId);
        if (!user) return;

        document.getElementById("editUserId").value = user.id;
        document.getElementById("editFirstName").value = user.first_name || "";
        document.getElementById("editLastName").value = user.last_name || "";
        document.getElementById("editEmail").value = user.email || "";
        document.getElementById("editCompany").value = user.company || "";
        document.getElementById("editRole").value = user.role || "SOC_ANALYST";
        document.getElementById("editStatus").value = user.status || "active";
        document.getElementById("editPassword").value = "";
        editUserError.classList.add("d-none");

        if (editUserModal) editUserModal.show();
      });
    });

    // Toggle Lock status
    document.querySelectorAll(".btn-lock-toggle").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const userId = parseInt(btn.dataset.id, 10);
        const currentSt = btn.dataset.status;
        const targetStatus = currentSt === "locked" ? "active" : "locked";

        try {
          const res = await fetch(`/user-management/api/users/${userId}`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status: targetStatus }),
          });
          const result = await res.json();
          if (!res.ok || !result.success) {
            throw new Error(result.error || "Failed to update status");
          }

          if (window.showToast) {
            window.showToast({
              type: targetStatus === "active" ? "success" : "warning",
              title: targetStatus === "active" ? "Account Unlocked" : "Account Locked",
              msg: result.message,
            });
          }
          loadUsers(currentPage);
        } catch (err) {
          alert(`Status change failed: ${err.message}`);
        }
      });
    });

    // Delete Modal
    document.querySelectorAll(".btn-delete-user").forEach((btn) => {
      btn.addEventListener("click", () => {
        const userId = parseInt(btn.dataset.id, 10);
        const userName = btn.dataset.name;

        deleteUserIdInput.value = userId;
        deleteTargetName.textContent = userName;
        if (deleteModal) deleteModal.show();
      });
    });
  }

  // Add User Form Submission
  if (addUserForm) {
    addUserForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      addUserError.classList.add("d-none");
      addUserSpinner.classList.remove("d-none");

      const payload = {
        first_name: document.getElementById("addFirstName").value.trim(),
        last_name: document.getElementById("addLastName").value.trim(),
        username: document.getElementById("addUsername").value.trim(),
        email: document.getElementById("addEmail").value.trim(),
        role: document.getElementById("addRole").value,
        status: document.getElementById("addStatus").value,
        company: document.getElementById("addCompany").value.trim(),
        password: document.getElementById("addPassword").value,
      };

      try {
        const res = await fetch("/user-management/api/users", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        const result = await res.json();
        if (!res.ok || !result.success) {
          throw new Error(result.error || "Failed to provision user");
        }

        if (addUserModal) addUserModal.hide();
        addUserForm.reset();

        if (window.showToast) {
          window.showToast({
            type: "success",
            title: "Identity Provisioned",
            msg: result.message,
          });
        }
        loadUsers(1);
      } catch (err) {
        addUserError.textContent = err.message;
        addUserError.classList.remove("d-none");
      } finally {
        addUserSpinner.classList.add("d-none");
      }
    });
  }

  // Edit User Form Submission
  if (editUserForm) {
    editUserForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      editUserError.classList.add("d-none");
      editUserSpinner.classList.remove("d-none");

      const userId = document.getElementById("editUserId").value;
      const payload = {
        first_name: document.getElementById("editFirstName").value.trim(),
        last_name: document.getElementById("editLastName").value.trim(),
        email: document.getElementById("editEmail").value.trim(),
        company: document.getElementById("editCompany").value.trim(),
        role: document.getElementById("editRole").value,
        status: document.getElementById("editStatus").value,
      };

      const pw = document.getElementById("editPassword").value;
      if (pw) {
        payload.password = pw;
      }

      try {
        const res = await fetch(`/user-management/api/users/${userId}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        const result = await res.json();
        if (!res.ok || !result.success) {
          throw new Error(result.error || "Failed to update user");
        }

        if (editUserModal) editUserModal.hide();

        if (window.showToast) {
          window.showToast({
            type: "success",
            title: "Identity Updated",
            msg: result.message,
          });
        }
        loadUsers(currentPage);
      } catch (err) {
        editUserError.textContent = err.message;
        editUserError.classList.remove("d-none");
      } finally {
        editUserSpinner.classList.add("d-none");
      }
    });
  }

  // Delete User Confirmation
  if (deleteConfirmBtn) {
    deleteConfirmBtn.addEventListener("click", async () => {
      const userId = deleteUserIdInput.value;
      deleteSpinner.classList.remove("d-none");
      deleteConfirmBtn.disabled = true;

      try {
        const res = await fetch(`/user-management/api/users/${userId}`, {
          method: "DELETE",
        });
        const result = await res.json();
        if (!res.ok || !result.success) {
          throw new Error(result.error || "Failed to remove user");
        }

        if (deleteModal) deleteModal.hide();

        if (window.showToast) {
          window.showToast({
            type: result.soft_deleted ? "warning" : "success",
            title: result.soft_deleted ? "Account Deactivated" : "Account Deleted",
            msg: result.message,
          });
        }
        loadUsers(currentPage);
      } catch (err) {
        alert(`Deletion error: ${err.message}`);
      } finally {
        deleteSpinner.classList.add("d-none");
        deleteConfirmBtn.disabled = false;
      }
    });
  }

  // Filters & Search Handlers
  let searchTimeout = null;
  if (searchInput) {
    searchInput.addEventListener("input", () => {
      clearTimeout(searchTimeout);
      searchTimeout = setTimeout(() => {
        currentSearch = searchInput.value.trim();
        loadUsers(1);
      }, 300);
    });
  }

  if (roleSelect) {
    roleSelect.addEventListener("change", () => {
      currentRole = roleSelect.value;
      loadUsers(1);
    });
  }

  if (statusSelect) {
    statusSelect.addEventListener("change", () => {
      currentStatus = statusSelect.value;
      loadUsers(1);
    });
  }

  if (refreshBtn) {
    refreshBtn.addEventListener("click", () => {
      loadUsers(currentPage);
    });
  }

  // Initial load
  loadUsers(1);
});

