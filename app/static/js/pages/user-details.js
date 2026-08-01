/* ==========================================================================
   user-details.js — page module for app/user-details.html
   Depends on: USERS_DATA, ROLES_DATA, ACTIVITY_DATA (data/users-data.js)
   ========================================================================== */

   (function () {
    const STATUS_LABEL = { active: "Active", inactive: "Inactive", locked: "Locked" };
    function initials(name) { return name.split(" ").map((p) => p[0]).slice(0, 2).join("").toUpperCase(); }
  
    const params = new URLSearchParams(window.location.search);
    const id = params.get("id");
    const user = USERS_DATA.find((u) => u.id === id) || USERS_DATA[0];
    const role = ROLES_DATA.find((r) => r.id === user.roleId);
  
    document.getElementById("breadcrumbUserName").textContent = user.name;
    document.getElementById("userAvatar").textContent = initials(user.name);
    document.getElementById("userName").textContent = user.name;
    document.getElementById("userEmail").textContent = user.email;
    document.getElementById("userStatusPill").innerHTML = `<span class="status-pill st-${user.status}"><span class="dot"></span>${STATUS_LABEL[user.status]}</span>`;
    document.getElementById("userRoleBadge").textContent = user.roleName;
    document.getElementById("userDeptBadge").textContent = user.department;
    document.getElementById("userMfaBadge").innerHTML = `<i class="bi bi-shield-${user.mfaEnabled ? "check" : "x"}"></i> MFA ${user.mfaEnabled ? "Enabled" : "Disabled"}`;
    document.getElementById("userMfaBadge").classList.add(user.mfaEnabled ? "on" : "off");
  
    document.getElementById("statSessions").textContent = user.sessions;
    document.getElementById("statLastLogin").textContent = XDRUtils.formatTime(user.lastLogin);
    document.getElementById("statCreated").textContent = XDRUtils.formatTime(user.createdAt);
    document.getElementById("statPerms").textContent = role ? role.permCount : "—";
  
    document.getElementById("roleDescription").textContent = role ? role.description : "No role assigned.";
  
    const activity = ACTIVITY_DATA.filter((a) => a.userId === user.id).sort((a, b) => new Date(b.ts) - new Date(a.ts)).slice(0, 8);
    document.getElementById("userActivityBody").innerHTML = activity.length
      ? activity.map((a) => `
          <tr><td class="text-sm text-muted">${XDRUtils.formatTime(a.ts)}</td><td>${a.label}</td><td class="text-sm">${a.resource}</td>
          <td><span class="badge ${a.result === "success" ? "badge-success" : "badge-danger"}">${a.result}</span></td></tr>`).join("")
      : `<tr><td colspan="4"><div class="empty-state"><i class="bi bi-inbox"></i><h3>No recent activity</h3></div></td></tr>`;
  
    document.getElementById("toggleStatusBtn").innerHTML = user.status === "locked"
      ? `<i class="bi bi-power"></i> Reactivate` : `<i class="bi bi-power"></i> Deactivate`;
    document.getElementById("toggleStatusBtn").addEventListener("click", () => {
      const nowLocked = user.status !== "locked";
      user.status = nowLocked ? "locked" : "active";
      document.getElementById("userStatusPill").innerHTML = `<span class="status-pill st-${user.status}"><span class="dot"></span>${STATUS_LABEL[user.status]}</span>`;
      document.getElementById("toggleStatusBtn").innerHTML = user.status === "locked" ? `<i class="bi bi-power"></i> Reactivate` : `<i class="bi bi-power"></i> Deactivate`;
      if (window.showToast) window.showToast({ type: nowLocked ? "danger" : "success", title: nowLocked ? "User deactivated" : "User reactivated", msg: user.name });
    });
  
    document.getElementById("resetPwBtn").addEventListener("click", () => {
      if (window.showToast) window.showToast({ type: "success", title: "Password reset sent", msg: `Reset link emailed to ${user.email}.` });
    });
  })();
  