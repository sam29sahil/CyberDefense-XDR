/* ==========================================================================
   profile.js — page module for app/profile.html
   Depends on: SESSIONS_DATA (data/settings-data.js), modal-helpers.js
   ========================================================================== */

   (function () {
    let sessions = SESSIONS_DATA.map((s) => ({ ...s }));
  
    function render() {
      document.getElementById("sessionsList").innerHTML = sessions.map((s) => `
        <div class="settings-row">
          <div>
            <div class="row-label">${s.device} ${s.current ? '<span class="badge badge-success">This device</span>' : ""}</div>
            <div class="row-hint">${s.location} · ${s.ip} · since ${XDRUtils.formatTime(s.startedAt)}</div>
          </div>
          ${s.current ? "" : `<button class="btn btn-icon btn-ghost btn-sm revoke-session-btn" data-id="${s.id}" title="Revoke"><i class="bi bi-x-circle"></i></button>`}
        </div>`).join("");
  
      document.querySelectorAll(".revoke-session-btn").forEach((btn) => btn.addEventListener("click", () => {
        const s = sessions.find((x) => x.id === btn.dataset.id);
        document.getElementById("revokeSessionDevice").textContent = s.device;
        document.getElementById("confirmRevokeSessionBtn").dataset.id = s.id;
        window.xdrOpenModal("revokeSessionModal");
      }));
    }
    render();
  
    document.getElementById("confirmRevokeSessionBtn").addEventListener("click", () => {
      const id = document.getElementById("confirmRevokeSessionBtn").dataset.id;
      const s = sessions.find((x) => x.id === id);
      sessions = sessions.filter((x) => x.id !== id);
      render();
      if (window.showToast && s) window.showToast({ type: "success", title: "Session revoked", msg: s.device });
    });
  
    document.getElementById("changeAvatarBtn").addEventListener("click", () => {
      if (window.showToast) window.showToast({ type: "info", title: "Upload disabled in preview", msg: "This is a static frontend demo — file upload isn't wired to a backend yet." });
    });
  
    document.getElementById("reconfigureMfaBtn").addEventListener("click", () => {
      if (window.showToast) window.showToast({ type: "info", title: "MFA reconfiguration started", msg: "Scan the new QR code with your authenticator app." });
    });
  
    document.getElementById("changePwBtn").addEventListener("click", () => {
      const cur = document.getElementById("curPw").value;
      const next = document.getElementById("newPw").value;
      const confirm = document.getElementById("confirmPw").value;
      if (!cur || !next) {
        if (window.showToast) window.showToast({ type: "warning", title: "All fields required" });
        return;
      }
      if (next !== confirm) {
        if (window.showToast) window.showToast({ type: "danger", title: "Passwords don't match" });
        return;
      }
      document.getElementById("curPw").value = "";
      document.getElementById("newPw").value = "";
      document.getElementById("confirmPw").value = "";
      if (window.showToast) window.showToast({ type: "success", title: "Password updated" });
    });
  
    document.getElementById("saveBtn").addEventListener("click", () => {
      if (window.showToast) window.showToast({ type: "success", title: "Profile saved" });
    });
  })();
  