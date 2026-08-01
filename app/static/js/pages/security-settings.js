/* ==========================================================================
   security-settings.js — page module for app/security-settings.html
   Depends on: IP_ALLOWLIST_DATA (data/settings-data.js)
   ========================================================================== */

   (function () {
    let allowlist = IP_ALLOWLIST_DATA.map((a) => ({ ...a }));
  
    function render() {
      document.getElementById("allowlistBody").innerHTML = allowlist.length
        ? allowlist.map((a) => `
            <div class="settings-row">
              <div><div class="row-label cell-mono">${a.cidr}</div><div class="row-hint">${a.label} · added by ${a.addedBy}</div></div>
              <button class="btn btn-icon btn-ghost btn-sm remove-cidr-btn" data-id="${a.id}"><i class="bi bi-trash"></i></button>
            </div>`).join("")
        : `<p class="text-muted text-sm">No IP restrictions configured — access allowed from any network.</p>`;
  
      document.querySelectorAll(".remove-cidr-btn").forEach((btn) => btn.addEventListener("click", () => {
        const entry = allowlist.find((a) => a.id === btn.dataset.id);
        allowlist = allowlist.filter((a) => a.id !== btn.dataset.id);
        render();
        if (window.showToast) window.showToast({ type: "warning", title: "Entry removed", msg: entry.cidr });
      }));
    }
    render();
  
    document.getElementById("addCidrBtn").addEventListener("click", () => {
      const input = document.getElementById("newCidrInput");
      const val = input.value.trim();
      if (!val) return;
      allowlist.push({ id: `IP-${Math.floor(Math.random() * 900 + 100)}`, cidr: val, label: "Manually added", addedBy: "Aria Reyes" });
      input.value = "";
      render();
      if (window.showToast) window.showToast({ type: "success", title: "IP range added", msg: val });
    });
  
    document.getElementById("saveBtn").addEventListener("click", () => {
      if (window.showToast) window.showToast({ type: "success", title: "Security settings saved" });
    });
  })();
  