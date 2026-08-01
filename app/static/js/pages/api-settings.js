/* ==========================================================================
   api-settings.js — page module for app/api-settings.html
   Depends on: API_KEYS_DATA (data/settings-data.js), modal-helpers.js
   ========================================================================== */

   (function () {
    let keys = API_KEYS_DATA.map((k) => ({ ...k }));
  
    function render() {
      document.getElementById("apiKeysBody").innerHTML = keys.map((k) => `
        <tr>
          <td style="font-weight:600;">${k.name}<div class="text-xs text-muted">by ${k.createdBy}</div></td>
          <td class="api-key-value">${k.prefix}••••••••••••</td>
          <td>${k.scopes.map((s) => `<span class="scope-chip">${s}</span>`).join(" ")}</td>
          <td class="text-sm text-muted">${XDRUtils.formatTime(k.createdAt)}</td>
          <td class="text-sm text-muted">${XDRUtils.formatTime(k.lastUsed)}</td>
          <td><span class="badge ${k.status === "active" ? "badge-success" : "badge-neutral"}">${k.status}</span></td>
          <td><button class="btn btn-icon btn-ghost btn-sm revoke-btn" data-id="${k.id}" ${k.status === "revoked" ? "disabled" : ""} title="Revoke"><i class="bi bi-trash"></i></button></td>
        </tr>`).join("");
  
      document.querySelectorAll(".revoke-btn").forEach((btn) => btn.addEventListener("click", () => {
        const key = keys.find((k) => k.id === btn.dataset.id);
        document.getElementById("revokeKeyName").textContent = key.name;
        document.getElementById("confirmRevokeBtn").dataset.id = key.id;
        window.xdrOpenModal("revokeKeyModal");
      }));
    }
    render();
  
    document.getElementById("confirmRevokeBtn").addEventListener("click", () => {
      const id = document.getElementById("confirmRevokeBtn").dataset.id;
      const key = keys.find((k) => k.id === id);
      key.status = "revoked";
      render();
      if (window.showToast) window.showToast({ type: "danger", title: "Key revoked", msg: key.name });
    });
  
    document.getElementById("generateKeyConfirm").addEventListener("click", () => {
      const name = document.getElementById("newKeyName").value.trim();
      if (!name) {
        if (window.showToast) window.showToast({ type: "warning", title: "Key name required" });
        return;
      }
      const scopes = [...document.querySelectorAll("#newKeyModal input:checked")].map((c) => c.value);
      const fullKey = "xdr_" + Array.from({ length: 32 }, () => "abcdef0123456789"[Math.floor(Math.random() * 16)]).join("");
      keys.unshift({
        id: `KEY-${Math.floor(Math.random() * 900 + 100)}`, name, prefix: fullKey.slice(0, 12),
        scopes: scopes.length ? scopes : ["read:alerts"], createdAt: new Date().toISOString(),
        createdBy: "Aria Reyes", lastUsed: new Date().toISOString(), status: "active",
      });
      document.getElementById("newKeyName").value = "";
      render();
      document.getElementById("revealedKeyText").textContent = fullKey;
      window.xdrOpenModal("revealKeyModal");
    });
  })();
  