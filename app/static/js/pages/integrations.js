/* ==========================================================================
   integrations.js — page module for app/integrations.html
   Depends on: INTEGRATIONS_DATA (data/settings-data.js), modal-helpers.js
   ========================================================================== */

   (function () {
    let integrations = INTEGRATIONS_DATA.map((i) => ({ ...i }));
  
    function renderSummary() {
      document.getElementById("integrationsSummary").textContent =
        `${integrations.filter((i) => i.connected).length} of ${integrations.length} integrations connected`;
    }
  
    function render() {
      document.getElementById("integrationsGrid").innerHTML = integrations.map((i) => `
        <div class="col-lg-3 col-md-6">
          <div class="integration-card">
            <div class="d-flex justify-content-between align-items-start">
              <span class="integration-icon"><i class="bi ${i.icon}"></i></span>
              <span class="text-xs text-muted"><span class="integration-status-dot ${i.status}"></span> ${i.status}</span>
            </div>
            <div><h3 class="fs-inherit-md mb-0">${i.name}</h3><span class="text-xs text-muted">${i.category}</span></div>
            <p class="text-muted text-sm mb-0">${i.description}</p>
            <div class="d-flex gap-2 mt-auto">
              <button class="btn ${i.connected ? "btn-secondary" : "btn-primary"} btn-sm flex-fill toggle-conn-btn" data-id="${i.id}">
                ${i.connected ? "Disconnect" : "Connect"}
              </button>
              ${i.connected ? `<button class="btn btn-icon btn-ghost btn-sm configure-btn" data-id="${i.id}" title="Configure"><i class="bi bi-gear"></i></button>` : ""}
            </div>
          </div>
        </div>`).join("");
  
      document.querySelectorAll(".toggle-conn-btn").forEach((btn) => btn.addEventListener("click", () => {
        const item = integrations.find((i) => i.id === btn.dataset.id);
        item.connected = !item.connected;
        item.status = item.connected ? "active" : "disconnected";
        render();
        renderSummary();
        if (window.showToast) window.showToast({ type: item.connected ? "success" : "warning", title: item.connected ? "Integration connected" : "Integration disconnected", msg: item.name });
      }));
      document.querySelectorAll(".configure-btn").forEach((btn) => btn.addEventListener("click", () => {
        const item = integrations.find((i) => i.id === btn.dataset.id);
        document.getElementById("cfgModalTitle").textContent = `Configure ${item.name}`;
        window.xdrOpenModal("configureModal");
      }));
    }
    render();
    renderSummary();
  
    document.getElementById("cfgSaveBtn").addEventListener("click", () => {
      if (window.showToast) window.showToast({ type: "success", title: "Configuration saved" });
    });
  })();
  