/* ==========================================================================
   campaigns.js — page module for app/campaigns.html
   Depends on: CAMPAIGNS_DATA (data/threat-data.js), modal-helpers.js
   ========================================================================== */

   (function () {
    const campaigns = CAMPAIGNS_DATA;
    document.getElementById("campaignSummary").textContent =
      `${campaigns.length} campaigns tracked · ${campaigns.filter((c) => c.status === "active").length} active`;
  
    function renderGrid(list) {
      document.getElementById("campaignGrid").innerHTML = list.length ? list.map((c) => `
        <div class="col-lg-4 col-md-6">
          <div class="campaign-card" data-id="${c.id}" role="button" style="cursor:pointer;">
            <div><span class="campaign-status-dot ${c.status}"></span><strong>${c.name}</strong></div>
            <p class="text-muted text-sm mb-0">Attributed to ${c.actorName}</p>
            <div class="d-flex flex-wrap gap-1">${c.targetSectors.map((s) => `<span class="badge badge-neutral">${s}</span>`).join("")}</div>
            <div class="d-flex justify-content-between text-xs text-muted mt-auto">
              <span>${c.iocCount} IOCs</span><span>${XDRUtils.formatTime(c.firstObserved)}</span>
            </div>
          </div>
        </div>`).join("")
        : `<div class="col-12"><div class="empty-state"><i class="bi bi-inbox"></i><h3>No campaigns found</h3><p>Try a different search term.</p></div></div>`;
  
      document.querySelectorAll(".campaign-card").forEach((card) => card.addEventListener("click", () => openCampaign(campaigns.find((c) => c.id === card.dataset.id))));
    }
    renderGrid(campaigns);
  
    function openCampaign(c) {
      document.getElementById("cmModalTitle").textContent = c.name;
      document.getElementById("cmModalDesc").textContent = c.description;
      document.getElementById("cmModalActor").textContent = c.actorName;
      document.getElementById("cmModalStatus").innerHTML = `<span class="campaign-status-dot ${c.status}"></span>${c.status[0].toUpperCase() + c.status.slice(1)}`;
      document.getElementById("cmModalFirst").textContent = XDRUtils.formatTime(c.firstObserved);
      document.getElementById("cmModalIocs").textContent = c.iocCount;
      document.getElementById("cmModalTtps").innerHTML = c.ttps.map((t) => `<span class="mitre-chip">${t}</span>`).join("");
      window.xdrOpenModal("campaignModal");
    }
  
    document.getElementById("campaignSearch").addEventListener("input", (e) => {
      const q = e.target.value.trim().toLowerCase();
      renderGrid(!q ? campaigns : campaigns.filter((c) => c.name.toLowerCase().includes(q) || c.actorName.toLowerCase().includes(q)));
    });
  })();
  