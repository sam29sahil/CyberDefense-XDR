/* ==========================================================================
   actors.js — page module for app/actors.html
   Depends on: ACTORS_DATA (data/actors-data.js), modal-helpers.js
   ========================================================================== */

   (function () {
    const actors = ACTORS_DATA;
    document.getElementById("actorSummary").textContent = `${actors.length} actors tracked across ${new Set(actors.map((a) => a.origin)).size} regions`;
  
    function renderGrid(list) {
      document.getElementById("actorGrid").innerHTML = list.length ? list.map((a) => `
        <div class="col-lg-4 col-md-6">
          <div class="actor-card" data-id="${a.id}" role="button">
            <div class="d-flex align-items-center gap-3">
              <span class="actor-avatar">${a.name.slice(0, 2).toUpperCase()}</span>
              <div>
                <h3 class="fs-inherit-md mb-0">${a.name}</h3>
                <span class="text-xs text-muted">${a.origin}</span>
              </div>
            </div>
            <div class="d-flex gap-2 flex-wrap">
              <span class="sophistication-pill">${a.sophistication}</span>
              <span class="badge badge-neutral">${a.motivation}</span>
            </div>
            <div class="d-flex justify-content-between text-xs text-muted mt-auto">
              <span>${a.campaignCount} campaigns</span><span>Last seen ${XDRUtils.formatTime(a.lastActivity)}</span>
            </div>
          </div>
        </div>`).join("")
        : `<div class="col-12"><div class="empty-state"><i class="bi bi-inbox"></i><h3>No actors found</h3><p>Try a different search term.</p></div></div>`;
  
      document.querySelectorAll(".actor-card").forEach((card) => card.addEventListener("click", () => openActor(actors.find((a) => a.id === card.dataset.id))));
    }
    renderGrid(actors);
  
    function openActor(a) {
      document.getElementById("acModalName").textContent = a.name;
      document.getElementById("acModalDesc").textContent = a.description;
      document.getElementById("acModalOrigin").textContent = a.origin;
      document.getElementById("acModalMotivation").textContent = a.motivation;
      document.getElementById("acModalSoph").innerHTML = `<span class="sophistication-pill">${a.sophistication}</span>`;
      document.getElementById("acModalFirst").textContent = XDRUtils.formatTime(a.firstSeen);
      document.getElementById("acModalLast").textContent = XDRUtils.formatTime(a.lastActivity);
      document.getElementById("acModalSectors").innerHTML = a.targetSectors.map((s) => `<span class="badge badge-neutral">${s}</span>`).join("");
      document.getElementById("acModalTactics").innerHTML = a.mitreTactics.map((t) => `<span class="mitre-chip">${t}</span>`).join("");
      window.xdrOpenModal("actorModal");
    }
  
    document.getElementById("actorSearch").addEventListener("input", (e) => {
      const q = e.target.value.trim().toLowerCase();
      renderGrid(!q ? actors : actors.filter((a) => a.name.toLowerCase().includes(q) || a.origin.toLowerCase().includes(q)));
    });
  })();
  