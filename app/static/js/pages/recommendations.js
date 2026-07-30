/* ==========================================================================
   recommendations.js — page module for app/recommendations.html
   Depends on: RECOMMENDATIONS_DATA (data/ai-data.js)
   ========================================================================== */

   (function () {
    let data = RECOMMENDATIONS_DATA.map((r) => ({ ...r }));
    const STATUS_BADGE = { new: "badge-info", in_progress: "badge-warning", applied: "badge-success", dismissed: "badge-neutral" };
  
    function renderSummary() {
      document.getElementById("recSummary").textContent =
        `${data.length} recommendations · ${data.filter((r) => r.status === "new").length} new`;
    }
  
    function render() {
      const priority = document.getElementById("filterPriority").value;
      const status = document.getElementById("filterStatus").value;
      const filtered = data.filter((r) => (!priority || r.priority === priority) && (!status || r.status === status));
  
      document.getElementById("recommendationsList").innerHTML = filtered.length ? filtered.map((r) => `
        <div class="card mb-3">
          <div class="card-body d-flex gap-3">
            <span class="rec-priority-rail ${r.priority}"></span>
            <div class="flex-grow-1">
              <div class="d-flex justify-content-between flex-wrap gap-2">
                <div>
                  <div class="d-flex align-items-center gap-2 flex-wrap">
                    <strong>${XDRUtils.escapeHtml(r.title)}</strong>
                    ${XDRUtils.severityBadge(r.priority)}
                    <span class="badge badge-neutral">${r.category}</span>
                    <span class="badge ${STATUS_BADGE[r.status]}">${r.status.replace("_", " ")}</span>
                  </div>
                  <p class="text-muted text-sm mt-2 mb-1">${r.description}</p>
                  <span class="text-xs text-muted">Impact: ${r.impact} · Generated ${XDRUtils.formatTime(r.generatedAt)}</span>
                </div>
                <div class="d-flex gap-2 align-self-start">
                  ${r.status === "new" || r.status === "in_progress" ? `
                    <button class="btn btn-secondary btn-sm dismiss-btn" data-id="${r.id}">Dismiss</button>
                    <button class="btn btn-primary btn-sm apply-btn" data-id="${r.id}">Apply</button>` : ""}
                </div>
              </div>
            </div>
          </div>
        </div>`).join("")
        : `<div class="empty-state"><i class="bi bi-inbox"></i><h3>No recommendations match</h3><p>Try a different filter combination.</p></div>`;
  
      document.querySelectorAll(".apply-btn").forEach((btn) => btn.addEventListener("click", () => {
        const r = data.find((x) => x.id === btn.dataset.id);
        r.status = "applied";
        render(); renderSummary();
        if (window.showToast) window.showToast({ type: "success", title: "Recommendation applied", msg: r.title });
      }));
      document.querySelectorAll(".dismiss-btn").forEach((btn) => btn.addEventListener("click", () => {
        const r = data.find((x) => x.id === btn.dataset.id);
        r.status = "dismissed";
        render(); renderSummary();
        if (window.showToast) window.showToast({ type: "info", title: "Recommendation dismissed", msg: r.title });
      }));
    }
  
    ["filterPriority", "filterStatus"].forEach((id) => document.getElementById(id).addEventListener("change", render));
    renderSummary();
    render();
  })();
  