/* ==========================================================================
   targets.js — page module for scanner targets
   Depends on: TARGETS_DATA (fallback), XDRUtils, toast
   ========================================================================== */

(function () {
  let targets = typeof TARGETS_DATA !== "undefined" ? [...TARGETS_DATA] : [];

  const targetsGrid = document.getElementById("targetsGrid");
  const countSummary = document.getElementById("targetCountSummary");
  const searchInput = document.getElementById("targetSearch");

  function renderGrid(list) {
    if (countSummary) {
      countSummary.textContent = `${list.length} target${list.length === 1 ? "" : "s"}`;
    }

    if (!targetsGrid) return;

    if (!list.length) {
      targetsGrid.innerHTML = `
        <div class="col-12">
          <div class="card p-5 text-center text-muted">
            <i class="bi bi-crosshair mb-2" style="font-size: 2rem;"></i>
            <h5>No scan targets found</h5>
            <p class="text-sm mb-0">Add an authorized target (IPv4, IPv6, Domain, URL, or Subnet) to begin scanning.</p>
          </div>
        </div>`;
      return;
    }

    targetsGrid.innerHTML = list.map((t) => {
      const riskColor = (t.riskScore || 0) >= 70 ? "bar-danger" : (t.riskScore || 0) >= 40 ? "bar-warning" : "bar-success";
      const targetVal = t.targetInput || t.targetValue || t.name;
      const isAuth = t.isAuthorized !== false;
      const authBadge = isAuth
        ? `<span class="badge bg-success-subtle text-success text-xs"><i class="bi bi-shield-check me-1"></i>Authorized</span>`
        : `<span class="badge bg-warning-subtle text-warning text-xs"><i class="bi bi-shield-exclamation me-1"></i>Pending Auth</span>`;

      let dnsBadge = "";
      if (t.dnsRecords && (t.dnsRecords.ipv4?.length || t.dnsRecords.ipv6?.length)) {
        const ip = t.dnsRecords.ipv4?.[0] || t.dnsRecords.ipv6?.[0];
        dnsBadge = `<span class="badge bg-secondary-subtle text-secondary text-xs cell-mono"><i class="bi bi-diagram-2 me-1"></i>${ip}</span>`;
      }

      return `
        <div class="col-lg-4 col-md-6" id="target-card-${t.id}">
          <div class="card h-100">
            <div class="card-body">
              <div class="d-flex justify-content-between align-items-start mb-2">
                <div>
                  <h3 class="fs-6 mb-0" style="font-weight:600;">${t.name}</h3>
                  <div class="text-xs text-muted mt-1"><i class="bi bi-hdd-network"></i> <span class="cell-mono">${targetVal}</span></div>
                </div>
                <div class="d-flex flex-column align-items-end gap-1">
                  <span class="badge bg-secondary-subtle text-secondary">${t.type || t.targetType || "Host"}</span>
                  ${authBadge}
                </div>
              </div>
              ${dnsBadge ? `<div class="mt-1 mb-2">${dnsBadge}</div>` : ''}
              <div class="mt-3 mb-2">
                <div class="d-flex justify-content-between text-xs text-muted mb-1">
                  <span>Risk Score</span>
                  <span class="cell-mono">${t.riskScore || 0}/99</span>
                </div>
                <div class="xdr-progress">
                  <div class="xdr-progress-bar ${riskColor}" style="width: ${Math.min(100, t.riskScore || 0)}%"></div>
                </div>
              </div>
              <div class="d-flex justify-content-between align-items-center text-xs text-muted pt-2 border-top">
                <span><i class="bi bi-shield"></i> Assets: ${t.assetCount || 1}</span>
                <div class="d-flex gap-2">
                  <button class="btn btn-ghost btn-icon btn-sm text-danger delete-target-btn" data-id="${t.id}" title="Delete target">
                    <i class="bi bi-trash3"></i>
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>`;
    }).join("");

    // Wire delete buttons
    targetsGrid.querySelectorAll(".delete-target-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const id = btn.dataset.id;
        if (!confirm("Are you sure you want to delete this target?")) return;

        fetch(`/scanner/api/targets/${id}`, { method: "DELETE" })
          .then((res) => (res.ok ? res.json() : Promise.reject(res)))
          .then(() => {
            targets = targets.filter((x) => String(x.id) !== String(id));
            renderGrid(targets);
            if (window.showToast) window.showToast({ type: "success", title: "Target Deleted", msg: "Target removed successfully." });
          })
          .catch((err) => {
            if (window.showToast) window.showToast({ type: "danger", title: "Error", msg: err.message || "Failed to delete target." });
          });
      });
    });
  }

  // Search
  if (searchInput) {
    searchInput.addEventListener("input", (e) => {
      const query = e.target.value.toLowerCase().trim();
      if (!query) {
        renderGrid(targets);
      } else {
        const filtered = targets.filter((t) =>
          (t.name && t.name.toLowerCase().includes(query)) ||
          (t.targetInput && t.targetInput.toLowerCase().includes(query)) ||
          (t.targetValue && t.targetValue.toLowerCase().includes(query)) ||
          (t.type && t.type.toLowerCase().includes(query)) ||
          (t.owner && t.owner.toLowerCase().includes(query))
        );
        renderGrid(filtered);
      }
    });
  }

  // Load from API
  fetch("/scanner/api/targets")
    .then((res) => (res.ok ? res.json() : Promise.reject(res)))
    .then((data) => {
      if (data && data.targets) {
        targets = data.targets;
        renderGrid(targets);
      }
    })
    .catch(() => {
      renderGrid(targets);
    });

  // Add Target Modal action
  const confirmBtn = document.getElementById("addTargetConfirm");
  if (confirmBtn) {
    confirmBtn.addEventListener("click", () => {
      const name = document.getElementById("newTargetName")?.value?.trim();
      const targetInput = document.getElementById("newTargetInput")?.value?.trim() || name;
      const type = document.getElementById("newTargetType")?.value || "Host";
      const owner = document.getElementById("newTargetOwner")?.value?.trim() || "SecOps";
      const isAuthorized = document.getElementById("newTargetAuthorized")?.checked ?? true;

      if (!name) {
        if (window.showToast) window.showToast({ type: "warning", title: "Target Name Required", msg: "Please provide a target name." });
        return;
      }

      fetch("/scanner/api/targets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name,
          target_input: targetInput,
          type,
          owner,
          is_authorized: isAuthorized,
        }),
      })
        .then((res) => res.json().then((data) => ({ status: res.status, body: data })))
        .then(({ status, body }) => {
          if (status >= 200 && status < 300 && (body.target || body.data)) {
            const newT = body.target || body.data;
            targets.unshift(newT);
            renderGrid(targets);
            if (window.showToast) window.showToast({ type: "success", title: "Target Added", msg: `Target '${name}' created successfully.` });
            const modal = document.getElementById("addTargetModal");
            const backdrop = document.querySelector('[data-modal-backdrop="addTargetModal"]');
            if (modal) modal.classList.remove("open");
            if (backdrop) backdrop.classList.remove("open");
            document.getElementById("newTargetName").value = "";
            document.getElementById("newTargetInput").value = "";
          } else {
            if (window.showToast) window.showToast({ type: "danger", title: "Failed to Add Target", msg: body.error || body.message || "Validation error" });
          }
        })
        .catch((err) => {
          if (window.showToast) window.showToast({ type: "danger", title: "Error", msg: err.message || "Failed to add target." });
        });
    });
  }
})();


