/**
 * CyberDefense XDR
 * Asset Management Inventory Controller
 * Connects directly to backend PostgreSQL REST APIs (/assets/api).
 */

document.addEventListener("DOMContentLoaded", () => {
  // Stat elements
  const statTotal = document.getElementById("statTotalAssets");
  const statOnline = document.getElementById("statOnlineAssets");
  const statCritical = document.getElementById("statCriticalAssets");
  const statUnassigned = document.getElementById("statUnassignedAssets");
  const headerSubtitle = document.getElementById("headerSubtitle");

  // Table and controls
  const tableBody = document.getElementById("assetsTableBody");
  const searchInput = document.getElementById("assetSearch");
  const filterType = document.getElementById("filterType");
  const filterSev = document.getElementById("filterSev");
  const filterStatus = document.getElementById("filterStatus");
  const clearFiltersBtn = document.getElementById("clearFilters");
  const paginationInfo = document.getElementById("paginationInfo");
  const paginationButtons = document.getElementById("paginationButtons");

  // Actions
  const btnRescan = document.getElementById("btnRescanInventory");
  const addAssetForm = document.getElementById("addAssetForm");
  const addAssetAlert = document.getElementById("addAssetAlert");
  const btnSubmitAddAsset = document.getElementById("btnSubmitAddAsset");

  let currentPage = 1;
  const perPage = 15;
  let totalPages = 1;
  let searchTimeout = null;

  const TYPE_ICONS = {
    "Server": "bi-hdd-rack",
    "Database": "bi-database",
    "Workstation": "bi-pc-display",
    "Firewall": "bi-bricks",
    "Router": "bi-router",
    "Switch": "bi-diagram-3",
    "Domain Controller": "bi-diagram-2",
    "Mail Gateway": "bi-envelope",
    "Container Host": "bi-boxes",
    "Load Balancer": "bi-signpost-split",
    "Cloud Instance": "bi-cloud",
    "Network Device": "bi-diagram-3",
    "IoT/OT Device": "bi-cpu",
    "Other": "bi-hdd-network",
  };

  // ============================================================================
  // Fetch Real Stats from /assets/api/stats
  // ============================================================================
  async function fetchStats() {
    try {
      const res = await fetch("/assets/api/stats");
      const data = await res.json();
      if (data.success) {
        const total = data.totalAssets || 0;
        const envCount = data.environmentCount ?? data.environment_count ?? 0;
        if (statTotal) statTotal.textContent = total.toLocaleString();
        if (statOnline) statOnline.textContent = (data.onlineAssets || 0).toLocaleString();
        if (statCritical) statCritical.textContent = (data.criticalRiskAssets || 0).toLocaleString();
        if (statUnassigned) statUnassigned.textContent = (data.unassignedOwnerAssets || 0).toLocaleString();

        if (headerSubtitle) {
          headerSubtitle.textContent = `${total.toLocaleString()} asset${total === 1 ? '' : 's'} discovered across ${envCount} environment${envCount === 1 ? '' : 's'}`;
        }
      }
    } catch (err) {
      console.error("Failed to load asset stats:", err);
      if (headerSubtitle) {
        headerSubtitle.textContent = "Asset telemetry unavailable";
      }
    }
  }

  // ============================================================================
  // Fetch Real Assets from /assets/api
  // ============================================================================
  async function fetchAssets(page = 1) {
    if (tableBody) {
      tableBody.innerHTML = `<tr><td colspan="8" class="text-center text-muted py-4"><span class="spinner-border spinner-border-sm me-2"></span>Loading assets...</td></tr>`;
    }

    const search = searchInput ? searchInput.value.trim() : "";
    const type = filterType ? filterType.value : "";
    const sev = filterSev ? filterSev.value : "";
    const status = filterStatus ? filterStatus.value : "";

    const params = new URLSearchParams({
      page: page,
      per_page: perPage,
      sort_by: "created_at",
      sort_dir: "desc",
    });

    if (search) params.append("search", search);
    if (type) params.append("type", type);
    if (sev) params.append("sev", sev);
    if (status) params.append("status", status);

    try {
      const res = await fetch(`/assets/api?${params.toString()}`);
      const data = await res.json();

      if (!data.success) {
        if (tableBody) {
          tableBody.innerHTML = `<tr><td colspan="8" class="text-center text-danger py-4">Error loading assets: ${escapeHtml(data.error || "Unknown error")}</td></tr>`;
        }
        return;
      }

      currentPage = data.page || 1;
      totalPages = data.pages || 1;
      const total = data.total || 0;

      renderTable(data.items || []);
      renderPagination(total, currentPage, totalPages);

    } catch (err) {
      if (tableBody) {
        tableBody.innerHTML = `<tr><td colspan="8" class="text-center text-danger py-4">Network error loading assets: ${escapeHtml(err.message)}</td></tr>`;
      }
    }
  }

  function renderTable(items) {
    if (!tableBody) return;

    if (!items.length) {
      tableBody.innerHTML = `<tr><td colspan="8" class="text-center text-muted py-4"><i class="bi bi-inbox me-2"></i>No assets found in inventory. Click "Add Asset" to register one.</td></tr>`;
      return;
    }

    tableBody.innerHTML = items.map(a => {
      const icon = TYPE_ICONS[a.asset_type] || "bi-hdd-network";
      const statusBadge = getStatusBadge(a.status);
      const sevBadge = getSeverityBadge(a.risk_severity);
      const riskBarClass = a.risk_score >= 80 ? "bg-danger" : a.risk_score >= 60 ? "bg-warning" : a.risk_score >= 35 ? "bg-info" : "bg-success";

      return `
        <tr>
          <td>
            <a href="/assets/${a.asset_id}" class="fw-semibold text-decoration-none d-flex align-items-center gap-2 text-light">
              <i class="bi ${icon} text-primary"></i>
              <span>${escapeHtml(a.name)}</span>
            </a>
            <div class="text-muted small ps-4">${escapeHtml(a.asset_type)} &middot; <span class="badge bg-secondary-subtle text-muted">${escapeHtml(a.environment || "Unspecified")}</span></div>
          </td>
          <td>
            <code class="cell-mono text-info">${escapeHtml(a.ip_address || '-')}</code>
            ${a.hostname ? `<div class="text-muted small cell-mono">${escapeHtml(a.hostname)}</div>` : ''}
          </td>
          <td>
            <span class="small">${escapeHtml(a.operating_system || 'Unknown OS')}</span>
            ${a.platform ? `<div class="text-muted small">${escapeHtml(a.platform)}</div>` : ''}
          </td>
          <td class="small text-muted">${escapeHtml(a.owner_team || a.owner || 'Unassigned')}</td>
          <td>${statusBadge}</td>
          <td>
            <div class="d-flex align-items-center gap-2" style="min-width: 110px;">
              <div class="progress flex-grow-1" style="height: 6px;">
                <div class="progress-bar ${riskBarClass}" style="width: ${Math.min(100, Math.max(0, a.risk_score || 0))}%;"></div>
              </div>
              <span class="cell-mono small text-muted">${a.risk_score || 0}</span>
            </div>
          </td>
          <td>${sevBadge}</td>
          <td class="text-end">
            <a href="/assets/${a.asset_id}" class="btn btn-outline-primary btn-sm me-1" title="View details">
              <i class="bi bi-eye"></i>
            </a>
            <button class="btn btn-outline-secondary btn-sm btn-scan-asset me-1" data-id="${a.asset_id}" title="Scan asset">
              <i class="bi bi-search"></i>
            </button>
            <button class="btn btn-outline-danger btn-sm btn-delete-asset" data-id="${a.asset_id}" title="Delete asset">
              <i class="bi bi-trash"></i>
            </button>
          </td>
        </tr>
      `;
    }).join("");

    // Wire action buttons
    document.querySelectorAll(".btn-delete-asset").forEach(btn => {
      btn.addEventListener("click", async (e) => {
        const id = e.currentTarget.getAttribute("data-id");
        if (confirm("Are you sure you want to delete this asset from inventory?")) {
          await deleteAsset(id);
        }
      });
    });

    document.querySelectorAll(".btn-scan-asset").forEach(btn => {
      btn.addEventListener("click", async (e) => {
        const id = e.currentTarget.getAttribute("data-id");
        await triggerScan(id);
      });
    });
  }

  function renderPagination(total, page, pages) {
    if (paginationInfo) {
      const start = total > 0 ? (page - 1) * perPage + 1 : 0;
      const end = Math.min(page * perPage, total);
      paginationInfo.textContent = `Showing ${start}-${end} of ${total.toLocaleString()} assets`;
    }

    if (!paginationButtons) return;
    paginationButtons.innerHTML = "";

    if (pages <= 1) return;

    const prevBtn = document.createElement("button");
    prevBtn.className = "btn btn-outline-secondary btn-sm";
    prevBtn.innerHTML = `<i class="bi bi-chevron-left"></i>`;
    prevBtn.disabled = page <= 1;
    prevBtn.addEventListener("click", () => fetchAssets(page - 1));
    paginationButtons.appendChild(prevBtn);

    const pageIndicator = document.createElement("span");
    pageIndicator.className = "btn btn-secondary btn-sm disabled text-light";
    pageIndicator.textContent = `${page} / ${pages}`;
    paginationButtons.appendChild(pageIndicator);

    const nextBtn = document.createElement("button");
    nextBtn.className = "btn btn-outline-secondary btn-sm";
    nextBtn.innerHTML = `<i class="bi bi-chevron-right"></i>`;
    nextBtn.disabled = page >= pages;
    nextBtn.addEventListener("click", () => fetchAssets(page + 1));
    paginationButtons.appendChild(nextBtn);
  }

  function getStatusBadge(status) {
    switch ((status || "").toLowerCase()) {
      case "online":
        return `<span class="badge bg-success-subtle text-success"><i class="bi bi-circle-fill me-1" style="font-size: 0.5rem;"></i>Online</span>`;
      case "offline":
        return `<span class="badge bg-secondary-subtle text-muted"><i class="bi bi-circle-fill me-1" style="font-size: 0.5rem;"></i>Offline</span>`;
      case "maintenance":
        return `<span class="badge bg-warning-subtle text-warning"><i class="bi bi-wrench me-1"></i>Maintenance</span>`;
      case "decommissioned":
        return `<span class="badge bg-danger-subtle text-danger"><i class="bi bi-archive me-1"></i>Decommissioned</span>`;
      default:
        return `<span class="badge bg-secondary-subtle text-muted">${escapeHtml(status || "Unknown")}</span>`;
    }
  }

  function getSeverityBadge(sev) {
    switch ((sev || "").toLowerCase()) {
      case "critical":
        return `<span class="badge bg-danger text-white">Critical</span>`;
      case "high":
        return `<span class="badge bg-danger-subtle text-danger">High</span>`;
      case "medium":
        return `<span class="badge bg-warning-subtle text-warning">Medium</span>`;
      case "low":
        return `<span class="badge bg-success-subtle text-success">Low</span>`;
      default:
        return `<span class="badge bg-secondary-subtle text-muted">Low</span>`;
    }
  }

  async function deleteAsset(id) {
    try {
      const res = await fetch(`/assets/api/${id}`, { method: "DELETE" });
      const data = await res.json();
      if (data.success) {
        fetchStats();
        fetchAssets(currentPage);
      } else {
        alert("Delete failed: " + (data.error || "Unknown error"));
      }
    } catch (err) {
      alert("Delete error: " + err.message);
    }
  }

  async function triggerScan(id) {
    try {
      const res = await fetch(`/assets/api/${id}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scan_type: "Quick Scan" }),
      });
      const data = await res.json();
      if (data.success) {
        alert(data.message || "Vulnerability scan started.");
        fetchStats();
        fetchAssets(currentPage);
      } else {
        alert("Scan trigger failed: " + (data.error || "Unknown error"));
      }
    } catch (err) {
      alert("Scan error: " + err.message);
    }
  }

  // ============================================================================
  // Add Asset Form Submit
  // ============================================================================
  if (addAssetForm) {
    addAssetForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (addAssetAlert) addAssetAlert.classList.add("d-none");
      if (btnSubmitAddAsset) btnSubmitAddAsset.disabled = true;

      const rawTags = (document.getElementById("addAssetTags")?.value || "")
        .split(",")
        .map(t => t.trim())
        .filter(t => t);

      const payload = {
        name: document.getElementById("addAssetName")?.value.trim(),
        asset_type: document.getElementById("addAssetType")?.value,
        environment: document.getElementById("addAssetEnv")?.value,
        ip_address: document.getElementById("addAssetIP")?.value.trim() || null,
        hostname: document.getElementById("addAssetHostname")?.value.trim() || null,
        mac_address: document.getElementById("addAssetMAC")?.value.trim() || null,
        status: document.getElementById("addAssetStatus")?.value || "online",
        criticality: document.getElementById("addAssetCrit")?.value || "medium",
        operating_system: document.getElementById("addAssetOS")?.value.trim() || null,
        owner_team: document.getElementById("addAssetOwner")?.value.trim() || null,
        tags: rawTags,
      };

      try {
        const res = await fetch("/assets/api", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        const data = await res.json();

        if (data.success) {
          addAssetForm.reset();
          const modalEl = document.getElementById("addAssetModal");
          if (modalEl) {
            const modal = bootstrap.Modal.getInstance(modalEl);
            if (modal) modal.hide();
          }
          fetchStats();
          fetchAssets(1);
        } else {
          if (addAssetAlert) {
            addAssetAlert.textContent = data.error || "Failed to create asset.";
            addAssetAlert.classList.remove("d-none");
          }
        }
      } catch (err) {
        if (addAssetAlert) {
          addAssetAlert.textContent = "Error: " + err.message;
          addAssetAlert.classList.remove("d-none");
        }
      } finally {
        if (btnSubmitAddAsset) btnSubmitAddAsset.disabled = false;
      }
    });
  }

  // ============================================================================
  // Rescan Inventory
  // ============================================================================
  if (btnRescan) {
    btnRescan.addEventListener("click", async () => {
      btnRescan.disabled = true;
      btnRescan.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span>Scanning...`;
      try {
        const res = await fetch("/assets/api/rescan", { method: "POST" });
        const data = await res.json();
        alert(data.message || "Rescan completed.");
        fetchStats();
        fetchAssets(1);
      } catch (err) {
        alert("Rescan error: " + err.message);
      } finally {
        btnRescan.disabled = false;
        btnRescan.innerHTML = `<i class="bi bi-arrow-repeat me-1"></i>Rescan Inventory`;
      }
    });
  }

  // Search & Filter Events
  if (searchInput) {
    searchInput.addEventListener("input", () => {
      clearTimeout(searchTimeout);
      searchTimeout = setTimeout(() => fetchAssets(1), 300);
    });
  }

  [filterType, filterSev, filterStatus].forEach(el => {
    if (el) el.addEventListener("change", () => fetchAssets(1));
  });

  if (clearFiltersBtn) {
    clearFiltersBtn.addEventListener("click", () => {
      if (searchInput) searchInput.value = "";
      if (filterType) filterType.value = "";
      if (filterSev) filterSev.value = "";
      if (filterStatus) filterStatus.value = "";
      fetchAssets(1);
    });
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

  // Initial Load
  fetchStats();
  fetchAssets(1);
});