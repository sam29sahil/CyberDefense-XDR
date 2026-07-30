/* ==========================================================================
   asset-details.js — page module for app/asset-details.html
   Reads ?id=AST-XXXX from the URL and populates the header from ASSETS_DATA.
   Falls back to the first asset if no match, so the page never renders empty
   when opened directly (e.g. from the design system or a bookmark).
   ========================================================================== */

   (function () {
    const TYPE_ICON = {
      "Server": "bi-hdd-rack", "Database": "bi-database", "Workstation": "bi-pc-display",
      "Firewall": "bi-bricks", "Router": "bi-router", "Domain Controller": "bi-diagram-2",
      "Mail Gateway": "bi-envelope", "Container Host": "bi-boxes", "Load Balancer": "bi-signpost-split",
    };
  
    const params = new URLSearchParams(window.location.search);
    const id = params.get("id");
    const asset = ASSETS_DATA.find((a) => a.id === id) || ASSETS_DATA[0];
  
    document.getElementById("assetName").textContent = asset.name;
    document.getElementById("breadcrumbAssetName").textContent = asset.name;
    document.getElementById("assetIdBadge").textContent = asset.id;
    document.getElementById("assetMeta").textContent = `${asset.type} · ${asset.env} · Owned by ${asset.owner}`;
    document.getElementById("assetTypeIcon").innerHTML = `<i class="bi ${TYPE_ICON[asset.type] || 'bi-hdd'}"></i>`;
    document.getElementById("infoOS").textContent = asset.os;
    document.getElementById("infoEnv").textContent = asset.env;
    document.getElementById("infoIP").textContent = asset.ip;
    document.getElementById("infoOwner").textContent = asset.owner;
    document.getElementById("statRisk").textContent = asset.risk;
    document.getElementById("statRisk").style.color =
      asset.sev === "critical" || asset.sev === "high" ? "var(--danger)" :
      asset.sev === "medium" ? "var(--warning)" : "var(--success)";
  
    document.getElementById("assetTags").innerHTML =
      `<span class="badge badge-${asset.status === 'online' ? 'success' : 'neutral'}">${asset.status === 'online' ? 'Online' : 'Offline'}</span>` +
      asset.tags.map((t) => `<span class="badge badge-neutral">${t}</span>`).join("");
  
    // Tabs
    const tabs = document.querySelectorAll(".xdr-tab");
    const panels = {
      overview: document.getElementById("tabOverview"),
      vulns: document.getElementById("tabVulns"),
      alerts: document.getElementById("tabAlerts"),
      network: document.getElementById("tabNetwork"),
      compliance: document.getElementById("tabCompliance"),
    };
    tabs.forEach((tab) => {
      tab.addEventListener("click", () => {
        tabs.forEach((t) => t.classList.remove("active"));
        tab.classList.add("active");
        Object.values(panels).forEach((p) => p.classList.add("d-none"));
        panels[tab.dataset.tab].classList.remove("d-none");
      });
    });
  })();
  