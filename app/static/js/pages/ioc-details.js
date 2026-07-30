/* ==========================================================================
   ioc-details.js — page module for app/ioc-details.html
   Depends on: IOCS_DATA, CAMPAIGNS_DATA, ACTORS_DATA (data/*)
   ========================================================================== */

   (function () {
    const TYPE_ICON = { ip: "bi-hdd-network", domain: "bi-globe", hash: "bi-fingerprint", url: "bi-link-45deg" };
  
    const params = new URLSearchParams(window.location.search);
    const id = params.get("id");
    const ioc = IOCS_DATA.find((i) => i.id === id) || IOCS_DATA[0];
    const campaign = ioc.campaignId ? CAMPAIGNS_DATA.find((c) => c.id === ioc.campaignId) : null;
    const actor = campaign ? ACTORS_DATA.find((a) => a.id === campaign.actorId) : null;
  
    document.getElementById("breadcrumbIocId").textContent = ioc.value;
    document.getElementById("iocValue").textContent = ioc.value;
    document.getElementById("iocIcon").className = `bi ${TYPE_ICON[ioc.type] || "bi-radar"}`;
    document.getElementById("iocLevelBadge").innerHTML = XDRUtils.severityBadge(ioc.threatLevel);
    document.getElementById("iocTypeChip").textContent = ioc.type.toUpperCase();
    document.getElementById("iocSource").textContent = ioc.source;
    document.getElementById("iocConfidence").textContent = ioc.confidence;
    document.getElementById("iocTags").innerHTML = ioc.tags.map((t) => `<span class="badge badge-neutral">${t}</span>`).join("");
  
    document.getElementById("statSightings").textContent = ioc.sightings;
    document.getElementById("statFirstSeen").textContent = XDRUtils.formatTime(ioc.firstSeen);
    document.getElementById("statLastSeen").textContent = XDRUtils.formatTime(ioc.lastSeen);
    document.getElementById("statStatus").textContent = ioc.status[0].toUpperCase() + ioc.status.slice(1);
  
    document.getElementById("attrCampaign").innerHTML = campaign ? `<a href="campaigns.html" style="color:var(--text);">${campaign.name}</a>` : `<span class="text-muted">Unattributed</span>`;
    document.getElementById("attrActor").innerHTML = actor ? `<a href="actors.html" style="color:var(--text);">${actor.name}</a>` : `<span class="text-muted">Unknown</span>`;
    document.getElementById("attrSource").textContent = ioc.source;
    document.getElementById("attrType").textContent = ioc.type.toUpperCase();
  
    // ---------- Related indicators — same campaign ----------
    const related = ioc.campaignId ? IOCS_DATA.filter((i) => i.campaignId === ioc.campaignId && i.id !== ioc.id).slice(0, 8) : [];
    document.getElementById("relatedIocsList").innerHTML = related.length
      ? related.map((r) => `
          <div class="info-row"><a href="ioc-details.html?id=${r.id}" class="ioc-value" style="text-decoration:none;font-size:var(--fs-sm);">${XDRUtils.escapeHtml(r.value)}</a>${XDRUtils.severityBadge(r.threatLevel)}</div>`).join("")
      : `<div class="empty-state"><i class="bi bi-inbox"></i><h3>No related indicators</h3><p>This indicator isn't linked to a tracked campaign.</p></div>`;
  
    document.getElementById("blockBtn").addEventListener("click", () => {
      const nowBlocked = ioc.status !== "blocked";
      ioc.status = nowBlocked ? "blocked" : "active";
      document.getElementById("statStatus").textContent = ioc.status[0].toUpperCase() + ioc.status.slice(1);
      if (window.showToast) window.showToast({ type: nowBlocked ? "danger" : "success", title: nowBlocked ? "Indicator blocked" : "Indicator unblocked", msg: ioc.value });
    });
    document.getElementById("watchlistBtn").addEventListener("click", () => {
      if (window.showToast) window.showToast({ type: "success", title: "Added to watchlist", msg: ioc.value });
    });
  })();
  