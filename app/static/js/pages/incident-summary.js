/* ==========================================================================
   incident-summary.js — page module for app/incident-summary.html
   Depends on: INCIDENTS_DATA, TIMELINE_DATA (data/incident-data.js, timeline-data.js)
   ========================================================================== */

   (function () {
    const STATUS_LABEL = { open: "Open", in_progress: "In Progress", resolved: "Resolved", closed: "Closed" };
    const select = document.getElementById("incidentSelect");
    select.innerHTML = INCIDENTS_DATA.map((i) => `<option value="${i.id}">${i.id} — ${i.title}</option>`).join("");
  
    const params = new URLSearchParams(window.location.search);
    const preselect = params.get("id");
    if (preselect && INCIDENTS_DATA.some((i) => i.id === preselect)) select.value = preselect;
  
    function buildNarrative(inc) {
      const assetList = inc.affectedAssets.length ? inc.affectedAssets.join(", ") : "no assets currently on record";
      const statusPhrase = inc.status === "closed" || inc.status === "resolved"
        ? `The incident has been marked ${inc.status}, with mitigation steps applied.`
        : `The incident remains ${STATUS_LABEL[inc.status].toLowerCase()}, currently assigned to ${inc.assignedAnalyst} on the ${inc.assignedTeam} team.`;
      const relatedPhrase = inc.relatedIOCs.length
        ? ` ${inc.relatedIOCs.length} related indicator${inc.relatedIOCs.length === 1 ? "" : "s"} of compromise ${inc.relatedIOCs.length === 1 ? "has" : "have"} been linked to this activity.`
        : "";
      return `${inc.title} was opened on ${new Date(inc.createdAt).toISOString().slice(0, 10)} and classified as ${inc.severity} severity (${inc.priority}) under the ${inc.category} category. ${inc.description} Affected systems include ${assetList}. ${statusPhrase}${relatedPhrase}`;
    }
  
    function suggestNextActions(inc) {
      const actions = [];
      if (inc.status === "open") actions.push("Confirm initial scope and formally assign an owning analyst.");
      if (inc.status === "open" || inc.status === "in_progress") actions.push("Collect and preserve evidence from affected hosts before further containment steps.");
      if (inc.relatedVulnerabilities.length) actions.push(`Prioritize remediation of ${inc.relatedVulnerabilities.join(", ")} on affected assets.`);
      if (inc.relatedIOCs.length) actions.push("Add associated indicators to the block list and monitor for recurrence.");
      if (inc.status === "resolved") actions.push("Complete lessons-learned documentation and close the incident.");
      if (!actions.length) actions.push("No further action recommended at this time — continue standard monitoring.");
      return actions;
    }
  
    function render() {
      const inc = INCIDENTS_DATA.find((i) => i.id === select.value) || INCIDENTS_DATA[0];
      document.getElementById("narrativeText").textContent = buildNarrative(inc);
      document.getElementById("factSev").innerHTML = XDRUtils.severityBadge(inc.severity);
      document.getElementById("factStatus").innerHTML = `<span class="status-pill st-${inc.status}"><span class="dot"></span>${STATUS_LABEL[inc.status]}</span>`;
      document.getElementById("factCategory").textContent = inc.category;
      document.getElementById("factAssigned").textContent = `${inc.assignedAnalyst} (${inc.assignedTeam})`;
      document.getElementById("factAssets").textContent = inc.affectedAssets.join(", ") || "None recorded";
  
      document.getElementById("nextActionsList").innerHTML = suggestNextActions(inc).map((a) => `
        <div class="insight-card"><span class="insight-icon info"><i class="bi bi-arrow-right-circle"></i></span><div class="text-sm">${a}</div></div>`).join("");
  
      const events = TIMELINE_DATA.filter((t) => t.incidentId === inc.id).sort((a, b) => new Date(b.ts) - new Date(a.ts)).slice(0, 5);
      document.getElementById("condensedTimeline").innerHTML = events.length
        ? events.map((e) => `<div class="timeline-item"><div class="timeline-time">${XDRUtils.formatTime(e.ts)}</div><strong>${XDRUtils.escapeHtml(e.message)}</strong></div>`).join("")
        : `<p class="text-muted text-sm">No timeline events recorded.</p>`;
    }
  
    select.addEventListener("change", render);
    render();
  })();
  