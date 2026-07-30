/* ==========================================================================
   timeline.js — page module for app/timeline.html
   Depends on: INCIDENTS_DATA, TIMELINE_DATA
   ========================================================================== */

   (function () {
    const TYPE_ICON = {
      created: "bi-flag", assigned: "bi-person-check", status_change: "bi-arrow-repeat",
      evidence_added: "bi-archive", comment: "bi-chat-left-text", escalated: "bi-arrow-up-circle", resolved: "bi-check-circle",
    };
  
    const params = new URLSearchParams(window.location.search);
    const id = params.get("id");
    const incident = INCIDENTS_DATA.find((i) => i.id === id) || INCIDENTS_DATA[0];
  
    document.getElementById("breadcrumbIncLink").textContent = incident.title;
    document.getElementById("breadcrumbIncLink").href = `incident-details.html?id=${incident.id}`;
  
    const allEvents = TIMELINE_DATA.filter((t) => t.incidentId === incident.id).sort((a, b) => new Date(b.ts) - new Date(a.ts));
    document.getElementById("timelineSummary").textContent = `${allEvents.length} events for ${incident.id} — ${incident.title}`;
  
    function render(events) {
      document.getElementById("fullTimeline").innerHTML = events.length
        ? events.map((e) => `
            <div class="timeline-item">
              <div class="timeline-time"><i class="bi ${TYPE_ICON[e.type] || "bi-dot"}"></i> ${XDRUtils.formatTime(e.ts)}</div>
              <strong>${XDRUtils.escapeHtml(e.message)}</strong>
              <p class="text-muted mb-0">${e.actor} · ${e.type.replace("_", " ")}</p>
            </div>`).join("")
        : `<div class="empty-state"><i class="bi bi-inbox"></i><h3>No matching events</h3><p>Try a different event type filter.</p></div>`;
    }
    render(allEvents);
  
    document.getElementById("filterType").addEventListener("change", (e) => {
      const type = e.target.value;
      render(type ? allEvents.filter((ev) => ev.type === type) : allEvents);
    });
  })();
  