/* ==========================================================================
   incident-details.js — page module for app/incident-details.html
   Depends on: INCIDENTS_DATA, TIMELINE_DATA, modal-helpers.js
   ========================================================================== */

   (function () {
    const STATUS_LABEL = { open: "Open", in_progress: "In Progress", resolved: "Resolved", closed: "Closed" };
    const TYPE_ICON = { created: "bi-flag", assigned: "bi-person-check", status_change: "bi-arrow-repeat", evidence_added: "bi-archive", comment: "bi-chat-left-text", escalated: "bi-arrow-up-circle", resolved: "bi-check-circle" };
  
    const params = new URLSearchParams(window.location.search);
    const id = params.get("id");
    const incident = INCIDENTS_DATA.find((i) => i.id === id) || INCIDENTS_DATA[0];
    let notes = [];
  
    document.getElementById("breadcrumbIncId").textContent = incident.id;
    document.getElementById("incTitle").textContent = incident.title;
    document.getElementById("incDesc").textContent = incident.description;
    document.getElementById("incSevBadge").innerHTML = XDRUtils.severityBadge(incident.severity);
    document.getElementById("incStatusPill").innerHTML = `<span class="status-pill st-${incident.status}"><span class="dot"></span>${STATUS_LABEL[incident.status]}</span>`;
    document.getElementById("incAnalyst").textContent = incident.assignedAnalyst;
    document.getElementById("incTeam").textContent = incident.assignedTeam;
    const dueDate = new Date(incident.dueDate);
    const isOverdue = dueDate < new Date("2026-07-24T09:58:00Z") && incident.status !== "resolved" && incident.status !== "closed";
    document.getElementById("incDue").innerHTML = `<span class="${isOverdue ? "due-overdue" : ""}">${XDRUtils.formatTime(incident.dueDate)}${isOverdue ? " (overdue)" : ""}</span>`;
  
    document.getElementById("viewEvidenceBtn").href = `evidence.html?id=${incident.id}`;
    document.getElementById("viewTimelineBtn").href = `timeline.html?id=${incident.id}`;
    document.getElementById("evidenceFullLink").href = `evidence.html?id=${incident.id}`;
    document.getElementById("timelineFullLink").href = `timeline.html?id=${incident.id}`;
  
    // ---------- Affected assets ----------
    document.getElementById("affectedAssetsList").innerHTML = incident.affectedAssets.length
      ? incident.affectedAssets.map((a) => `
          <div class="info-row"><span><i class="bi bi-hdd-network text-muted"></i> ${a}</span><a href="assets.html" class="text-sm">View <i class="bi bi-arrow-right"></i></a></div>`).join("")
      : `<div class="empty-state"><i class="bi bi-inbox"></i><h3>No assets linked</h3><p>No affected assets recorded for this incident.</p></div>`;
  
    // ---------- Related items ----------
    document.getElementById("relatedAlertsList").innerHTML = incident.relatedAlerts.length
      ? incident.relatedAlerts.map((a) => `<a href="alert-details.html?id=${a}" class="badge badge-info" style="text-decoration:none;">${a}</a>`).join("")
      : `<span class="text-muted text-sm">None</span>`;
    document.getElementById("relatedVulnsList").innerHTML = incident.relatedVulnerabilities.length
      ? incident.relatedVulnerabilities.map((v) => `<span class="badge badge-warning">${v}</span>`).join("")
      : `<span class="text-muted text-sm">None</span>`;
    document.getElementById("relatedIocsList").innerHTML = incident.relatedIOCs.length
      ? incident.relatedIOCs.map((v) => `<span class="badge badge-danger cell-mono">${v}</span>`).join("")
      : `<span class="text-muted text-sm">None</span>`;
  
    // ---------- Evidence summary (top 4) ----------
    document.getElementById("evidenceSummaryList").innerHTML = incident.evidence.length
      ? incident.evidence.slice(0, 4).map((e) => `
          <div class="evidence-card">
            <div class="evidence-icon"><i class="bi bi-file-earmark-binary"></i></div>
            <div class="evidence-meta">
              <div class="evidence-name">${e.name}</div>
              <div class="evidence-hash">${e.hash.slice(0, 24)}…</div>
            </div>
            <span class="text-xs text-muted">${e.size}</span>
          </div>`).join("")
      : `<div class="empty-state"><i class="bi bi-inbox"></i><h3>No evidence yet</h3><p>No artifacts have been collected for this incident.</p></div>`;
  
    // ---------- Timeline preview (top 5) ----------
    const events = TIMELINE_DATA.filter((t) => t.incidentId === incident.id).sort((a, b) => new Date(b.ts) - new Date(a.ts));
    document.getElementById("incTimelinePreview").innerHTML = events.slice(0, 5).map((e) => `
        <div class="timeline-item">
          <div class="timeline-time">${XDRUtils.formatTime(e.ts)}</div>
          <strong>${XDRUtils.escapeHtml(e.message)}</strong>
          <p class="text-muted mb-0">${e.actor}</p>
        </div>`).join("") || `<div class="empty-state"><i class="bi bi-inbox"></i><h3>No timeline events</h3></div>`;
  
    // ---------- Notes ----------
    function renderNotes() {
      document.getElementById("notesList").innerHTML = notes.length
        ? notes.map((n) => `<div class="info-row"><span>${XDRUtils.escapeHtml(n.text)}</span><span class="text-xs text-muted">${n.author} · just now</span></div>`).join("")
        : `<p class="text-muted text-sm">No analyst notes yet.</p>`;
    }
    document.getElementById("addNoteBtn").addEventListener("click", () => {
      const input = document.getElementById("newNoteInput");
      if (!input.value.trim()) return;
      notes.unshift({ text: input.value.trim(), author: "Aria Reyes" });
      input.value = "";
      renderNotes();
      if (window.showToast) window.showToast({ type: "success", title: "Note added" });
    });
    renderNotes();
  
    // ---------- Resolution ----------
    document.getElementById("resNotes").value = incident.resolutionNotes;
    document.getElementById("resMitigation").value = incident.mitigation;
    document.getElementById("resLessons").value = incident.lessonsLearned;
    document.getElementById("recoveryStepsList").innerHTML = incident.recoverySteps.length
      ? incident.recoverySteps.map((s, i) => `<div class="playbook-step-row"><span class="playbook-step-num">${i + 1}</span><span class="text-sm">${s}</span></div>`).join("")
      : `<p class="text-muted text-sm">No recovery steps recorded.</p>`;
  
    // ---------- Tabs ----------
    const tabs = document.querySelectorAll(".xdr-tab");
    const panels = { evidence: document.getElementById("tabEvidence"), timeline: document.getElementById("tabTimeline"), notes: document.getElementById("tabNotes"), resolution: document.getElementById("tabResolution") };
    tabs.forEach((tab) => tab.addEventListener("click", () => {
      tabs.forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      Object.values(panels).forEach((p) => p.classList.add("d-none"));
      panels[tab.dataset.tab].classList.remove("d-none");
    }));
  
    // ---------- Close incident ----------
    document.getElementById("closeIncidentBtn").addEventListener("click", () => {
      document.getElementById("closeIncTitle").textContent = incident.title;
      window.xdrOpenModal("closeIncidentModal");
    });
    document.getElementById("confirmCloseIncidentBtn").addEventListener("click", () => {
      incident.status = "closed";
      document.getElementById("incStatusPill").innerHTML = `<span class="status-pill st-closed"><span class="dot"></span>Closed</span>`;
      if (window.showToast) window.showToast({ type: "success", title: "Incident closed", msg: incident.id });
    });
  })();
  