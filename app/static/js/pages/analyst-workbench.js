/* ==========================================================================
   analyst-workbench.js — page module for app/analyst-workbench.html
   Depends on: ALERTS_DATA, CASES_DATA, ANALYSTS_DATA
   Personalizes the view for the currently "logged in" analyst (Aria Reyes),
   matching the navbar profile used across the app.
   ========================================================================== */

   (function () {
    const ME = "Aria Reyes";
    const me = ANALYSTS_DATA.find((a) => a.name === ME) || ANALYSTS_DATA[0];
  
    const myAlerts = ALERTS_DATA.filter((a) => a.assignedAnalyst === ME && a.status !== "closed");
    const myCases = CASES_DATA.filter((c) => c.owner === ME && c.status !== "closed");
    const rank = ANALYSTS_DATA.slice().sort((a, b) => a.workloadScore - b.workloadScore).findIndex((a) => a.name === ME) + 1;
  
    document.getElementById("statMyAlerts").textContent = myAlerts.length;
    document.getElementById("statMyCases").textContent = myCases.length;
    document.getElementById("statClosedWeek").textContent = me.closedThisWeek;
    document.getElementById("statWorkloadRank").textContent = `#${rank} of ${ANALYSTS_DATA.length}`;
  
    document.getElementById("myAlertsList").innerHTML = myAlerts.length
      ? myAlerts.slice(0, 8).map((a) => `
          <div class="queue-item">
            <span class="priority-pill p-${a.priority}">${a.priority}</span>
            <a href="alert-details.html?id=${a.id}" class="qi-title" style="color:var(--text);text-decoration:none;">${XDRUtils.escapeHtml(a.title)}</a>
            <span class="badge ${a.status === "investigating" ? "badge-warning" : "badge-info"}">${a.status}</span>
          </div>`).join("")
      : `<div class="empty-state"><i class="bi bi-check2-circle"></i><h3>Queue clear</h3><p>No alerts currently assigned to you.</p></div>`;
  
    document.getElementById("myCasesList").innerHTML = myCases.length
      ? myCases.map((c) => `
          <div class="queue-item">
            <span class="priority-pill p-${c.priority}">${c.priority}</span>
            <a href="case-details.html?id=${c.id}" class="qi-title" style="color:var(--text);text-decoration:none;">${XDRUtils.escapeHtml(c.title)}</a>
            <span class="badge badge-neutral">${c.status.replace("_", " ")}</span>
          </div>`).join("")
      : `<div class="empty-state"><i class="bi bi-check2-circle"></i><h3>No open cases</h3><p>You're not currently the owner of any active investigation.</p></div>`;
  
    const maxWorkload = Math.max(...ANALYSTS_DATA.map((a) => a.workloadScore), 1);
    document.getElementById("teamWorkloadList").innerHTML = ANALYSTS_DATA.slice()
      .sort((a, b) => b.workloadScore - a.workloadScore)
      .map((a) => `
        <div class="analyst-load-row">
          <span class="status-dot ${a.status}"></span>
          <span class="avatar avatar-sm">${a.initials}</span>
          <span class="aln-name">${a.name}${a.name === ME ? " (you)" : ""}</span>
          <div class="xdr-progress"><div class="xdr-progress-bar ${a.name === ME ? "bar-warning" : "bar-primary"}" style="width:${Math.round(a.workloadScore / maxWorkload * 100)}%"></div></div>
          <span class="text-muted text-xs">${a.assignedAlerts + a.assignedCases}</span>
        </div>`).join("");
  
    // ---------- Quick notes (session-local, in-memory only) ----------
    let quickNotes = [];
    function renderQuickNotes() {
      document.getElementById("quickNotesList").innerHTML = quickNotes.map((n, i) => `
        <div class="note-item">
          <span class="avatar avatar-sm">AR</span>
          <div class="note-body">
            <div class="d-flex justify-content-between"><span class="note-time">${XDRUtils.formatTime(n.ts)}</span>
              <button class="btn btn-icon btn-ghost btn-sm remove-note-btn" data-idx="${i}"><i class="bi bi-x"></i></button></div>
            <p class="mb-0 mt-1">${XDRUtils.escapeHtml(n.text)}</p>
          </div>
        </div>`).join("");
      document.querySelectorAll(".remove-note-btn").forEach((btn) => btn.addEventListener("click", () => {
        quickNotes.splice(parseInt(btn.dataset.idx, 10), 1);
        renderQuickNotes();
      }));
    }
    document.getElementById("saveQuickNoteBtn").addEventListener("click", () => {
      const text = document.getElementById("quickNoteText").value.trim();
      if (!text) return;
      quickNotes.unshift({ ts: new Date().toISOString(), text });
      document.getElementById("quickNoteText").value = "";
      renderQuickNotes();
      if (window.showToast) window.showToast({ type: "success", title: "Note saved", msg: "Visible only in this session." });
    });
  })();
  