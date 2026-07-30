
/* ==========================================================================
   case-details.js — page module for app/case-details.html
   Depends on: CASES_DATA, ALERTS_DATA, ANALYSTS_DATA
   ========================================================================== */

   (function () {
    const STATUS_LABEL = { open: "Open", in_progress: "In Progress", pending_review: "Pending Review", closed: "Closed" };
    const STATUS_BADGE = { open: "badge-info", in_progress: "badge-warning", pending_review: "badge-neutral", closed: "badge-success" };
    const now = new Date("2026-07-24T09:58:00Z");
  
    const params = new URLSearchParams(window.location.search);
    const id = params.get("id");
    const kase = CASES_DATA.find((c) => c.id === id) || CASES_DATA[0];
  
    function slaState() {
      if (kase.status === "closed") return "ok";
      const hoursLeft = (new Date(kase.slaDue).getTime() - now.getTime()) / 3600000;
      if (hoursLeft < 0) return "breach";
      if (hoursLeft < 4) return "warn";
      return "ok";
    }
    function slaLabel() {
      if (kase.status === "closed") return "SLA met";
      const hoursLeft = Math.round((new Date(kase.slaDue).getTime() - now.getTime()) / 3600000);
      return hoursLeft < 0 ? `${Math.abs(hoursLeft)}h overdue` : `${hoursLeft}h left on SLA`;
    }
  
    document.getElementById("breadcrumbCaseId").textContent = kase.title;
    document.getElementById("caseTitle").textContent = kase.title;
    document.getElementById("casePriorityPill").innerHTML = `<span class="priority-pill p-${kase.priority}">${kase.priority}</span>`;
    document.getElementById("caseSevBadge").innerHTML = XDRUtils.severityBadge(kase.severity);
    document.getElementById("caseStatusBadge").innerHTML = `<span class="badge ${STATUS_BADGE[kase.status]}">${STATUS_LABEL[kase.status]}</span>`;
    document.getElementById("caseMeta").innerHTML = `Owned by <strong>${kase.owner}</strong> · opened ${XDRUtils.formatTime(kase.createdAt)} · ${kase.id}`;
    document.getElementById("caseSlaBadge").innerHTML = `<span class="sla-badge sla-${slaState()}"><i class="bi bi-stopwatch"></i> ${slaLabel()}</span>`;
  
    // ---------- Indicators ----------
    document.getElementById("indicatorsList").innerHTML = kase.indicators.map((ioc) => `
      <span class="indicator-chip"><i class="bi bi-bullseye"></i>${XDRUtils.escapeHtml(ioc)}</span>`).join("");
  
    // ---------- Related alerts ----------
    const related = ALERTS_DATA.filter((a) => kase.relatedAlerts.includes(a.id));
    document.getElementById("relatedAlertsCaseBody").innerHTML = related.length
      ? related.map((a) => `
          <tr>
            <td><a href="alert-details.html?id=${a.id}" style="color:var(--text);font-weight:600;text-decoration:none;">${XDRUtils.escapeHtml(a.title)}</a></td>
            <td>${XDRUtils.severityBadge(a.severity)}</td>
            <td>${a.host}</td>
            <td><span class="badge ${a.status === "closed" ? "badge-success" : a.status === "investigating" ? "badge-warning" : "badge-info"}">${a.status}</span></td>
          </tr>`).join("")
      : `<tr><td colspan="4"><div class="empty-state"><i class="bi bi-inbox"></i><h3>No related alerts</h3><p>This case has no linked alerts in the current dataset.</p></div></td></tr>`;
  
    // ---------- Recommended actions ----------
    document.getElementById("recActionsList").innerHTML = kase.recommendedActions.map((a) => `
      <div class="rec-action-row"><i class="bi bi-arrow-right-circle"></i><span class="text-sm">${XDRUtils.escapeHtml(a)}</span></div>`).join("");
  
    // ---------- Notes ----------
    function renderNotes() {
      document.getElementById("notesList").innerHTML = kase.notes.map((n) => `
        <div class="note-item">
          <span class="avatar avatar-sm">${(n.author.match(/\b\w/g) || ["?"]).join("").slice(0, 2).toUpperCase()}</span>
          <div class="note-body">
            <div class="d-flex justify-content-between"><span class="note-author">${n.author}</span><span class="note-time">${XDRUtils.formatTime(n.ts)}</span></div>
            <p class="mb-0 mt-1">${XDRUtils.escapeHtml(n.text)}</p>
          </div>
        </div>`).join("");
    }
    renderNotes();
  
    document.getElementById("addNoteBtn").addEventListener("click", () => {
      const text = document.getElementById("newNoteText").value.trim();
      if (!text) return;
      kase.notes.push({ author: "Aria Reyes", ts: new Date().toISOString(), text });
      document.getElementById("newNoteText").value = "";
      renderNotes();
      if (window.showToast) window.showToast({ type: "success", title: "Note added" });
    });
  
    // ---------- Activity feed (synthesized) ----------
    const activity = [
      { ts: kase.createdAt, label: `Case opened by ${kase.owner}` },
      ...related.slice(0, 4).map((a) => ({ ts: a.ts, label: `Linked alert: ${a.title}` })),
      ...kase.notes.slice(1).map((n) => ({ ts: n.ts, label: `${n.author} added a note` })),
    ].sort((a, b) => new Date(b.ts) - new Date(a.ts));
  
    document.getElementById("activityTimeline").innerHTML = activity.map((ev) => `
      <div class="timeline-item sev-info">
        <div class="timeline-time">${XDRUtils.formatTime(ev.ts)}</div>
        <strong>${XDRUtils.escapeHtml(ev.label)}</strong>
      </div>`).join("");
  
    // ---------- Header actions ----------
    document.getElementById("reassignBtn").addEventListener("click", () => {
      if (window.showToast) window.showToast({ type: "info", title: "Reassign case", msg: "Case reassignment would open the analyst picker here." });
    });
    document.getElementById("closeCaseBtn").addEventListener("click", () => {
      kase.status = "closed";
      document.getElementById("caseStatusBadge").innerHTML = `<span class="badge ${STATUS_BADGE[kase.status]}">${STATUS_LABEL[kase.status]}</span>`;
      document.getElementById("caseSlaBadge").innerHTML = `<span class="sla-badge sla-ok"><i class="bi bi-stopwatch"></i> SLA met</span>`;
      if (window.showToast) window.showToast({ type: "danger", title: "Case closed", msg: kase.title });
    });
  })();
  