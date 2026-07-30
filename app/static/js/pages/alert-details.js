/* ==========================================================================
   alert-details.js — page module for app/alert-details.html
   Depends on: ALERTS_DATA, ANALYSTS_DATA
   ========================================================================== */

   (function () {
    const STATUS_BADGE = { open: "badge-info", investigating: "badge-warning", closed: "badge-success" };
  
    const params = new URLSearchParams(window.location.search);
    const id = params.get("id");
    const alert = ALERTS_DATA.find((a) => a.id === id) || ALERTS_DATA[0];
  
    document.getElementById("breadcrumbAlertId").textContent = alert.title;
    document.getElementById("alertTitle").textContent = alert.title;
    document.getElementById("alertDesc").textContent = alert.description;
    document.getElementById("alertPriorityPill").innerHTML = `<span class="priority-pill p-${alert.priority}">${alert.priority}</span>`;
    document.getElementById("alertSevBadge").innerHTML = XDRUtils.severityBadge(alert.severity);
    document.getElementById("alertStatusBadge").innerHTML = `<span class="badge ${STATUS_BADGE[alert.status]}">${alert.status}</span>`;
    document.getElementById("alertMitreRow").innerHTML = `<span class="mitre-chip">${alert.mitreId} <span class="tname">${alert.mitreName}</span></span>`;
  
    document.getElementById("statAsset").textContent = alert.asset;
    document.getElementById("statSource").textContent = alert.source;
    document.getElementById("statRule").innerHTML = `<a href="rule-details.html?id=${alert.ruleId}" style="color:inherit;">${alert.ruleId}</a>`;
    document.getElementById("statAnalyst").textContent = alert.assignedAnalyst || "Unassigned";
  
    // ---------- Related alerts — same host ----------
    const related = ALERTS_DATA.filter((a) => a.host === alert.host && a.id !== alert.id).slice(0, 6);
    document.getElementById("relatedAlertsBody").innerHTML = related.length
      ? related.map((a) => `
          <tr>
            <td><a href="alert-details.html?id=${a.id}" style="color:var(--text);font-weight:600;text-decoration:none;">${XDRUtils.escapeHtml(a.title)}</a></td>
            <td>${XDRUtils.severityBadge(a.severity)}</td>
            <td><span class="cell-mono text-sm">${XDRUtils.formatTime(a.ts)}</span></td>
            <td><span class="badge ${STATUS_BADGE[a.status]}">${a.status}</span></td>
          </tr>`).join("")
      : `<tr><td colspan="4"><div class="empty-state"><i class="bi bi-inbox"></i><h3>No related alerts</h3><p>No other alerts on ${alert.host} right now.</p></div></td></tr>`;
  
    // ---------- Timeline ----------
    const timelineEvents = [
      { ts: alert.ts, label: `Alert generated from ${alert.source}`, sev: alert.severity },
      ...(alert.assignedAnalyst ? [{ ts: alert.ts, label: `Assigned to ${alert.assignedAnalyst}`, sev: "low" }] : []),
      ...alert.comments.map((c) => ({ ts: c.ts, label: `${c.author} commented`, sev: "info" })),
    ].sort((a, b) => new Date(a.ts) - new Date(b.ts));
  
    document.getElementById("alertTimeline").innerHTML = timelineEvents.map((t) => `
      <div class="timeline-item sev-${t.sev}">
        <div class="timeline-time">${XDRUtils.formatTime(t.ts)}</div>
        <strong>${XDRUtils.escapeHtml(t.label)}</strong>
      </div>`).join("");
  
    // ---------- Evidence (synthesized from alert context) ----------
    const evidenceItems = [
      { icon: "bi-file-earmark-text", name: `${alert.source} raw event`, sub: `log-explorer.html · ${alert.host}` },
      { icon: "bi-hdd-network", name: alert.asset, sub: `asset-details.html · ${alert.host}` },
      { icon: "bi-diagram-3", name: `MITRE ${alert.mitreId}`, sub: alert.mitreName },
    ];
    document.getElementById("evidenceList").innerHTML = evidenceItems.map((e) => `
      <div class="evidence-item">
        <span class="ev-icon"><i class="bi ${e.icon}"></i></span>
        <div class="ev-meta"><div class="ev-name">${e.name}</div><div class="ev-sub">${e.sub}</div></div>
      </div>`).join("");
  
    // ---------- Comments ----------
    function renderComments() {
      document.getElementById("commentsList").innerHTML = alert.comments.length
        ? alert.comments.map((c) => `
            <div class="note-item">
              <span class="avatar avatar-sm">${c.initials}</span>
              <div class="note-body">
                <div class="d-flex justify-content-between"><span class="note-author">${c.author}</span><span class="note-time">${XDRUtils.formatTime(c.ts)}</span></div>
                <p class="mb-0 mt-1">${XDRUtils.escapeHtml(c.text)}</p>
              </div>
            </div>`).join("")
        : `<p class="text-muted text-sm">No comments yet — be the first to add investigation notes.</p>`;
    }
    renderComments();
  
    document.getElementById("addCommentBtn").addEventListener("click", () => {
      const text = document.getElementById("newCommentText").value.trim();
      if (!text) return;
      alert.comments.push({ author: "Aria Reyes", initials: "AR", ts: new Date().toISOString(), text });
      document.getElementById("newCommentText").value = "";
      renderComments();
      if (window.showToast) window.showToast({ type: "success", title: "Comment added" });
    });
  
    // ---------- Header actions ----------
    document.getElementById("assignBtn").addEventListener("click", () => {
      if (window.showToast) window.showToast({ type: "info", title: "Open Alert Center to assign", msg: "Use the Assign action from the alerts table." });
      setTimeout(() => { window.location.href = "alerts.html"; }, 700);
    });
    document.getElementById("investigateBtn").addEventListener("click", () => {
      if (alert.status === "open") alert.status = "investigating";
      document.getElementById("alertStatusBadge").innerHTML = `<span class="badge ${STATUS_BADGE[alert.status]}">${alert.status}</span>`;
      if (window.showToast) window.showToast({ type: "info", title: "Investigation started", msg: alert.title });
    });
    document.getElementById("closeBtn").addEventListener("click", () => {
      alert.status = "closed";
      document.getElementById("alertStatusBadge").innerHTML = `<span class="badge ${STATUS_BADGE[alert.status]}">${alert.status}</span>`;
      if (window.showToast) window.showToast({ type: "danger", title: "Alert closed", msg: alert.title });
    });
  })();
  