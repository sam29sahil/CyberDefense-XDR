/* ==========================================================================
   alert-details.js
   Single Alert Detail Page Module
   Uses:
     - /alert-center/<alert_id>/data
     - XDRUtils
   ========================================================================== */

(function () {
  "use strict";

  const headerCard = document.getElementById("alertHeaderCard");
  if (!headerCard) return;

  const alertId = headerCard.dataset.alertId;
  if (!alertId) return;

  function escapeHtml(val) {
    if (val === null || val === undefined) return "";
    return String(val)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function showToast(type, title, msg) {
    if (window.showToast) {
      window.showToast({ type, title, msg });
    }
  }

  const STATUS_BADGE = {
    new: "badge-info",
    acknowledged: "badge-secondary",
    investigating: "badge-warning",
    escalated: "badge-danger",
    resolved: "badge-success",
    false_positive: "badge-neutral",
    suppressed: "badge-neutral",
  };

  const STATUS_LABEL = {
    new: "New",
    acknowledged: "Acknowledged",
    investigating: "Investigating",
    escalated: "Escalated",
    resolved: "Resolved",
    false_positive: "False Positive",
    suppressed: "Suppressed",
  };

  async function loadAlertData() {
    try {
      const res = await fetch(`/alert-center/${encodeURIComponent(alertId)}/data`, {
        headers: { Accept: "application/json" },
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      if (!json.success) throw new Error(json.message || "Failed to load alert details.");

      const alert = json.data;

      // Render Badges
      const sevBadge = document.getElementById("alertSevBadge");
      if (sevBadge) {
        if (window.XDRUtils && window.XDRUtils.severityBadge) {
          sevBadge.innerHTML = window.XDRUtils.severityBadge(alert.severity);
        } else {
          sevBadge.className = `badge ${alert.severity === "critical" ? "badge-danger" : alert.severity === "high" ? "badge-warning" : "badge-info"}`;
          sevBadge.textContent = alert.severity;
        }
      }

      const statusBadge = document.getElementById("alertStatusBadge");
      if (statusBadge) {
        statusBadge.className = `badge ${STATUS_BADGE[alert.status] || "badge-neutral"}`;
        statusBadge.textContent = STATUS_LABEL[alert.status] || alert.status;
      }

      // Render Related Alerts
      const relatedBody = document.getElementById("relatedAlertsBody");
      if (relatedBody) {
        const related = json.related || [];
        if (related.length === 0) {
          relatedBody.innerHTML = `<tr><td colspan="3" class="text-muted text-center py-3">No other alerts for this host.</td></tr>`;
        } else {
          relatedBody.innerHTML = related
            .map(
              (r) => `<tr>
                <td>
                  <a href="/alert-center/${encodeURIComponent(r.alert_id)}" style="color:var(--text);font-weight:600;text-decoration:none;">${escapeHtml(r.alert_id)}</a>
                  <div class="text-xs text-muted">${escapeHtml(r.title)}</div>
                </td>
                <td><span class="badge ${r.severity === "critical" ? "badge-danger" : r.severity === "high" ? "badge-warning" : "badge-info"}">${escapeHtml(r.severity)}</span></td>
                <td><span class="badge ${STATUS_BADGE[r.status] || "badge-neutral"}">${escapeHtml(STATUS_LABEL[r.status] || r.status)}</span></td>
              </tr>`
            )
            .join("");
        }
      }
    } catch (err) {
      console.error("Failed to load alert details:", err);
      showToast("danger", "Detail Load Error", err.message);
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    loadAlertData();

    // Acknowledge Action
    const btnAck = document.getElementById("btnAcknowledge");
    if (btnAck) {
      btnAck.addEventListener("click", async () => {
        try {
          const res = await fetch(`/alert-center/${encodeURIComponent(alertId)}/acknowledge`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
          });
          const json = await res.json();
          if (!json.success) throw new Error(json.message);
          showToast("success", "Acknowledged", `Alert ${alertId} acknowledged.`);
          window.location.reload();
        } catch (err) {
          showToast("danger", "Action Failed", err.message);
        }
      });
    }

    // Mark Investigating
    const btnInv = document.getElementById("btnInvestigate");
    if (btnInv) {
      btnInv.addEventListener("click", async () => {
        try {
          const res = await fetch(`/alert-center/${encodeURIComponent(alertId)}/status`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status: "investigating", notes: "Investigation initiated by analyst." }),
          });
          const json = await res.json();
          if (!json.success) throw new Error(json.message);
          showToast("info", "Status Updated", "Alert marked as Investigating.");
          window.location.reload();
        } catch (err) {
          showToast("danger", "Action Failed", err.message);
        }
      });
    }

    // Reopen Alert
    const btnReopen = document.getElementById("btnReopen");
    if (btnReopen) {
      btnReopen.addEventListener("click", async () => {
        try {
          const res = await fetch(`/alert-center/${encodeURIComponent(alertId)}/status`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status: "investigating", notes: "Reopened for further review." }),
          });
          const json = await res.json();
          if (!json.success) throw new Error(json.message);
          showToast("info", "Alert Reopened", "Alert returned to Investigating status.");
          window.location.reload();
        } catch (err) {
          showToast("danger", "Action Failed", err.message);
        }
      });
    }

    // Confirm Assign
    const btnConfirmAssign = document.getElementById("btnConfirmAssign");
    if (btnConfirmAssign) {
      btnConfirmAssign.addEventListener("click", async () => {
        const sel = document.getElementById("detailAssignSelect");
        const note = document.getElementById("detailAssignNote");
        const userId = sel ? sel.value : null;
        const notes = note ? note.value.trim() : "";

        try {
          const res = await fetch(`/alert-center/${encodeURIComponent(alertId)}/assign`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ assigned_to: userId ? parseInt(userId, 10) : null, notes }),
          });
          const json = await res.json();
          if (!json.success) throw new Error(json.message);
          showToast("success", "Assigned", "Alert assignee updated.");
          if (window.xdrCloseModal) window.xdrCloseModal("assignModal");
          window.location.reload();
        } catch (err) {
          showToast("danger", "Assignment Failed", err.message);
        }
      });
    }

    // Confirm Resolve
    const btnConfirmResolve = document.getElementById("btnConfirmResolve");
    if (btnConfirmResolve) {
      btnConfirmResolve.addEventListener("click", async () => {
        const reasonSel = document.getElementById("detailResolveReasonSelect");
        const notesEl = document.getElementById("detailResolveNotes");

        const reason = reasonSel ? reasonSel.value : "";
        const custom = notesEl ? notesEl.value.trim() : "";
        const resolutionNotes = custom ? `${reason}: ${custom}` : reason;

        if (!resolutionNotes) {
          showToast("warning", "Missing Notes", "Please supply resolution notes.");
          return;
        }

        try {
          const res = await fetch(`/alert-center/${encodeURIComponent(alertId)}/resolve`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ resolution_notes: resolutionNotes }),
          });
          const json = await res.json();
          if (!json.success) throw new Error(json.message);
          showToast("success", "Alert Resolved", `Alert ${alertId} resolved.`);
          if (window.xdrCloseModal) window.xdrCloseModal("resolveModal");
          window.location.reload();
        } catch (err) {
          showToast("danger", "Resolution Failed", err.message);
        }
      });
    }

    // Post Note
    const btnPostNote = document.getElementById("btnPostNote");
    if (btnPostNote) {
      btnPostNote.addEventListener("click", async () => {
        const noteEl = document.getElementById("appendNoteText");
        const notes = noteEl ? noteEl.value.trim() : "";
        if (!notes) {
          showToast("warning", "Empty Note", "Please enter a note before posting.");
          return;
        }

        const currentStatus = headerCard.dataset.alertStatus || "investigating";
        try {
          const res = await fetch(`/alert-center/${encodeURIComponent(alertId)}/status`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status: currentStatus, notes }),
          });
          const json = await res.json();
          if (!json.success) throw new Error(json.message);
          showToast("success", "Note Added", "Investigation note appended.");
          window.location.reload();
        } catch (err) {
          showToast("danger", "Note Failed", err.message);
        }
      });
    }

    // Create Incident from Alert
    const btnConfirmCreateInc = document.getElementById("btnConfirmCreateIncident");
    if (btnConfirmCreateInc) {
      btnConfirmCreateInc.addEventListener("click", async () => {
        const title = document.getElementById("newIncTitle")?.value?.trim();
        const severity = document.getElementById("newIncSeverity")?.value || "medium";
        const category = document.getElementById("newIncCategory")?.value?.trim() || "Security";
        const description = document.getElementById("newIncDesc")?.value?.trim();

        if (!title) {
          showToast("warning", "Missing Title", "Incident title is required.");
          return;
        }

        try {
          const res = await fetch(`/alert-center/${encodeURIComponent(alertId)}/link-incident`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              create_new: true,
              title,
              severity,
              category,
              description,
            }),
          });
          const json = await res.json();
          if (!json.success) throw new Error(json.message);
          showToast("success", "Incident Created", `Created Incident ${json.data.incident.incident_id}`);
          if (window.xdrCloseModal) window.xdrCloseModal("createIncidentModal");
          window.location.reload();
        } catch (err) {
          showToast("danger", "Escalation Failed", err.message);
        }
      });
    }

    // Link Existing Incident
    const btnConfirmLinkInc = document.getElementById("btnConfirmLinkIncident");
    if (btnConfirmLinkInc) {
      btnConfirmLinkInc.addEventListener("click", async () => {
        const incIdInput = document.getElementById("linkIncIdInput")?.value?.trim();
        if (!incIdInput) {
          showToast("warning", "Missing ID", "Incident ID is required.");
          return;
        }

        try {
          const res = await fetch(`/alert-center/${encodeURIComponent(alertId)}/link-incident`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ incident_id: incIdInput }),
          });
          const json = await res.json();
          if (!json.success) throw new Error(json.message);
          showToast("success", "Incident Linked", `Alert linked to ${incIdInput}.`);
          if (window.xdrCloseModal) window.xdrCloseModal("linkIncidentModal");
          window.location.reload();
        } catch (err) {
          showToast("danger", "Link Failed", err.message);
        }
      });
    }
  });
})();