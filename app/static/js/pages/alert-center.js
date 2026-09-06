/* ==========================================================================
   alert-center.js
   Live Alert Center Page Module
   Uses:
     - /alert-center/data
     - XDRTable (core/datatable.js)
     - XDRUtils
   ========================================================================== */

(function () {
  "use strict";

  let alertData = [];
  let activeAlertId = null;
  let activeAlertTitle = "";

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

  function renderKpiMetrics(stats) {
    if (!stats) return;
    const totalEl = document.getElementById("kpiTotal");
    const critEl = document.getElementById("kpiCritical");
    const highEl = document.getElementById("kpiHigh");
    const medEl = document.getElementById("kpiMedium");
    const newEl = document.getElementById("kpiNew");
    const resEl = document.getElementById("kpiResolved");

    if (totalEl) totalEl.textContent = stats.total || 0;
    if (critEl) critEl.textContent = stats.critical || 0;
    if (highEl) highEl.textContent = stats.high || 0;
    if (medEl) medEl.textContent = stats.medium || 0;
    if (newEl) newEl.textContent = stats.new || 0;
    if (resEl) resEl.textContent = stats.resolved || 0;
  }

  function updateSummary(total, items) {
    const summary = document.getElementById("alertCountSummary");
    if (!summary) return;
    const count = total !== undefined ? total : items.length;
    const newCount = items.filter((a) => a.status === "new").length;
    const investigatingCount = items.filter((a) => a.status === "investigating").length;
    summary.textContent = `${count} total alerts · ${newCount} new · ${investigatingCount} investigating`;
  }

  function populateFilterDropdowns(items) {
    const catSel = document.getElementById("filterCategory");
    const srcSel = document.getElementById("filterSource");

    if (catSel && catSel.options.length <= 1) {
      const categories = [...new Set(items.map((a) => a.category).filter(Boolean))].sort();
      categories.forEach((cat) => {
        catSel.insertAdjacentHTML("beforeend", `<option value="${escapeHtml(cat)}">${escapeHtml(cat)}</option>`);
      });
    }

    if (srcSel && srcSel.options.length <= 1) {
      const sources = [...new Set(items.map((a) => a.source).filter(Boolean))].sort();
      sources.forEach((src) => {
        srcSel.insertAdjacentHTML("beforeend", `<option value="${escapeHtml(src)}">${escapeHtml(src)}</option>`);
      });
    }
  }

  /* ============================================================
     TABLE COLUMNS
     ============================================================ */

  const columns = [
    {
      key: "alert_id",
      label: "Alert ID",
      sortable: true,
      render: (r) =>
        `<a href="/alert-center/${encodeURIComponent(r.alert_id)}" class="cell-mono text-sm fw-bold" style="color:var(--text); text-decoration:none;">${escapeHtml(r.alert_id)}</a>`,
    },
    {
      key: "title",
      label: "Title / Detail",
      sortable: true,
      render: (r) => {
        const hostSub = r.affected_host ? `${escapeHtml(r.affected_host)}` : "";
        const catSub = r.category ? ` &middot; ${escapeHtml(r.category)}` : "";
        return `<div>
          <a href="/alert-center/${encodeURIComponent(r.alert_id)}" style="color:var(--text);font-weight:600;text-decoration:none;">${escapeHtml(r.title)}</a>
          <div class="text-xs text-muted" style="margin-top:2px;">${hostSub}${catSub}</div>
        </div>`;
      },
    },
    {
      key: "severity",
      label: "Severity",
      sortable: true,
      render: (r) => {
        if (window.XDRUtils && window.XDRUtils.severityBadge) {
          return window.XDRUtils.severityBadge(r.severity);
        }
        const sevClass = r.severity === "critical" ? "badge-danger" : r.severity === "high" ? "badge-warning" : "badge-info";
        return `<span class="badge ${sevClass}">${escapeHtml(r.severity)}</span>`;
      },
    },
    {
      key: "status",
      label: "Status",
      sortable: true,
      render: (r) => {
        const badgeClass = STATUS_BADGE[r.status] || "badge-neutral";
        const label = STATUS_LABEL[r.status] || r.status;
        return `<span class="badge ${badgeClass}">${escapeHtml(label)}</span>`;
      },
    },
    {
      key: "source",
      label: "Source",
      sortable: true,
      render: (r) => `<span class="text-sm">${escapeHtml(r.source || "—")}</span>`,
    },
    {
      key: "affected_host",
      label: "Host / Asset",
      sortable: true,
      render: (r) => `<span class="cell-mono text-sm">${escapeHtml(r.affected_host || r.affected_asset || "—")}</span>`,
    },
    {
      key: "created_at",
      label: "Created",
      sortable: true,
      render: (r) => {
        if (window.XDRUtils && window.XDRUtils.formatTime) {
          return `<span class="cell-mono text-sm">${window.XDRUtils.formatTime(r.created_at)}</span>`;
        }
        return `<span class="cell-mono text-sm">${escapeHtml(r.created_at || "—")}</span>`;
      },
    },
    {
      key: "actions",
      label: "",
      sortable: false,
      render: (r) => {
        const canAck = r.status === "new";
        const canInvestigate = r.status === "new" || r.status === "acknowledged";
        const canResolve = r.status !== "resolved";

        return `<div class="row-actions">
          <a href="/alert-center/${encodeURIComponent(r.alert_id)}" class="btn btn-icon btn-ghost btn-sm" title="View Details">
            <i class="bi bi-eye"></i>
          </a>
          ${
            canAck
              ? `<button class="btn btn-icon btn-ghost btn-sm text-primary action-ack" data-id="${escapeHtml(r.alert_id)}" title="Acknowledge"><i class="bi bi-check2"></i></button>`
              : ""
          }
          ${
            canInvestigate
              ? `<button class="btn btn-icon btn-ghost btn-sm text-warning action-investigate" data-id="${escapeHtml(r.alert_id)}" title="Investigate"><i class="bi bi-search"></i></button>`
              : ""
          }
          <button class="btn btn-icon btn-ghost btn-sm action-assign" data-id="${escapeHtml(r.alert_id)}" data-title="${escapeHtml(r.title)}" data-assigned="${escapeHtml(r.assigned_to || "")}" title="Assign">
            <i class="bi bi-person-plus"></i>
          </button>
          ${
            canResolve
              ? `<button class="btn btn-icon btn-ghost btn-sm text-success action-resolve" data-id="${escapeHtml(r.alert_id)}" data-title="${escapeHtml(r.title)}" title="Resolve"><i class="bi bi-check-circle"></i></button>`
              : ""
          }
        </div>`;
      },
    },
  ];

  /* ============================================================
     FETCH DATA & INITIALIZATION
     ============================================================ */

  let table = null;

  async function fetchAlerts() {
    try {
      const search = document.getElementById("alertSearch")?.value?.trim() || "";
      const sev = document.getElementById("filterSev")?.value || "";
      const status = document.getElementById("filterStatus")?.value || "";
      const category = document.getElementById("filterCategory")?.value || "";
      const source = document.getElementById("filterSource")?.value || "";
      const assignee = document.getElementById("filterAssignee")?.value || "";

      const params = new URLSearchParams();
      if (search) params.set("search", search);
      if (sev) params.set("severity", sev);
      if (status) params.set("status", status);
      if (category) params.set("category", category);
      if (source) params.set("source", source);
      if (assignee) params.set("assigned_to", assignee);
      params.set("per_page", "100");

      const res = await fetch(`/alert-center/data?${params.toString()}`, {
        headers: { Accept: "application/json" },
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();

      if (!json.success) {
        throw new Error(json.message || "Failed to load alerts.");
      }

      alertData = json.data || [];
      renderKpiMetrics(json.stats);
      updateSummary(json.total, alertData);
      populateFilterDropdowns(alertData);

      if (!table) {
        table = new XDRTable({
          tableEl: document.getElementById("alertsTable"),
          searchInput: document.getElementById("alertSearch"),
          paginationEl: document.getElementById("alertsPagination"),
          data: alertData,
          pageSize: 10,
          searchKeys: ["alert_id", "title", "affected_host", "category", "source"],
          columns,
          onRowsChange: wireTableActions,
        });
        table.state.sortKey = "created_at";
        table.state.sortDir = -1;
      } else {
        table.setData(alertData);
      }

      wireTableActions();
    } catch (err) {
      console.error("Alert load error:", err);
      showToast("danger", "Alert Center Error", err.message || "Could not retrieve alert records.");
    }
  }

  /* ============================================================
     WIRE ACTION BUTTONS
     ============================================================ */

  function wireTableActions() {
    // Acknowledge Action
    document.querySelectorAll(".action-ack").forEach((btn) => {
      btn.onclick = async () => {
        const id = btn.dataset.id;
        try {
          const res = await fetch(`/alert-center/${encodeURIComponent(id)}/acknowledge`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
          });
          const json = await res.json();
          if (!json.success) throw new Error(json.message);
          showToast("success", "Alert Acknowledged", `Alert ${id} is now acknowledged.`);
          fetchAlerts();
        } catch (err) {
          showToast("danger", "Action Failed", err.message);
        }
      };
    });

    // Mark Investigating Action
    document.querySelectorAll(".action-investigate").forEach((btn) => {
      btn.onclick = async () => {
        const id = btn.dataset.id;
        try {
          const res = await fetch(`/alert-center/${encodeURIComponent(id)}/status`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status: "investigating", notes: "Investigation initiated from alert table." }),
          });
          const json = await res.json();
          if (!json.success) throw new Error(json.message);
          showToast("info", "Investigation Started", `Alert ${id} status set to Investigating.`);
          fetchAlerts();
        } catch (err) {
          showToast("danger", "Action Failed", err.message);
        }
      };
    });

    // Open Assign Modal
    document.querySelectorAll(".action-assign").forEach((btn) => {
      btn.onclick = () => {
        activeAlertId = btn.dataset.id;
        activeAlertTitle = btn.dataset.title || "";
        const titleEl = document.getElementById("assignAlertTitle");
        const idEl = document.getElementById("assignAlertId");
        const selEl = document.getElementById("assignAnalystSelect");

        if (titleEl) titleEl.textContent = activeAlertTitle;
        if (idEl) idEl.textContent = activeAlertId;
        if (selEl) selEl.value = btn.dataset.assigned || "";

        if (window.xdrOpenModal) {
          window.xdrOpenModal("assignModal");
        }
      };
    });

    // Open Resolve Modal
    document.querySelectorAll(".action-resolve").forEach((btn) => {
      btn.onclick = () => {
        activeAlertId = btn.dataset.id;
        activeAlertTitle = btn.dataset.title || "";
        const titleEl = document.getElementById("resolveAlertTitle");
        const idEl = document.getElementById("resolveAlertId");

        if (titleEl) titleEl.textContent = activeAlertTitle;
        if (idEl) idEl.textContent = activeAlertId;

        if (window.xdrOpenModal) {
          window.xdrOpenModal("resolveModal");
        }
      };
    });
  }

  /* ============================================================
     WIRE MODAL CONFIRMATIONS & CONTROLS
     ============================================================ */

  document.addEventListener("DOMContentLoaded", () => {
    // Refresh button
    const refreshBtn = document.getElementById("refreshAlertsBtn");
    if (refreshBtn) refreshBtn.addEventListener("click", fetchAlerts);

    // Filter changes
    ["filterSev", "filterStatus", "filterCategory", "filterSource", "filterAssignee"].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.addEventListener("change", fetchAlerts);
    });

    // Clear filters
    const clearBtn = document.getElementById("clearFilters");
    if (clearBtn) {
      clearBtn.addEventListener("click", () => {
        const search = document.getElementById("alertSearch");
        if (search) search.value = "";
        ["filterSev", "filterStatus", "filterCategory", "filterSource", "filterAssignee"].forEach((id) => {
          const el = document.getElementById(id);
          if (el) el.value = "";
        });
        fetchAlerts();
      });
    }

    // Confirm Assignment
    const confirmAssignBtn = document.getElementById("confirmAssignBtn");
    if (confirmAssignBtn) {
      confirmAssignBtn.addEventListener("click", async () => {
        if (!activeAlertId) return;
        const selEl = document.getElementById("assignAnalystSelect");
        const noteEl = document.getElementById("assignNote");
        const userId = selEl ? selEl.value : null;
        const notes = noteEl ? noteEl.value.trim() : "";

        try {
          const res = await fetch(`/alert-center/${encodeURIComponent(activeAlertId)}/assign`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ assigned_to: userId ? parseInt(userId, 10) : null, notes }),
          });
          const json = await res.json();
          if (!json.success) throw new Error(json.message);

          showToast("success", "Assignment Saved", `Alert ${activeAlertId} assignment updated.`);
          if (window.xdrCloseModal) window.xdrCloseModal("assignModal");
          if (noteEl) noteEl.value = "";
          fetchAlerts();
        } catch (err) {
          showToast("danger", "Assignment Failed", err.message);
        }
      });
    }

    // Confirm Resolution
    const confirmResolveBtn = document.getElementById("confirmResolveBtn");
    if (confirmResolveBtn) {
      confirmResolveBtn.addEventListener("click", async () => {
        if (!activeAlertId) return;
        const reasonSel = document.getElementById("resolveReasonSelect");
        const notesEl = document.getElementById("resolveNotes");

        const reason = reasonSel ? reasonSel.value : "";
        const customNotes = notesEl ? notesEl.value.trim() : "";
        const resolutionNotes = customNotes ? `${reason}: ${customNotes}` : reason;

        if (!resolutionNotes) {
          showToast("warning", "Missing Notes", "Please provide resolution notes.");
          return;
        }

        try {
          const res = await fetch(`/alert-center/${encodeURIComponent(activeAlertId)}/resolve`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ resolution_notes: resolutionNotes }),
          });
          const json = await res.json();
          if (!json.success) throw new Error(json.message);

          showToast("success", "Alert Resolved", `Alert ${activeAlertId} marked as resolved.`);
          if (window.xdrCloseModal) window.xdrCloseModal("resolveModal");
          if (notesEl) notesEl.value = "";
          fetchAlerts();
        } catch (err) {
          showToast("danger", "Resolution Failed", err.message);
        }
      });
    }

    // Confirm Create Alert
    const confirmCreateBtn = document.getElementById("confirmCreateAlertBtn");
    if (confirmCreateBtn) {
      confirmCreateBtn.addEventListener("click", async () => {
        const title = document.getElementById("newAlertTitle")?.value?.trim();
        const severity = document.getElementById("newAlertSeverity")?.value || "medium";
        const category = document.getElementById("newAlertCategory")?.value?.trim() || "Security";
        const source = document.getElementById("newAlertSource")?.value?.trim() || "Manual";
        const host = document.getElementById("newAlertHost")?.value?.trim();
        const mitreId = document.getElementById("newAlertMitreId")?.value?.trim();
        const assignee = document.getElementById("newAlertAssignee")?.value;
        const description = document.getElementById("newAlertDesc")?.value?.trim();

        if (!title) {
          showToast("warning", "Validation Error", "Alert title is required.");
          return;
        }

        const payload = {
          title,
          severity,
          category,
          source,
          affected_host: host,
          affected_asset: host,
          mitre_id: mitreId,
          assigned_to: assignee ? parseInt(assignee, 10) : null,
          description,
        };

        try {
          const res = await fetch("/alert-center/create", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
          });
          const json = await res.json();
          if (!json.success) throw new Error(json.message);

          showToast("success", "Alert Created", `Created alert ${json.data.alert_id}`);
          if (window.xdrCloseModal) window.xdrCloseModal("createAlertModal");

          // Reset inputs
          document.getElementById("newAlertTitle").value = "";
          document.getElementById("newAlertDesc").value = "";
          fetchAlerts();
        } catch (err) {
          showToast("danger", "Creation Failed", err.message);
        }
      });
    }

    // Initial fetch
    fetchAlerts();
  });
})();

