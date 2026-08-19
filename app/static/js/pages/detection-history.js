/* ==========================================================================
   detection-history.js — Detection History
   Uses live backend data from:
   GET /detection/history/data

   Depends on:
   - XDRTable
   - XDRUtils
   - toast.js
   ========================================================================== */

(function () {
  "use strict";

  let data = [];
  let table = null;

  const STATUS_BADGE = {
    new: "badge-info",
    investigating: "badge-warning",
    resolved: "badge-success",
    false_positive: "badge-neutral",
  };

  // ============================================================
  // HELPERS
  // ============================================================

  function escape(value) {
    if (window.XDRUtils && typeof XDRUtils.escapeHtml === "function") {
      return XDRUtils.escapeHtml(value ?? "");
    }

    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function showToast(type, title, msg) {
    if (window.showToast) {
      window.showToast({
        type,
        title,
        msg,
      });
    }
  }

  function formatTimestamp(value) {
    if (!value) return "—";

    return String(value)
      .replace("T", " ")
      .replace("Z", "");
  }

  function updateSummary() {
    const summary = document.getElementById("historyCountSummary");
    const critHigh = document.getElementById("statCritHigh");
    const newCount = document.getElementById("statNew");
    const investigating = document.getElementById("statInvestigating");
    const resolved = document.getElementById("statResolved");

    const criticalHighCount = data.filter(
      (event) =>
        event.severity === "critical" ||
        event.severity === "high"
    ).length;

    const newEvents = data.filter(
      (event) => event.status === "new"
    ).length;

    const investigatingEvents = data.filter(
      (event) => event.status === "investigating"
    ).length;

    const resolvedEvents = data.filter(
      (event) => event.status === "resolved"
    ).length;

    if (summary) {
      summary.textContent =
        `${data.length} events across all active rules`;
    }

    if (critHigh) {
      critHigh.textContent = criticalHighCount;
    }

    if (newCount) {
      newCount.textContent = newEvents;
    }

    if (investigating) {
      investigating.textContent = investigatingEvents;
    }

    if (resolved) {
      resolved.textContent = resolvedEvents;
    }
  }

  function populateSourceFilter() {
    const sourceSel = document.getElementById("filterSource");

    if (!sourceSel) return;

    sourceSel.innerHTML =
      `<option value="">All sources</option>`;

    const sources = [
      ...new Set(
        data
          .map((event) => event.source)
          .filter(Boolean)
      ),
    ].sort();

    sources.forEach((source) => {
      const option = document.createElement("option");

      option.value = source;
      option.textContent = source;

      sourceSel.appendChild(option);
    });
  }

  // ============================================================
  // TABLE
  // ============================================================

  function createTable() {
    const tableElement =
      document.getElementById("historyTable");

    if (!tableElement) {
      console.error(
        "Detection history table element not found."
      );
      return;
    }

    const columns = [
      {
        key: "ts",
        label: "Time",
        sortable: true,

        render: (row) => `
          <span class="cell-mono">
            ${escape(formatTimestamp(row.ts))}
          </span>
        `,
      },

      {
        key: "source",
        label: "Source",
        sortable: true,

        render: (row) => `
          <span>
            ${escape(row.source || "—")}
          </span>
        `,
      },

      {
        key: "ruleName",
        label: "Rule",
        sortable: true,

        render: (row) => {
          const ruleId = row.ruleId || "";

          return `
            <a
              href="rule-details.html?id=${encodeURIComponent(ruleId)}"
              style="color:var(--text);font-weight:600;text-decoration:none;"
            >
              ${escape(row.ruleName || "Unknown Rule")}
            </a>

            <div
              class="text-xs text-muted"
              style="margin-top:2px;"
            >
              ${
                row.mitreId
                  ? `<span class="mitre-chip">${escape(row.mitreId)}</span>`
                  : ""
              }
            </div>
          `;
        },
      },

      {
        key: "severity",
        label: "Severity",
        sortable: true,

        render: (row) => {
          if (
            window.XDRUtils &&
            typeof XDRUtils.severityBadge === "function"
          ) {
            return XDRUtils.severityBadge(row.severity);
          }

          return `
            <span class="badge badge-neutral">
              ${escape(row.severity || "unknown")}
            </span>
          `;
        },
      },

      {
        key: "host",
        label: "Hostname",
        sortable: true,

        render: (row) => `
          <span style="font-weight:600;">
            ${escape(row.host || "—")}
          </span>
        `,
      },

      {
        key: "status",
        label: "Status",
        sortable: true,

        render: (row) => {
          const status =
            String(row.status || "new").toLowerCase();

          const badge =
            STATUS_BADGE[status] || "badge-neutral";

          return `
            <span class="badge ${badge}">
              ${escape(status.replace(/_/g, " "))}
            </span>
          `;
        },
      },
    ];

    table = new XDRTable({
      tableEl: tableElement,

      searchInput:
        document.getElementById("historySearch"),

      paginationEl:
        document.getElementById("historyPagination"),

      data,

      pageSize: 12,

      searchKeys: [
        "ruleName",
        "host",
        "source",
        "mitreId",
        "severity",
        "status",
      ],

      columns,
    });

    table.state.sortKey = "ts";
    table.state.sortDir = -1;
  }

  // ============================================================
  // FILTERS
  // ============================================================

  function applyFilters() {
    if (!table) return;

    const severity =
      document.getElementById("filterSev")?.value || "";

    const status =
      document.getElementById("filterStatus")?.value || "";

    const source =
      document.getElementById("filterSource")?.value || "";

    table.setFilter((row) => {
      return (
        (!severity || row.severity === severity) &&
        (!status || row.status === status) &&
        (!source || row.source === source)
      );
    });
  }

  function setupFilters() {
    const filterIds = [
      "filterSev",
      "filterStatus",
      "filterSource",
    ];

    filterIds.forEach((id) => {
      const element = document.getElementById(id);

      if (!element) return;

      element.addEventListener(
        "change",
        applyFilters
      );
    });

    const clearButton =
      document.getElementById("clearFilters");

    if (clearButton) {
      clearButton.addEventListener("click", () => {
        const search =
          document.getElementById("historySearch");

        if (search) {
          search.value = "";
        }

        filterIds.forEach((id) => {
          const element = document.getElementById(id);

          if (element) {
            element.value = "";
          }
        });

        if (table) {
          table.state.query = "";
          table.setFilter(null);
        }
      });
    }
  }

  // ============================================================
  // EXPORT CSV
  // ============================================================

  function csvEscape(value) {
    const stringValue = String(value ?? "");

    return `"${stringValue.replace(/"/g, '""')}"`;
  }

  function exportCSV() {
    if (!data.length) {
      showToast(
        "warning",
        "Nothing to export",
        "There are no detection events available."
      );

      return;
    }

    const header = [
      "id",
      "ts",
      "ruleId",
      "ruleName",
      "severity",
      "source",
      "host",
      "status",
      "mitreId",
    ];

    const rows = data.map((event) => [
      csvEscape(event.id),
      csvEscape(event.ts),
      csvEscape(event.ruleId),
      csvEscape(event.ruleName),
      csvEscape(event.severity),
      csvEscape(event.source),
      csvEscape(event.host),
      csvEscape(event.status),
      csvEscape(event.mitreId),
    ]);

    const csv = [
      header.join(","),
      ...rows.map((row) => row.join(",")),
    ].join("\n");

    const blob = new Blob(
      [csv],
      {
        type: "text/csv;charset=utf-8;",
      }
    );

    const url =
      URL.createObjectURL(blob);

    const link =
      document.createElement("a");

    link.href = url;
    link.download =
      "detection-history-export.csv";

    document.body.appendChild(link);

    link.click();

    link.remove();

    URL.revokeObjectURL(url);

    showToast(
      "success",
      "Export ready",
      "detection-history-export.csv downloaded."
    );
  }

  // ============================================================
  // LOAD LIVE DATA
  // ============================================================

  async function loadDetectionHistory() {
    try {
      const response =
        await fetch("/detection/history/data", {
          method: "GET",
          headers: {
            "Accept": "application/json",
          },
          credentials: "same-origin",
        });

      if (!response.ok) {
        throw new Error(
          `HTTP ${response.status}`
        );
      }

      const result =
        await response.json();

      if (!result.success) {
        throw new Error(
          result.message ||
          "Unable to load detection history."
        );
      }

      data = Array.isArray(result.data)
        ? result.data
        : [];

      updateSummary();

      populateSourceFilter();

      createTable();

      setupFilters();

    } catch (error) {
      console.error(
        "Detection history loading failed:",
        error
      );

      data = [];

      updateSummary();

      showToast(
        "danger",
        "Unable to load detection history",
        "The detection history API could not be reached."
      );
    }
  }

  // ============================================================
  // INIT
  // ============================================================

  document.addEventListener(
    "DOMContentLoaded",
    () => {

      const exportButton =
        document.getElementById("exportBtn");

      if (exportButton) {
        exportButton.addEventListener(
          "click",
          exportCSV
        );
      }

      loadDetectionHistory();
    }
  );

})();