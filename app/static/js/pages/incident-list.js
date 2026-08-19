/* ==========================================================================
   incident-list.js
   Live Incident List
   Uses:
     - /incidents/data
     - XDRTable
     - XDRUtils
   ========================================================================== */

(function () {
  "use strict";

  let data = [];

  const STATUS_LABEL = {
    new: "New",
    investigating: "Investigating",
    contained: "Contained",
    resolved: "Resolved",
    closed: "Closed",
  };

  const STATUS_BADGE = {
    new: "badge-info",
    investigating: "badge-warning",
    contained: "badge-warning",
    resolved: "badge-success",
    closed: "badge-neutral",
  };

  /* ============================================================
     HELPERS
     ============================================================ */

  function escape(value) {
    return XDRUtils.escapeHtml(
      value === null || value === undefined ? "" : String(value)
    );
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

  function updateSummary() {
    const summary = document.getElementById("incidentCountSummary");

    if (!summary) return;

    const total = data.length;

    const active = data.filter(
      (i) =>
        i.status === "new" ||
        i.status === "investigating" ||
        i.status === "contained"
    ).length;

    const resolved = data.filter(
      (i) => i.status === "resolved" || i.status === "closed"
    ).length;

    summary.textContent =
      `${total} incidents · ${active} active · ${resolved} resolved`;
  }

  /* ============================================================
     TABLE COLUMNS
     ============================================================ */

  const columns = [
    {
      key: "title",
      label: "Incident",
      sortable: true,

      render: (r) => `
        <a
          href="/incidents/${encodeURIComponent(r.id)}"
          style="color:var(--text);font-weight:600;text-decoration:none;"
        >
          ${escape(r.title)}
        </a>

        <div
          class="text-xs text-muted"
          style="margin-top:2px;"
        >
          ${escape(r.id)}
        </div>
      `,
    },

    {
      key: "severity",
      label: "Severity",
      sortable: true,

      render: (r) =>
        XDRUtils.severityBadge(
          r.severity || "medium"
        ),
    },

    {
      key: "priority",
      label: "Priority",
      sortable: true,

      render: (r) => `
        <span class="cell-mono">
          ${escape(r.priority || "medium")}
        </span>
      `,
    },

    {
      key: "category",
      label: "Category",
      sortable: true,

      render: (r) => `
        <span>
          ${escape(r.category || "Security")}
        </span>
      `,
    },

    {
      key: "status",
      label: "Status",
      sortable: true,

      render: (r) => `
        <span class="badge ${STATUS_BADGE[r.status] || "badge-neutral"}">
          ${escape(
            STATUS_LABEL[r.status] ||
            r.status ||
            "Unknown"
          )}
        </span>
      `,
    },

    {
      key: "affectedHost",
      label: "Host",
      sortable: true,

      render: (r) => `
        <span style="font-weight:600;">
          ${escape(r.affectedHost || "—")}
        </span>
      `,
    },

    {
      key: "source",
      label: "Source",
      sortable: true,

      render: (r) => `
        <span>
          ${escape(r.source || "—")}
        </span>
      `,
    },

    {
      key: "detectedAt",
      label: "Detected",
      sortable: true,

      render: (r) =>
        r.detectedAt
          ? XDRUtils.formatTime(r.detectedAt)
          : "—",
    },

    {
      key: "actions",
      label: "",
      sortable: false,

      render: (r) => `
        <div class="row-actions">

          <a
            href="/incidents/${encodeURIComponent(r.id)}"
            class="btn btn-icon btn-ghost btn-sm"
            title="View"
          >
            <i class="bi bi-eye"></i>
          </a>

        </div>
      `,
    },
  ];

  /* ============================================================
     TABLE
     ============================================================ */

  const table = new XDRTable({
    tableEl: document.getElementById("incidentTable"),

    searchInput:
      document.getElementById("incidentSearch"),

    paginationEl:
      document.getElementById("incidentPagination"),

    data,

    pageSize: 10,

    searchKeys: [
      "id",
      "title",
      "category",
      "severity",
      "priority",
      "status",
      "source",
      "affectedHost",
      "affectedAsset",
      "mitreId",
    ],

    columns,
  });

  /* ============================================================
     LOAD LIVE DATA
     ============================================================ */

  async function loadIncidents() {
    try {
      const response = await fetch(
        "/incidents/data",
        {
          method: "GET",
          headers: {
            "Accept": "application/json",
          },
          credentials: "same-origin",
        }
      );

      if (!response.ok) {
        throw new Error(
          `HTTP ${response.status}`
        );
      }

      const result = await response.json();

      if (!result.success) {
        throw new Error(
          result.message ||
          "Unable to load incidents."
        );
      }

      data = Array.isArray(result.data)
        ? result.data
        : [];

      table.data = data;

      updateSummary();

      table.render();

    } catch (error) {
      console.error(
        "Incident loading error:",
        error
      );

      data = [];

      table.data = data;

      updateSummary();

      table.render();

      showToast(
        "danger",
        "Unable to load incidents",
        "The incident data could not be loaded from the server."
      );
    }
  }

  /* ============================================================
     FILTERS
     ============================================================ */

  function applyFilters() {
    const severity =
      document.getElementById(
        "filterSev"
      )?.value || "";

    const status =
      document.getElementById(
        "filterStatus"
      )?.value || "";

    const category =
      document.getElementById(
        "filterCategory"
      )?.value || "";

    const priority =
      document.getElementById(
        "filterPriority"
      )?.value || "";

    table.setFilter((row) => {
      return (
        (!severity ||
          row.severity === severity) &&

        (!status ||
          row.status === status) &&

        (!category ||
          row.category === category) &&

        (!priority ||
          row.priority === priority)
      );
    });
  }

  [
    "filterSev",
    "filterStatus",
    "filterCategory",
    "filterPriority",
  ].forEach((id) => {
    const element =
      document.getElementById(id);

    if (element) {
      element.addEventListener(
        "change",
        applyFilters
      );
    }
  });

  /* ============================================================
     CLEAR FILTERS
     ============================================================ */

  const clearButton =
    document.getElementById(
      "clearFilters"
    );

  if (clearButton) {
    clearButton.addEventListener(
      "click",
      () => {
        const search =
          document.getElementById(
            "incidentSearch"
          );

        if (search) {
          search.value = "";
        }

        [
          "filterSev",
          "filterStatus",
          "filterCategory",
          "filterPriority",
        ].forEach((id) => {
          const element =
            document.getElementById(id);

          if (element) {
            element.value = "";
          }
        });

        if (table.state) {
          table.state.query = "";
        }

        table.setFilter(null);

        table.render();
      }
    );
  }

  /* ============================================================
     INITIALIZE
     ============================================================ */

  updateSummary();

  loadIncidents();

})();