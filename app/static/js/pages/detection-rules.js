/* ==========================================================================
   detection-rules.js — live Detection Rules page
   Backend:
     GET  /detection/rules/data
     POST /detection/rules/<id>/toggle
     POST /detection/rules/<id>/duplicate
     POST /detection/rules/<id>/delete

   Depends on:
     XDRTable
     modal-helpers.js
   ========================================================================== */

(function () {
  "use strict";

  let data = [];

  const STATUS_LABEL = {
    active: "Active",
    disabled: "Disabled",
    testing: "Testing",
  };

  const API_BASE = "/detection";

  // --------------------------------------------------------------------------
  // Helpers
  // --------------------------------------------------------------------------

  async function apiRequest(url, options = {}) {
    const response = await fetch(url, {
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        ...(options.headers || {}),
      },
      ...options,
    });

    let payload = null;

    try {
      payload = await response.json();
    } catch (_) {
      payload = null;
    }

    if (!response.ok) {
      throw new Error(
        payload?.message ||
        `Request failed with status ${response.status}`
      );
    }

    return payload;
  }

  function showToast(type, title, msg = "") {
    if (window.showToast) {
      window.showToast({
        type,
        title,
        msg,
      });
    }
  }

  function renderSummary() {
    const summary = document.getElementById("ruleCountSummary");

    if (!summary) {
      return;
    }

    summary.textContent =
      `${data.length} rules · ` +
      `${data.filter((r) => r.status === "active").length} active · ` +
      `${data.filter((r) => r.status === "disabled").length} disabled`;
  }

  function populateCategories() {
    const categorySel = document.getElementById("filterCategory");

    if (!categorySel) {
      return;
    }

    // Keep the default option.
    categorySel.innerHTML = `<option value="">All categories</option>`;

    const categories = [
      ...new Set(
        data
          .map((r) => r.category)
          .filter(Boolean)
      ),
    ].sort();

    categories.forEach((category) => {
      const option = document.createElement("option");
      option.value = category;
      option.textContent = category;
      categorySel.appendChild(option);
    });
  }

  // --------------------------------------------------------------------------
  // Table columns
  // --------------------------------------------------------------------------

  const columns = [
    {
      key: "name",
      label: "Rule",
      sortable: true,

      render: (r) => `
        <a
          href="rule-details.html?id=${encodeURIComponent(r.id)}"
          style="color:var(--text);font-weight:600;text-decoration:none;"
        >
          ${XDRUtils.escapeHtml(r.name || "Unnamed Rule")}
        </a>

        <div class="text-xs text-muted" style="margin-top:2px;">
          ${XDRUtils.escapeHtml(r.category || "Uncategorized")}
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
      key: "mitreId",
      label: "MITRE Technique",
      sortable: true,

      render: (r) => {
        if (!r.mitreId) {
          return `<span class="text-muted">—</span>`;
        }

        return `
          <span class="mitre-chip">
            ${XDRUtils.escapeHtml(r.mitreId)}
            ${
              r.mitreName
                ? `<span class="tname">${XDRUtils.escapeHtml(r.mitreName)}</span>`
                : ""
            }
          </span>
        `;
      },
    },

    {
      key: "status",
      label: "Status",
      sortable: true,

      render: (r) => `
        <span class="status-pill st-${XDRUtils.escapeHtml(r.status || "testing")}">
          <span class="dot"></span>
          ${STATUS_LABEL[r.status] || XDRUtils.escapeHtml(r.status || "Unknown")}
        </span>
      `,
    },

    {
      key: "triggers30d",
      label: "Triggers (30d)",
      sortable: true,

      render: (r) => `
        <span class="cell-mono">
          ${Number(r.triggers30d || 0)}
        </span>
      `,
    },

    {
      key: "createdAt",
      label: "Created",
      sortable: true,

      render: (r) =>
        r.createdAt
          ? XDRUtils.formatTime(r.createdAt)
          : "—",
    },

    {
      key: "modifiedAt",
      label: "Modified",
      sortable: true,

      render: (r) =>
        r.modifiedAt
          ? XDRUtils.formatTime(r.modifiedAt)
          : "—",
    },

    {
      key: "actions",
      label: "",
      sortable: false,

      render: (r) => `
        <div class="row-actions">

          <a
            href="rule-details.html?id=${encodeURIComponent(r.id)}"
            class="btn btn-icon btn-ghost btn-sm"
            title="View"
          >
            <i class="bi bi-eye"></i>
          </a>

          <a
            href="create-rule.html?id=${encodeURIComponent(r.id)}"
            class="btn btn-icon btn-ghost btn-sm"
            title="Edit"
          >
            <i class="bi bi-pencil"></i>
          </a>

          <button
            class="btn btn-icon btn-ghost btn-sm toggle-btn"
            data-id="${XDRUtils.escapeHtml(r.id)}"
            title="${r.status === "disabled" ? "Enable" : "Disable"}"
          >
            <i class="bi bi-power"></i>
          </button>

          <button
            class="btn btn-icon btn-ghost btn-sm dup-btn"
            data-id="${XDRUtils.escapeHtml(r.id)}"
            title="Duplicate"
          >
            <i class="bi bi-copy"></i>
          </button>

          <button
            class="btn btn-icon btn-ghost btn-sm delete-btn"
            data-id="${XDRUtils.escapeHtml(r.id)}"
            title="Delete"
          >
            <i class="bi bi-trash"></i>
          </button>

        </div>
      `,
    },
  ];

  // --------------------------------------------------------------------------
  // Table
  // --------------------------------------------------------------------------

  const table = new XDRTable({
    tableEl: document.getElementById("rulesTable"),
    searchInput: document.getElementById("ruleSearch"),
    paginationEl: document.getElementById("rulesPagination"),

    data: [],

    pageSize: 10,

    searchKeys: [
      "name",
      "category",
      "mitreId",
      "mitreName",
    ],

    columns,

    onRowsChange: wireRowActions,
  });

  // --------------------------------------------------------------------------
  // Load rules from Flask
  // --------------------------------------------------------------------------

  async function loadRules() {
    try {
      const result = await apiRequest(
        `${API_BASE}/rules/data`
      );

      if (!result.success) {
        throw new Error(
          result.message || "Unable to load detection rules."
        );
      }

      data = Array.isArray(result.data)
        ? result.data
        : [];

      table.data = data;

      populateCategories();
      renderSummary();
      table.render();

    } catch (error) {
      console.error(
        "Detection rules load error:",
        error
      );

      data = [];
      table.data = [];

      renderSummary();
      table.render();

      showToast(
        "danger",
        "Unable to load rules",
        error.message
      );
    }
  }

  // --------------------------------------------------------------------------
  // Row actions
  // --------------------------------------------------------------------------

  function wireRowActions() {

    // ------------------------------------------------------------------------
    // Toggle
    // ------------------------------------------------------------------------

    document
      .querySelectorAll(".toggle-btn")
      .forEach((btn) => {

        btn.addEventListener("click", async () => {

          const id = btn.dataset.id;

          const row = data.find(
            (r) => r.id === id
          );

          if (!row) {
            return;
          }

          btn.disabled = true;

          try {

            const result = await apiRequest(
              `${API_BASE}/rules/${encodeURIComponent(id)}/toggle`,
              {
                method: "POST",
              }
            );

            if (!result.success) {
              throw new Error(
                result.message ||
                "Unable to change rule status."
              );
            }

            const updated = result.data;

            const index = data.findIndex(
              (r) => r.id === id
            );

            if (index !== -1) {
              data[index] = updated;
            }

            table.data = data;

            renderSummary();
            table.render();

            showToast(
              updated.status === "active"
                ? "success"
                : "warning",

              updated.status === "active"
                ? "Rule enabled"
                : "Rule disabled",

              updated.name
            );

          } catch (error) {

            console.error(
              "Toggle rule error:",
              error
            );

            showToast(
              "danger",
              "Unable to change rule",
              error.message
            );

            btn.disabled = false;
          }
        });
      });

    // ------------------------------------------------------------------------
    // Duplicate
    // ------------------------------------------------------------------------

    document
      .querySelectorAll(".dup-btn")
      .forEach((btn) => {

        btn.addEventListener("click", async () => {

          const id = btn.dataset.id;

          const row = data.find(
            (r) => r.id === id
          );

          if (!row) {
            return;
          }

          btn.disabled = true;

          try {

            const result = await apiRequest(
              `${API_BASE}/rules/${encodeURIComponent(id)}/duplicate`,
              {
                method: "POST",
              }
            );

            if (!result.success) {
              throw new Error(
                result.message ||
                "Unable to duplicate rule."
              );
            }

            const clone = result.data;

            data.unshift(clone);

            table.data = data;

            populateCategories();
            renderSummary();
            table.render();

            showToast(
              "success",
              "Rule duplicated",
              `${clone.name} created in Testing status.`
            );

          } catch (error) {

            console.error(
              "Duplicate rule error:",
              error
            );

            showToast(
              "danger",
              "Unable to duplicate rule",
              error.message
            );

          } finally {
            btn.disabled = false;
          }
        });
      });

    // ------------------------------------------------------------------------
    // Delete
    // ------------------------------------------------------------------------

    document
      .querySelectorAll(".delete-btn")
      .forEach((btn) => {

        btn.addEventListener("click", () => {

          const id = btn.dataset.id;

          const row = data.find(
            (r) => r.id === id
          );

          if (!row) {
            return;
          }

          const nameEl =
            document.getElementById(
              "deleteRuleName"
            );

          const confirmBtn =
            document.getElementById(
              "confirmDeleteRuleBtn"
            );

          if (nameEl) {
            nameEl.textContent =
              row.name;
          }

          if (confirmBtn) {
            confirmBtn.dataset.id =
              row.id;
          }

          window.xdrOpenModal(
            "deleteRuleModal"
          );
        });
      });
  }

  // --------------------------------------------------------------------------
  // Confirm delete
  // --------------------------------------------------------------------------

  const confirmDeleteBtn =
    document.getElementById(
      "confirmDeleteRuleBtn"
    );

  if (confirmDeleteBtn) {

    confirmDeleteBtn.addEventListener(
      "click",
      async () => {

        const id =
          confirmDeleteBtn.dataset.id;

        if (!id) {
          return;
        }

        const row = data.find(
          (r) => r.id === id
        );

        confirmDeleteBtn.disabled = true;

        try {

          const result = await apiRequest(
            `${API_BASE}/rules/${encodeURIComponent(id)}/delete`,
            {
              method: "POST",
            }
          );

          if (!result.success) {
            throw new Error(
              result.message ||
              "Unable to delete rule."
            );
          }

          data = data.filter(
            (r) => r.id !== id
          );

          table.data = data;

          populateCategories();
          renderSummary();
          table.render();

          showToast(
            "danger",
            "Rule deleted",
            row ? row.name : ""
          );

        } catch (error) {

          console.error(
            "Delete rule error:",
            error
          );

          showToast(
            "danger",
            "Unable to delete rule",
            error.message
          );

        } finally {
          confirmDeleteBtn.disabled = false;
        }
      }
    );
  }

  // --------------------------------------------------------------------------
  // Filters
  // --------------------------------------------------------------------------

  function applyFilters() {

    const sev =
      document.getElementById(
        "filterSev"
      ).value;

    const status =
      document.getElementById(
        "filterStatus"
      ).value;

    const category =
      document.getElementById(
        "filterCategory"
      ).value;

    table.setFilter((row) =>
      (!sev || row.severity === sev) &&
      (!status || row.status === status) &&
      (!category || row.category === category)
    );
  }

  [
    "filterSev",
    "filterStatus",
    "filterCategory",
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

  // --------------------------------------------------------------------------
  // Clear filters
  // --------------------------------------------------------------------------

  const clearFilters =
    document.getElementById(
      "clearFilters"
    );

  if (clearFilters) {

    clearFilters.addEventListener(
      "click",
      () => {

        const search =
          document.getElementById(
            "ruleSearch"
          );

        if (search) {
          search.value = "";
        }

        [
          "filterSev",
          "filterStatus",
          "filterCategory",
        ].forEach((id) => {

          const element =
            document.getElementById(id);

          if (element) {
            element.value = "";
          }
        });

        table.state.query = "";

        table.setFilter(null);

        table.render();
      }
    );
  }

  // --------------------------------------------------------------------------
  // Initial load
  // --------------------------------------------------------------------------

  loadRules();

})();