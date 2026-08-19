/* ==========================================================================
   detection-dashboard.js — Detection Dashboard
   Uses live backend data.

   Backend endpoints:
   GET /detection/rules/data
   GET /detection/history/data

   Depends on:
   - Chart.js
   - core/charts.js
   - XDRUtils
   ========================================================================== */

(function () {
  "use strict";

  let rules = [];
  let history = [];

  // ============================================================
  // HELPERS
  // ============================================================

  function escape(value) {
    if (
      window.XDRUtils &&
      typeof XDRUtils.escapeHtml === "function"
    ) {
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

  function getChartPalette() {
    return window.XDR_PALETTE || {
      severity: {
        critical: "#ef4444",
        high: "#f97316",
        medium: "#eab308",
        low: "#22c55e",
      },
      activity: [
        "#6366f1",
        "#8b5cf6",
        "#06b6d4",
        "#14b8a6",
      ],
    };
  }

  // ============================================================
  // KPI CARDS
  // ============================================================

  function renderKPIs() {
    const container =
      document.getElementById("kpiRow");

    if (!container) return;

    const activeRules =
      rules.filter(
        (r) => r.status === "active"
      );

    const disabledRules =
      rules.filter(
        (r) => r.status === "disabled"
      );

    const testingRules =
      rules.filter(
        (r) => r.status === "testing"
      );

    const criticalRules =
      rules.filter(
        (r) =>
          r.severity === "critical" &&
          r.status !== "disabled"
      );

    const now = Date.now();

    const recentDetections =
      history.filter((event) => {
        if (!event.ts) return false;

        const timestamp =
          new Date(event.ts).getTime();

        return (
          !Number.isNaN(timestamp) &&
          now - timestamp < 24 * 60 * 60 * 1000
        );
      });

    const falsePositives =
      history.filter(
        (event) =>
          event.status === "false_positive"
      );

    const topRule =
      rules
        .slice()
        .sort(
          (a, b) =>
            (b.triggers30d || 0) -
            (a.triggers30d || 0)
        )[0];

    const kpis = [
      {
        label: "Active Rules",
        value: activeRules.length,
        accent: "accent-success",
        icon: "bi-check-circle",
        sub: `of ${rules.length} total`,
      },

      {
        label: "Disabled Rules",
        value: disabledRules.length,
        accent: "",
        icon: "bi-slash-circle",
        sub: `${testingRules.length} in testing`,
      },

      {
        label: "Recent Detections",
        value: recentDetections.length,
        accent: "accent-primary",
        icon: "bi-radar",
        sub: "last 24 hours",
      },

      {
        label: "False Positives",
        value: falsePositives.length,
        accent: "accent-warning",
        icon: "bi-flag",
        sub: `${
          history.length
            ? Math.round(
                falsePositives.length /
                  history.length *
                  100
              )
            : 0
        }% of all events`,
      },

      {
        label: "Critical Rules",
        value: criticalRules.length,
        accent: "accent-danger",
        icon: "bi-skull",
        sub: "active or testing",
      },

      {
        label: "Top Triggered Rule",
        value: topRule
          ? topRule.triggers30d || 0
          : 0,
        accent: "accent-info",
        icon: "bi-graph-up-arrow",
        sub: topRule
          ? topRule.name
          : "—",
      },
    ];

    container.innerHTML = kpis
      .map(
        (kpi) => `
        <div class="col-lg-2 col-md-4 col-6">
          <div class="card stat-card ${kpi.accent} h-100">

            <div class="eyebrow">
              <i class="bi ${kpi.icon}"></i>
              ${escape(kpi.label)}
            </div>

            <div class="stat-value">
              ${escape(kpi.value)}
            </div>

            <span
              class="stat-delta text-muted text-truncate d-block"
              title="${escape(kpi.sub)}"
            >
              ${escape(kpi.sub)}
            </span>

          </div>
        </div>
        `
      )
      .join("");
  }

  // ============================================================
  // DETECTION TREND
  // ============================================================

  function renderDetectionTrend() {
    const canvas =
      document.getElementById(
        "detectionTrendChart"
      );

    if (!canvas || typeof Chart === "undefined") {
      return;
    }

    const now = new Date();

    const days = [];

    for (let i = 13; i >= 0; i--) {
      const date = new Date(now);

      date.setDate(
        date.getDate() - i
      );

      days.push(
        date.toISOString().slice(0, 10)
      );
    }

    const criticalByDay =
      days.map((day) =>
        history.filter(
          (event) =>
            event.ts &&
            event.ts.startsWith(day) &&
            event.severity === "critical"
        ).length
      );

    const highByDay =
      days.map((day) =>
        history.filter(
          (event) =>
            event.ts &&
            event.ts.startsWith(day) &&
            event.severity === "high"
        ).length
      );

    const palette =
      getChartPalette();

    const context =
      canvas.getContext("2d");

    let criticalBackground =
      palette.severity.critical;

    let highBackground =
      palette.severity.high;

    if (
      typeof window.xdrGradient ===
      "function"
    ) {
      criticalBackground =
        xdrGradient(
          context,
          palette.severity.critical
        );

      highBackground =
        xdrGradient(
          context,
          palette.severity.high
        );
    }

    new Chart(context, {
      type: "line",

      data: {
        labels: days.map(
          (day) => day.slice(5)
        ),

        datasets: [
          {
            label: "Critical",
            data: criticalByDay,
            borderColor:
              palette.severity.critical,
            backgroundColor:
              criticalBackground,
            fill: true,
            tension: 0.35,
            pointRadius: 0,
            borderWidth: 2,
          },

          {
            label: "High",
            data: highByDay,
            borderColor:
              palette.severity.high,
            backgroundColor:
              highBackground,
            fill: true,
            tension: 0.35,
            pointRadius: 0,
            borderWidth: 2,
          },
        ],
      },

      options:
        window.XDR_CHART_DEFAULTS || {},
    });
  }

  // ============================================================
  // RULE SEVERITY DISTRIBUTION
  // ============================================================

  function renderRuleSeverity() {
    const canvas =
      document.getElementById(
        "ruleSeverityChart"
      );

    if (
      !canvas ||
      typeof Chart === "undefined"
    ) {
      return;
    }

    const severityOrder = [
      "critical",
      "high",
      "medium",
      "low",
    ];

    const counts =
      severityOrder.map(
        (severity) =>
          rules.filter(
            (rule) =>
              rule.severity === severity
          ).length
      );

    const palette =
      getChartPalette();

    new Chart(canvas, {
      type: "doughnut",

      data: {
        labels: severityOrder.map(
          (severity) =>
            severity.charAt(0).toUpperCase() +
            severity.slice(1)
        ),

        datasets: [
          {
            data: counts,

            backgroundColor:
              severityOrder.map(
                (severity) =>
                  palette.severity[severity]
              ),

            borderWidth: 0,
          },
        ],
      },

      options: {
        responsive: true,
        maintainAspectRatio: false,

        cutout: "68%",

        plugins: {
          legend: {
            display: true,
            position: "bottom",

            labels: {
              usePointStyle: true,
              boxWidth: 8,
              boxHeight: 8,
            },
          },
        },
      },
    });
  }

  // ============================================================
  // MITRE / CATEGORY COVERAGE
  // ============================================================

  function renderCategoryCoverage() {
    const canvas =
      document.getElementById(
        "mitreCoverageChart"
      );

    if (
      !canvas ||
      typeof Chart === "undefined"
    ) {
      return;
    }

    const categories = [
      ...new Set(
        rules
          .map((rule) => rule.category)
          .filter(Boolean)
      ),
    ];

    const coverage =
      categories.map(
        (category) =>
          rules.filter(
            (rule) =>
              rule.category === category &&
              rule.status !== "disabled"
          ).length
      );

    const palette =
      getChartPalette();

    new Chart(canvas, {
      type: "radar",

      data: {
        labels: categories,

        datasets: [
          {
            label:
              "Active rule coverage",

            data: coverage,

            backgroundColor:
              "rgba(139,92,246,.18)",

            borderColor:
              palette.activity[2],

            pointBackgroundColor:
              palette.activity[2],

            borderWidth: 2,
          },
        ],
      },

      options: {
        responsive: true,
        maintainAspectRatio: false,

        plugins: {
          legend: {
            display: false,
          },
        },

        scales: {
          r: {
            angleLines: {
              color:
                "var(--border-subtle)",
            },

            grid: {
              color:
                "rgba(148,163,184,.12)",
            },

            pointLabels: {
              color:
                "var(--text-muted)",

              font: {
                size: 10,
              },
            },

            ticks: {
              display: false,
              beginAtZero: true,
            },
          },
        },
      },
    });
  }

  // ============================================================
  // TOP TRIGGERED RULES
  // ============================================================

  function renderTopRules() {
    const container =
      document.getElementById(
        "topRulesList"
      );

    if (!container) return;

    const topRules =
      rules
        .slice()
        .sort(
          (a, b) =>
            (b.triggers30d || 0) -
            (a.triggers30d || 0)
        )
        .slice(0, 6);

    if (!topRules.length) {
      container.innerHTML = `
        <div class="text-muted text-center py-4">
          No detection rules available.
        </div>
      `;

      return;
    }

    container.innerHTML =
      topRules
        .map(
          (rule, index) => `
          <div class="rule-rank-row">

            <span class="rule-rank-badge">
              ${index + 1}
            </span>

            <a
              href="rule-details.html?id=${encodeURIComponent(
                rule.id || ""
              )}"
              class="rr-name"
            >
              ${escape(rule.name)}
            </a>

            ${
              window.XDRUtils &&
              typeof XDRUtils.severityBadge ===
                "function"
                ? XDRUtils.severityBadge(
                    rule.severity
                  )
                : ""
            }

            <span class="rr-count">
              ${rule.triggers30d || 0}
            </span>

          </div>
          `
        )
        .join("");
  }

  // ============================================================
  // CATEGORY GRID
  // ============================================================

  function renderCategories() {
    const container =
      document.getElementById(
        "categoryGrid"
      );

    if (!container) return;

    const categories = [
      ...new Set(
        rules
          .map((rule) => rule.category)
          .filter(Boolean)
      ),
    ];

    if (!categories.length) {
      container.innerHTML = `
        <div class="col-12">
          <div class="text-muted text-center py-4">
            No rule categories available.
          </div>
        </div>
      `;

      return;
    }

    container.innerHTML =
      categories
        .map((category) => {
          const categoryRules =
            rules.filter(
              (rule) =>
                rule.category === category
            );

          const activeCount =
            categoryRules.filter(
              (rule) =>
                rule.status === "active"
            ).length;

          return `
            <div class="col-lg-3 col-md-4 col-6">

              <a
                href="detection-rules.html"
                class="card stat-card d-block h-100"
                style="text-decoration:none;"
              >

                <div class="eyebrow">
                  ${escape(category)}
                </div>

                <div class="stat-value fs-inherit-lg">
                  ${categoryRules.length}

                  <span class="text-muted text-sm">
                    rules
                  </span>
                </div>

                <span class="stat-delta text-success">
                  ${activeCount} active
                </span>

              </a>

            </div>
          `;
        })
        .join("");
  }

  // ============================================================
  // LOAD RULES
  // ============================================================

  async function loadRules() {
    const response =
      await fetch(
        "/detection/rules/data",
        {
          method: "GET",
          headers: {
            Accept:
              "application/json",
          },
          credentials:
            "same-origin",
        }
      );

    if (!response.ok) {
      throw new Error(
        `Rules API returned HTTP ${response.status}`
      );
    }

    const result =
      await response.json();

    if (!result.success) {
      throw new Error(
        result.message ||
        "Unable to load detection rules."
      );
    }

    rules =
      Array.isArray(result.data)
        ? result.data
        : [];
  }

  // ============================================================
  // LOAD HISTORY
  // ============================================================

  async function loadHistory() {
    const response =
      await fetch(
        "/detection/history/data",
        {
          method: "GET",
          headers: {
            Accept:
              "application/json",
          },
          credentials:
            "same-origin",
        }
      );

    if (!response.ok) {
      throw new Error(
        `History API returned HTTP ${response.status}`
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

    history =
      Array.isArray(result.data)
        ? result.data
        : [];
  }

  // ============================================================
  // INITIALIZE DASHBOARD
  // ============================================================

  async function initialize() {
    try {
      await Promise.all([
        loadRules(),
        loadHistory(),
      ]);

      renderKPIs();

      renderDetectionTrend();

      renderRuleSeverity();

      renderCategoryCoverage();

      renderTopRules();

      renderCategories();

    } catch (error) {
      console.error(
        "Detection dashboard loading failed:",
        error
      );

      showToast(
        "danger",
        "Dashboard loading failed",
        "Unable to load live detection data."
      );
    }
  }

  // ============================================================
  // START
  // ============================================================

  document.addEventListener(
    "DOMContentLoaded",
    initialize
  );

})();