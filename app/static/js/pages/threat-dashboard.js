/*
 * CyberDefense XDR
 * Threat Intelligence Dashboard
 *
 * Backend-connected dashboard.
 * Data source:
 *   /threat-intelligence/dashboard/data
 *   /threat-intelligence/iocs
 *   /threat-intelligence/campaigns
 *   /threat-intelligence/feeds
 *   /threat-intelligence/actors
 */

(function () {
  "use strict";

  const API_BASE = "/threat-intelligence";

  function escapeHtml(value) {
    if (window.XDRUtils && typeof XDRUtils.escapeHtml === "function") {
      return XDRUtils.escapeHtml(String(value ?? ""));
    }

    const div = document.createElement("div");
    div.textContent = String(value ?? "");
    return div.innerHTML;
  }

  function formatTime(value) {
    if (window.XDRUtils && typeof XDRUtils.formatTime === "function") {
      return XDRUtils.formatTime(value);
    }

    if (!value) return "—";

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
      return String(value);
    }

    return date.toLocaleString();
  }

  function severityBadge(level) {
    if (window.XDRUtils && typeof XDRUtils.severityBadge === "function") {
      return XDRUtils.severityBadge(level);
    }

    const safeLevel = escapeHtml(level || "unknown");

    return `<span class="badge badge-${safeLevel}">
      ${safeLevel}
    </span>`;
  }

  async function fetchJson(url) {
    const response = await fetch(url, {
      method: "GET",
      headers: {
        Accept: "application/json",
      },
      credentials: "same-origin",
    });

    if (!response.ok) {
      throw new Error(
        `Request failed: ${response.status} ${response.statusText}`
      );
    }

    const payload = await response.json();

    if (!payload.success) {
      throw new Error(payload.error || "API request failed");
    }

    return payload.data;
  }

  async function loadDashboard() {
    const [
      dashboard,
      iocResponse,
      campaignResponse,
      feedResponse,
      actorResponse,
    ] = await Promise.all([
      fetchJson(`${API_BASE}/dashboard/data`),
      fetchJson(`${API_BASE}/iocs?per_page=100`),
      fetchJson(`${API_BASE}/campaigns?per_page=100`),
      fetchJson(`${API_BASE}/feeds?per_page=100`),
      fetchJson(`${API_BASE}/actors?per_page=100`),
    ]);

    const iocs = iocResponse.items || [];
    const campaigns = campaignResponse.items || [];
    const feeds = feedResponse.items || [];
    const actors = actorResponse.items || [];

    renderKpis(
      dashboard,
      iocs,
      campaigns,
      feeds,
      actors
    );

    renderIocTrend(iocs);
    renderIocTypeDistribution(iocs);
    renderLatestIocs(iocs);
    renderTopActors(actors);
    renderActiveCampaigns(campaigns);

    updateSummary(iocs, campaigns, feeds);
  }

  // -------------------------------------------------------------------------
  // KPI cards
  // -------------------------------------------------------------------------

  function renderKpis(
    dashboard,
    iocs,
    campaigns,
    feeds,
    actors
  ) {
    const stats = dashboard || {};
    const iocStats = stats.iocs || {};
    const campaignStats = stats.campaigns || {};
    const feedStats = stats.feeds || {};
    const actorStats = stats.actors || {};

    const activeIocs =
      Number(iocStats.active ?? iocs.filter(
        (ioc) => ioc.status === "active"
      ).length);

    const criticalIocs =
      Number(iocStats.critical ?? iocs.filter(
        (ioc) => ioc.threatLevel === "critical"
      ).length);

    const activeCampaigns =
      Number(campaignStats.active ?? campaigns.filter(
        (campaign) => campaign.status === "active"
      ).length);

    const activeFeeds =
      Number(feedStats.active ?? feeds.filter(
        (feed) => feed.status === "active"
      ).length);

    const actorCount =
      Number(actorStats.total ?? actors.length);

    const today = new Date();
    const todayString = today.toISOString().slice(0, 10);

    const addedToday = iocs.filter((ioc) => {
      const firstSeen = ioc.firstSeen || ioc.first_seen;

      return firstSeen &&
        String(firstSeen).startsWith(todayString);
    }).length;

    const kpis = [
      {
        label: "Active IOCs",
        value: activeIocs,
        accent: "accent-primary",
        icon: "bi-radar",
        sub: `${iocStats.total ?? iocs.length} total tracked`,
      },
      {
        label: "Critical IOCs",
        value: criticalIocs,
        accent: "accent-danger",
        icon: "bi-exclamation-octagon",
        sub: "highest threat level",
      },
      {
        label: "Active Campaigns",
        value: activeCampaigns,
        accent: "accent-warning",
        icon: "bi-flag",
        sub: `${campaignStats.total ?? campaigns.length} tracked total`,
      },
      {
        label: "Threat Actors Tracked",
        value: actorCount,
        accent: "accent-info",
        icon: "bi-person-badge",
        sub: "attributed groups",
      },
      {
        label: "Feed Sources",
        value: activeFeeds,
        accent: "accent-success",
        icon: "bi-broadcast",
        sub: `${feedStats.total ?? feeds.length} configured`,
      },
      {
        label: "IOCs Added Today",
        value: addedToday,
        accent: "accent-primary",
        icon: "bi-plus-circle",
        sub: "based on first-seen date",
      },
    ];

    const element = document.getElementById("kpiRow");

    if (!element) return;

    element.innerHTML = kpis.map((kpi) => `
      <div class="col-lg-2 col-md-4 col-6">
        <div class="card stat-card ${kpi.accent} h-100">
          <div class="eyebrow">
            <i class="bi ${kpi.icon}"></i>
            ${escapeHtml(kpi.label)}
          </div>

          <div class="stat-value">${kpi.value}</div>

          <span class="stat-delta text-muted">
            ${escapeHtml(kpi.sub)}
          </span>
        </div>
      </div>
    `).join("");
  }

  // -------------------------------------------------------------------------
  // IOC trend
  // -------------------------------------------------------------------------

  function renderIocTrend(iocs) {
    const canvas = document.getElementById("iocTrendChart");

    if (!canvas || typeof Chart === "undefined") return;

    const now = new Date();

    const days = [];

    for (let i = 13; i >= 0; i -= 1) {
      const date = new Date(now);

      date.setHours(0, 0, 0, 0);
      date.setDate(date.getDate() - i);

      days.push(date.toISOString().slice(0, 10));
    }

    const counts = days.map((day) => {
      return iocs.filter((ioc) => {
        const firstSeen = ioc.firstSeen || ioc.first_seen;

        return firstSeen &&
          String(firstSeen).startsWith(day);
      }).length;
    });

    const ctx = canvas.getContext("2d");

    const palette =
      window.XDR_PALETTE?.activity || [];

    const primary =
      palette[1] || palette[0] || "#4f46e5";

    let background = undefined;

    if (
      typeof window.xdrGradient === "function" &&
      window.XDR_PALETTE?.activity
    ) {
      background = window.xdrGradient(
        ctx,
        primary
      );
    }

    new Chart(ctx, {
      type: "line",

      data: {
        labels: days.map((day) => day.slice(5)),

        datasets: [
          {
            label: "New IOCs",
            data: counts,
            borderColor: primary,
            backgroundColor: background,
            fill: true,
            tension: 0.35,
            pointRadius: 0,
            borderWidth: 2,
          },
        ],
      },

      options: window.XDR_CHART_DEFAULTS || {
        responsive: true,
        maintainAspectRatio: false,
      },
    });
  }

  // -------------------------------------------------------------------------
  // IOC type distribution
  // -------------------------------------------------------------------------

  function renderIocTypeDistribution(iocs) {
    const canvas = document.getElementById("iocTypeChart");

    if (!canvas || typeof Chart === "undefined") return;

    const types = [
      "ip",
      "domain",
      "hash",
      "url",
    ];

    const typeCounts = types.map((type) => {
      return iocs.filter(
        (ioc) => ioc.type === type
      ).length;
    });

    const activity =
      window.XDR_PALETTE?.activity || [];

    new Chart(canvas, {
      type: "doughnut",

      data: {
        labels: types.map(
          (type) => type.toUpperCase()
        ),

        datasets: [
          {
            data: typeCounts,

            backgroundColor: [
              activity[0] || undefined,
              activity[1] || undefined,
              activity[2] || undefined,
              activity[3] || undefined,
            ],

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

  // -------------------------------------------------------------------------
  // Latest indicators
  // -------------------------------------------------------------------------

  function renderLatestIocs(iocs) {
    const element =
      document.getElementById("latestIocsBody");

    if (!element) return;

    const latest = iocs
      .slice()
      .sort((a, b) => {
        return new Date(
          b.lastSeen || b.last_seen || 0
        ) - new Date(
          a.lastSeen || a.last_seen || 0
        );
      })
      .slice(0, 8);

    if (!latest.length) {
      element.innerHTML = `
        <tr>
          <td colspan="4" class="text-muted text-center">
            No indicators available
          </td>
        </tr>
      `;

      return;
    }

    element.innerHTML = latest.map((ioc) => {
      const id = ioc.id;
      const value = escapeHtml(ioc.value);
      const type = escapeHtml(ioc.type);
      const threatLevel = ioc.threatLevel || "unknown";
      const lastSeen =
        ioc.lastSeen || ioc.last_seen;

      return `
        <tr>
          <td>
            <a
              href="${API_BASE}/ioc-details?id=${encodeURIComponent(id)}"
              class="ioc-value"
              style="text-decoration:none;"
            >
              ${value}
            </a>
          </td>

          <td>
            <span class="ioc-type-chip">
              ${type}
            </span>
          </td>

          <td>
            ${severityBadge(threatLevel)}
          </td>

          <td class="text-sm text-muted">
            ${escapeHtml(formatTime(lastSeen))}
          </td>
        </tr>
      `;
    }).join("");
  }

  // -------------------------------------------------------------------------
  // Most active actors
  // -------------------------------------------------------------------------

  function renderTopActors(actors) {
    const element =
      document.getElementById("topActorsList");

    if (!element) return;

    const topActors = actors
      .slice()
      .sort(
        (a, b) =>
          Number(b.campaignCount || 0) -
          Number(a.campaignCount || 0)
      )
      .slice(0, 5);

    if (!topActors.length) {
      element.innerHTML = `
        <div class="text-muted">
          No threat actors available
        </div>
      `;

      return;
    }

    element.innerHTML = topActors.map((actor) => {
      const name = escapeHtml(actor.name || "Unknown");
      const initials = escapeHtml(
        (actor.name || "NA")
          .slice(0, 2)
          .toUpperCase()
      );

      return `
        <div class="mini-status-row">
          <span class="d-flex align-items-center gap-2">
            <span
              class="actor-avatar"
              style="width:28px;height:28px;font-size:12px;"
            >
              ${initials}
            </span>

            <span style="font-weight:600;">
              ${name}
            </span>
          </span>

          <span class="badge badge-neutral">
            ${Number(actor.campaignCount || 0)}
            campaigns
          </span>
        </div>
      `;
    }).join("");
  }

  // -------------------------------------------------------------------------
  // Active campaigns
  // -------------------------------------------------------------------------

  function renderActiveCampaigns(campaigns) {
    const element =
      document.getElementById("activeCampaignsGrid");

    if (!element) return;

    const activeCampaigns = campaigns
      .filter(
        (campaign) => campaign.status === "active"
      )
      .slice(0, 4);

    if (!activeCampaigns.length) {
      element.innerHTML = `
        <div class="col-12">
          <div class="text-muted">
            No active campaigns available
          </div>
        </div>
      `;

      return;
    }

    element.innerHTML = activeCampaigns.map(
      (campaign) => `
        <div class="col-lg-3 col-md-6">
          <div class="campaign-card">
            <div>
              <span
                class="campaign-status-dot ${escapeHtml(
                  campaign.status
                )}"
              ></span>

              <strong>
                ${escapeHtml(campaign.name)}
              </strong>
            </div>

            <p class="text-muted text-sm mb-0">
              Attributed to
              ${escapeHtml(
                campaign.actorName || "Unknown"
              )}
            </p>

            <span class="text-xs text-muted">
              ${Number(campaign.iocCount || 0)}
              IOCs linked
            </span>
          </div>
        </div>
      `
    ).join("");
  }

  // -------------------------------------------------------------------------
  // Page summary
  // -------------------------------------------------------------------------

  function updateSummary(
    iocs,
    campaigns,
    feeds
  ) {
    const summary =
      document.querySelector(
        ".section-title-row p"
      );

    if (!summary) return;

    const activeCampaigns =
      campaigns.filter(
        (campaign) =>
          campaign.status === "active"
      ).length;

    const activeFeeds =
      feeds.filter(
        (feed) => feed.status === "active"
      ).length;

    summary.textContent =
      `${iocs.length} tracked indicators · ` +
      `${activeCampaigns} active campaigns · ` +
      `${activeFeeds} feed sources`;
  }

  // -------------------------------------------------------------------------
  // Loading / error handling
  // -------------------------------------------------------------------------

  function showError(error) {
    console.error(
      "Threat Intelligence dashboard error:",
      error
    );

    const kpiRow =
      document.getElementById("kpiRow");

    if (kpiRow) {
      kpiRow.innerHTML = `
        <div class="col-12">
          <div class="alert alert-danger">
            Unable to load Threat Intelligence data.
            Please check the backend/API.
          </div>
        </div>
      `;
    }
  }

  document.addEventListener(
    "DOMContentLoaded",
    () => {
      loadDashboard().catch(showError);
    }
  );
})();