/* ==========================================================================
   CyberDefense XDR
   Incident Dashboard
   Uses live Flask incident data
   ========================================================================== */

(function () {
    "use strict";

    document.addEventListener("DOMContentLoaded", async function () {

        try {
            const response = await fetch("/incidents/data", {
                headers: {
                    "Accept": "application/json"
                }
            });

            if (!response.ok) {
                throw new Error(
                    `Incident API returned HTTP ${response.status}`
                );
            }

            const payload = await response.json();

            /*
             * Support common API response formats:
             *
             * 1. [...]
             * 2. { incidents: [...] }
             * 3. { data: [...] }
             */
            let incidents = [];

            if (Array.isArray(payload)) {
                incidents = payload;
            } else if (Array.isArray(payload.incidents)) {
                incidents = payload.incidents;
            } else if (Array.isArray(payload.data)) {
                incidents = payload.data;
            }

            console.log("CyberDefense XDR incidents:", incidents);

            if (!incidents.length) {
                console.warn("No incidents returned from /incidents/data");
            }

            initializeDashboard(incidents);

        } catch (error) {

            console.error(
                "Failed to load Incident Dashboard:",
                error
            );

            showDashboardError(error.message);
        }
    });


    /* ============================================================
       Dashboard
    ============================================================ */

    function initializeDashboard(incidents) {

        const STATUS_LABEL = {
            open: "Open",
            in_progress: "In Progress",
            resolved: "Resolved",
            closed: "Closed"
        };


        /* ========================================================
           KPI calculations
        ======================================================== */

        const openIncidents = incidents.filter(
            i => i.status === "open" || i.status === "in_progress"
        );

        const resolvedIncidents = incidents.filter(
            i => i.status === "resolved" || i.status === "closed"
        );

        const criticalIncidents = incidents.filter(
            i => i.severity === "critical" && i.status !== "closed"
        );


        const avgResponseHrs = resolvedIncidents.length
            ? Math.round(
                resolvedIncidents.reduce(
                    (sum, incident) => {

                        return sum +
                            hoursBetween(
                                incident.createdAt,
                                incident.updatedAt
                            );

                    },
                    0
                ) / resolvedIncidents.length * 10
            ) / 10
            : 0;


        const kpis = [
            {
                label: "Open Incidents",
                value: openIncidents.length,
                accent: "accent-primary",
                icon: "bi-folder2-open",
                sub: `${incidents.length} total tracked`
            },
            {
                label: "Resolved",
                value: resolvedIncidents.length,
                accent: "accent-success",
                icon: "bi-check-circle",
                sub: "resolved or closed"
            },
            {
                label: "Critical",
                value: criticalIncidents.length,
                accent: "accent-danger",
                icon: "bi-exclamation-octagon",
                sub: "unresolved"
            },
            {
                label: "Avg Response",
                value: `${avgResponseHrs}h`,
                accent: "accent-warning",
                icon: "bi-stopwatch",
                sub: "creation to last update"
            }
        ];


        const kpiRow = document.getElementById("kpiRow");

        if (kpiRow) {

            kpiRow.innerHTML = kpis.map(k => `
                <div class="col-lg-3 col-md-6 col-6">
                    <div class="card stat-card ${k.accent} h-100">

                        <div class="eyebrow">
                            <i class="bi ${k.icon}"></i>
                            ${escapeHtml(k.label)}
                        </div>

                        <div class="stat-value">
                            ${k.value}
                        </div>

                        <span class="stat-delta text-muted">
                            ${escapeHtml(k.sub)}
                        </span>

                    </div>
                </div>
            `).join("");
        }


        /* ========================================================
           Charts
        ======================================================== */

        createIncidentTrendChart(incidents);

        createPriorityChart(incidents);

        createResolutionChart(incidents);


        /* ========================================================
           Recent incidents
        ======================================================== */

        renderRecentIncidents(incidents);
    }


    /* ============================================================
       Incident Trend
    ============================================================ */

    function createIncidentTrendChart(incidents) {

        const canvas = document.getElementById(
            "incidentTrendChart"
        );

        if (!canvas) {
            console.warn("incidentTrendChart canvas not found");
            return;
        }

        if (typeof Chart === "undefined") {
            console.error("Chart.js is not loaded");
            return;
        }


        const days = [];

        const now = new Date();


        for (let i = 13; i >= 0; i--) {

            const date = new Date(now);

            date.setHours(0, 0, 0, 0);

            date.setDate(date.getDate() - i);

            days.push(date);
        }


        const counts = days.map(day => {

            return incidents.filter(incident => {

                const created = parseDate(
                    incident.createdAt
                );

                if (!created) {
                    return false;
                }

                return (
                    created.getFullYear() === day.getFullYear() &&
                    created.getMonth() === day.getMonth() &&
                    created.getDate() === day.getDate()
                );

            }).length;
        });


        const ctx = canvas.getContext("2d");


        const gradient = ctx.createLinearGradient(
            0,
            0,
            0,
            260
        );


        const lineColor =
            window.XDR_PALETTE?.activity?.[0] ||
            "#3B82F6";


        gradient.addColorStop(
            0,
            lineColor + "55"
        );

        gradient.addColorStop(
            1,
            lineColor + "00"
        );


        new Chart(ctx, {

            type: "line",

            data: {

                labels: days.map(
                    d => `${d.getMonth() + 1}/${d.getDate()}`
                ),

                datasets: [
                    {
                        label: "Incidents opened",

                        data: counts,

                        borderColor: lineColor,

                        backgroundColor: gradient,

                        fill: true,

                        tension: 0.35,

                        pointRadius: 3,

                        pointHoverRadius: 5,

                        borderWidth: 2
                    }
                ]
            },

            options: window.XDR_CHART_DEFAULTS || {

                responsive: true,

                maintainAspectRatio: false
            }
        });
    }


    /* ============================================================
       Priority Distribution
    ============================================================ */

    function createPriorityChart(incidents) {

        const canvas = document.getElementById(
            "priorityChart"
        );

        if (!canvas) {
            console.warn("priorityChart canvas not found");
            return;
        }


        const priorityOrder = [
            "P1",
            "P2",
            "P3",
            "P4"
        ];


        const priorityCounts =
            priorityOrder.map(priority => {

                return incidents.filter(
                    incident =>
                        incident.priority === priority
                ).length;

            });


        const severityMap = {
            P1: "critical",
            P2: "high",
            P3: "medium",
            P4: "low"
        };


        const colors = priorityOrder.map(priority => {

            return (
                window.XDR_PALETTE?.severity?.[
                    severityMap[priority]
                ] ||
                "#64748B"
            );

        });


        new Chart(canvas, {

            type: "doughnut",

            data: {

                labels: priorityOrder,

                datasets: [
                    {
                        data: priorityCounts,

                        backgroundColor: colors,

                        borderWidth: 0
                    }
                ]
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

                            boxHeight: 8
                        }
                    }
                }
            }
        });
    }


    /* ============================================================
       Resolution Time by Category
    ============================================================ */

    function createResolutionChart(incidents) {

        const canvas = document.getElementById(
            "resolutionChart"
        );

        if (!canvas) {
            console.warn("resolutionChart canvas not found");
            return;
        }


        const categories = [
            ...new Set(
                incidents
                    .map(i => i.category)
                    .filter(Boolean)
            )
        ];


        const resolutionTimes =
            categories.map(category => {

                const resolved = incidents.filter(
                    incident =>
                        incident.category === category &&
                        (
                            incident.status === "resolved" ||
                            incident.status === "closed"
                        )
                );


                if (!resolved.length) {
                    return 0;
                }


                const total = resolved.reduce(
                    (sum, incident) => {

                        return sum +
                            hoursBetween(
                                incident.createdAt,
                                incident.updatedAt
                            );

                    },
                    0
                );


                return Math.round(
                    total / resolved.length * 10
                ) / 10;

            });


        const barColor =
            window.XDR_PALETTE?.activity?.[2] ||
            "#8B5CF6";


        new Chart(canvas, {

            type: "bar",

            data: {

                labels: categories,

                datasets: [
                    {
                        label: "Average resolution time",

                        data: resolutionTimes,

                        backgroundColor: barColor,

                        borderRadius: 4
                    }
                ]
            },

            options: {

                responsive: true,

                maintainAspectRatio: false,

                indexAxis: "y",

                scales: {

                    x: {

                        beginAtZero: true

                    }

                },

                plugins: {

                    legend: {
                        display: false
                    }
                }
            }
        });
    }


    /* ============================================================
       Recent Incidents
    ============================================================ */

    function renderRecentIncidents(incidents) {

        const tbody = document.getElementById(
            "recentIncidentsBody"
        );

        if (!tbody) {
            return;
        }


        const recent = incidents
            .slice()
            .sort(
                (a, b) =>
                    parseDate(b.createdAt) -
                    parseDate(a.createdAt)
            )
            .slice(0, 8);


        tbody.innerHTML = recent.map(incident => {

            const severity = escapeHtml(
                incident.severity || "unknown"
            );

            const status =
                STATUS_LABEL[incident.status] ||
                incident.status ||
                "Unknown";


            return `
                <tr>

                    <td>

                        <a
                            href="/incidents/${encodeURIComponent(
                                incident.id
                            )}"
                            style="
                                color:var(--text);
                                font-weight:600;
                                text-decoration:none;
                            "
                        >
                            ${escapeHtml(
                                incident.title ||
                                incident.id ||
                                "Incident"
                            )}
                        </a>

                        <div class="text-xs text-muted">
                            ${escapeHtml(
                                incident.category || ""
                            )}
                        </div>

                    </td>

                    <td>
                        ${severity}
                    </td>

                    <td>
                        <span class="status-pill st-${escapeHtml(
                            incident.status || ""
                        )}">
                            <span class="dot"></span>
                            ${escapeHtml(status)}
                        </span>
                    </td>

                    <td>
                        ${escapeHtml(
                            incident.assignedAnalyst ||
                            "Unassigned"
                        )}
                    </td>

                </tr>
            `;

        }).join("");
    }


    /* ============================================================
       Helpers
    ============================================================ */

    function parseDate(value) {

        if (!value) {
            return null;
        }

        const date = new Date(value);

        return Number.isNaN(date.getTime())
            ? null
            : date;
    }


    function hoursBetween(a, b) {

        const start = parseDate(a);
        const end = parseDate(b);

        if (!start || !end) {
            return 0;
        }

        return (
            (end.getTime() - start.getTime()) /
            3600000
        );
    }


    function escapeHtml(value) {

        if (value === null || value === undefined) {
            return "";
        }

        return String(value)
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");
    }


    function showDashboardError(message) {

        console.error(
            "Incident dashboard error:",
            message
        );

        const containers = [
            "incidentTrendChart",
            "priorityChart",
            "resolutionChart"
        ];

        containers.forEach(id => {

            const canvas =
                document.getElementById(id);

            if (!canvas) {
                return;
            }

            const parent =
                canvas.parentElement;

            if (parent) {

                parent.innerHTML = `
                    <div class="text-center text-muted p-4">
                        <i class="bi bi-exclamation-triangle"></i>
                        <div class="mt-2">
                            Unable to load incident data
                        </div>
                    </div>
                `;
            }
        });
    }

})();