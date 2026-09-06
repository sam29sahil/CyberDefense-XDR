/* ==========================================================================
   IOC Feed
   CyberDefense XDR

   Data source:
   Flask API → PostgreSQL

   Endpoint:
   /threat-intelligence/iocs
   ========================================================================== */

(function () {
    "use strict";

    const API_BASE =
        window.THREAT_INTEL_API || "/threat-intelligence";

    const IOC_DETAILS_URL =
        window.THREAT_INTEL_IOC_DETAILS ||
        "/threat-intelligence/ioc-details";

    let data = [];
    let table = null;


    // -----------------------------------------------------------------------
    // API helper
    // -----------------------------------------------------------------------

    async function fetchJson(url, options = {}) {
        const response = await fetch(url, {
            credentials: "same-origin",
            headers: {
                "Accept": "application/json",
                ...(options.body
                    ? { "Content-Type": "application/json" }
                    : {})
            },
            ...options
        });

        let payload;

        try {
            payload = await response.json();
        } catch (error) {
            throw new Error(
                `Server returned invalid JSON (${response.status})`
            );
        }

        if (!response.ok || payload.success === false) {
            throw new Error(
                payload.message ||
                payload.error ||
                `Request failed (${response.status})`
            );
        }

        return payload;
    }


    // -----------------------------------------------------------------------
    // Utilities
    // -----------------------------------------------------------------------

    function escapeHtml(value) {
        if (window.XDRUtils && XDRUtils.escapeHtml) {
            return XDRUtils.escapeHtml(String(value ?? ""));
        }

        return String(value ?? "")
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");
    }


    function normalizeTags(tags) {
        if (Array.isArray(tags)) {
            return tags;
        }

        if (!tags) {
            return [];
        }

        if (typeof tags === "string") {
            try {
                const parsed = JSON.parse(tags);

                if (Array.isArray(parsed)) {
                    return parsed;
                }
            } catch (_) {
                return tags
                    .split(",")
                    .map((tag) => tag.trim())
                    .filter(Boolean);
            }
        }

        return [];
    }


    function normalizeIOC(ioc) {
        return {
            ...ioc,
            tags: normalizeTags(ioc.tags),
            value: ioc.value ?? "",
            type: ioc.type ?? "",
            threatLevel: ioc.threatLevel ?? "",
            confidence: ioc.confidence ?? "",
            source: ioc.source ?? "",
            sightings: Number(ioc.sightings ?? 0),
            status: ioc.status ?? ""
        };
    }


    // -----------------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------------

    function renderSummary() {
        const element =
            document.getElementById("iocCountSummary");

        if (!element) {
            return;
        }

        const total = data.length;

        const active = data.filter(
            (ioc) => ioc.status === "active"
        ).length;

        const blocked = data.filter(
            (ioc) => ioc.status === "blocked"
        ).length;

        element.textContent =
            `${total} indicators · ${active} active · ${blocked} blocked`;
    }


    // -----------------------------------------------------------------------
    // Table columns
    // -----------------------------------------------------------------------

    const columns = [

        {
            key: "value",
            label: "Indicator",
            sortable: true,

            render: (row) => {

                const id =
                    encodeURIComponent(row.id);

                const tags =
                    row.tags
                        .map((tag) => escapeHtml(tag))
                        .join(", ");

                return `
                    <a
                        href="${IOC_DETAILS_URL}?id=${id}"
                        class="ioc-value"
                        style="text-decoration:none;"
                    >
                        ${escapeHtml(row.value)}
                    </a>

                    <div
                        class="text-xs text-muted"
                        style="margin-top:2px;"
                    >
                        ${tags}
                    </div>
                `;
            }
        },


        {
            key: "type",
            label: "Type",
            sortable: true,

            render: (row) => `
                <span class="ioc-type-chip">
                    ${escapeHtml(row.type)}
                </span>
            `
        },


        {
            key: "threatLevel",
            label: "Threat Level",
            sortable: true,

            render: (row) => {

                if (
                    window.XDRUtils &&
                    XDRUtils.severityBadge
                ) {
                    return XDRUtils.severityBadge(
                        row.threatLevel
                    );
                }

                return `
                    <span class="badge badge-neutral">
                        ${escapeHtml(row.threatLevel)}
                    </span>
                `;
            }
        },


        {
            key: "confidence",
            label: "Confidence",
            sortable: true,

            render: (row) => {

                const confidence =
                    String(row.confidence || "").toLowerCase();

                return `
                    <span
                        class="confidence-dots conf-${escapeHtml(confidence)}"
                    >
                        <span></span>
                        <span></span>
                        <span></span>
                    </span>

                    <span class="text-sm">
                        ${escapeHtml(row.confidence)}
                    </span>
                `;
            }
        },


        {
            key: "source",
            label: "Source",
            sortable: true,

            render: (row) => `
                <span class="text-sm">
                    ${escapeHtml(row.source)}
                </span>
            `
        },


        {
            key: "sightings",
            label: "Sightings",
            sortable: true,

            render: (row) => `
                <span class="cell-mono">
                    ${row.sightings}
                </span>
            `
        },


        {
            key: "status",
            label: "Status",
            sortable: true,

            render: (row) => {

                let badgeClass = "badge-neutral";

                if (row.status === "active") {
                    badgeClass = "badge-warning";
                } else if (row.status === "blocked") {
                    badgeClass = "badge-danger";
                } else if (row.status === "whitelisted") {
                    badgeClass = "badge-success";
                }

                return `
                    <span class="badge ${badgeClass}">
                        ${escapeHtml(row.status)}
                    </span>
                `;
            }
        },


        {
            key: "actions",
            label: "",
            sortable: false,

            render: (row) => {

                const id =
                    encodeURIComponent(row.id);

                const isBlocked =
                    row.status === "blocked";

                return `
                    <div class="row-actions">

                        <a
                            href="${IOC_DETAILS_URL}?id=${id}"
                            class="btn btn-icon btn-ghost btn-sm"
                            title="View IOC"
                        >
                            <i class="bi bi-eye"></i>
                        </a>

                        <button
                            class="btn btn-icon btn-ghost btn-sm block-btn"
                            data-id="${escapeHtml(row.id)}"
                            title="${isBlocked ? "Unblock" : "Block"}"
                            type="button"
                        >
                            <i class="bi bi-slash-circle"></i>
                        </button>

                    </div>
                `;
            }
        }

    ];


    // -----------------------------------------------------------------------
    // Table
    // -----------------------------------------------------------------------

    function createTable() {

        table = new XDRTable({
            tableEl:
                document.getElementById("iocTable"),

            searchInput:
                document.getElementById("iocSearch"),

            paginationEl:
                document.getElementById("iocPagination"),

            data,

            pageSize: 12,

            searchKeys: [
                "value",
                "source",
                "tags"
            ],

            columns,

            onRowsChange: wireRowActions
        });

        table.state.sortKey = "lastSeen";
        table.state.sortDir = -1;
    }


    // -----------------------------------------------------------------------
    // Row actions
    // -----------------------------------------------------------------------

    function wireRowActions() {

        document
            .querySelectorAll(".block-btn")
            .forEach((button) => {

                button.addEventListener(
                    "click",
                    async () => {

                        const iocId =
                            button.dataset.id;

                        const row =
                            data.find(
                                (ioc) =>
                                    String(ioc.id) ===
                                    String(iocId)
                            );

                        if (!row) {
                            return;
                        }

                        const newStatus =
                            row.status === "blocked"
                                ? "active"
                                : "blocked";

                        button.disabled = true;

                        try {

                            await fetchJson(
                                `${API_BASE}/iocs/${encodeURIComponent(iocId)}/status`,
                                {
                                    method: "PATCH",

                                    body: JSON.stringify({
                                        status: newStatus
                                    })
                                }
                            );

                            row.status = newStatus;

                            renderSummary();

                            table.render();

                            if (window.showToast) {
                                window.showToast({
                                    type:
                                        newStatus === "blocked"
                                            ? "danger"
                                            : "success",

                                    title:
                                        newStatus === "blocked"
                                            ? "Indicator blocked"
                                            : "Indicator unblocked",

                                    msg: row.value
                                });
                            }

                        } catch (error) {

                            console.error(
                                "Failed to update IOC status:",
                                error
                            );

                            if (window.showToast) {
                                window.showToast({
                                    type: "danger",
                                    title: "Update failed",
                                    msg: error.message
                                });
                            } else {
                                alert(
                                    `Unable to update IOC: ${error.message}`
                                );
                            }

                        } finally {
                            button.disabled = false;
                        }

                    }
                );

            });
    }


    // -----------------------------------------------------------------------
    // Filters
    // -----------------------------------------------------------------------

    function applyFilters() {

        if (!table) {
            return;
        }

        const type =
            document.getElementById("filterType").value;

        const level =
            document.getElementById("filterLevel").value;

        const status =
            document.getElementById("filterStatus").value;


        table.setFilter((row) => {

            return (
                (!type || row.type === type) &&
                (!level || row.threatLevel === level) &&
                (!status || row.status === status)
            );

        });
    }


    function setupFilters() {

        [
            "filterType",
            "filterLevel",
            "filterStatus"
        ].forEach((id) => {

            document
                .getElementById(id)
                .addEventListener(
                    "change",
                    applyFilters
                );

        });


        document
            .getElementById("clearFilters")
            .addEventListener(
                "click",
                () => {

                    document
                        .getElementById("iocSearch")
                        .value = "";

                    [
                        "filterType",
                        "filterLevel",
                        "filterStatus"
                    ].forEach((id) => {

                        document
                            .getElementById(id)
                            .value = "";

                    });


                    if (table) {

                        table.state.query = "";

                        table.setFilter(null);

                        table.render();
                    }

                }
            );
    }


    // -----------------------------------------------------------------------
    // Load IOCs from Flask
    // -----------------------------------------------------------------------

    async function loadIOCs() {

        const summary =
            document.getElementById("iocCountSummary");

        try {

            const payload =
                await fetchJson(
                    `${API_BASE}/iocs?per_page=100&page=1`
                );

            const items =
                payload?.data?.items || [];

            data =
                items.map(normalizeIOC);

            renderSummary();

            createTable();

            setupFilters();

        } catch (error) {

            console.error(
                "Failed to load IOC feed:",
                error
            );

            if (summary) {
                summary.textContent =
                    "Unable to load indicators";
            }

            const tbody =
                document.querySelector(
                    "#iocTable tbody"
                );

            if (tbody) {
                tbody.innerHTML = `
                    <tr>
                        <td
                            colspan="8"
                            class="text-center text-muted"
                            style="padding:32px;"
                        >
                            <i class="bi bi-exclamation-triangle"></i>
                            Failed to load IOC data:
                            ${escapeHtml(error.message)}
                        </td>
                    </tr>
                `;
            }

            if (window.showToast) {
                window.showToast({
                    type: "danger",
                    title: "IOC Feed error",
                    msg: error.message
                });
            }

        }

    }


    // -----------------------------------------------------------------------
    // Start
    // -----------------------------------------------------------------------

    document.addEventListener(
        "DOMContentLoaded",
        loadIOCs
    );

})();