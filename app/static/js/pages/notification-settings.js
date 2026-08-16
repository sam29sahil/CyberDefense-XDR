/* ==========================================================================
   CyberDefense XDR
   Notification Settings
   API-connected page module
   ========================================================================== */

(function () {

    "use strict";


    // ============================================================
    // CONFIGURATION
    // ============================================================

    const DATA_URL = "/settings/notifications/data";
    const SAVE_URL = "/settings/notifications/save";


    // ============================================================
    // NOTIFICATION CATEGORIES
    // ============================================================

    const CATEGORIES = [
        {
            key: "critical",
            name: "Critical Alerts"
        },
        {
            key: "incidents",
            name: "New Incidents"
        },
        {
            key: "scan_completed",
            name: "Scan Completed"
        },
        {
            key: "report_ready",
            name: "Report Ready"
        },
        {
            key: "system_health",
            name: "System Health"
        },
        {
            key: "user_management",
            name: "User Management Changes"
        }
    ];


    // ============================================================
    // DOM HELPERS
    // ============================================================

    const $ = (selector) =>
        document.querySelector(selector);


    // ============================================================
    // SHOW MESSAGE
    // ============================================================

    function showMessage(
        type,
        title,
        message = ""
    ) {

        if (window.showToast) {

            window.showToast({
                type: type,
                title: title,
                msg: message
            });

            return;
        }

        console.log(
            `[${type}] ${title}`,
            message
        );
    }


    // ============================================================
    // SET LOADING STATE
    // ============================================================

    function setLoading(
        loading
    ) {

        const button = $("#saveBtn");

        if (!button) {
            return;
        }


        if (loading) {

            button.disabled = true;

            button.dataset.originalHtml =
                button.innerHTML;

            button.innerHTML = `
                <span
                    class="spinner-border spinner-border-sm me-2"
                    role="status"
                    aria-hidden="true"
                ></span>
                Saving...
            `;

        } else {

            button.disabled = false;

            button.innerHTML =
                button.dataset.originalHtml ||
                `
                <i class="bi bi-check-lg"></i>
                Save Changes
                `;
        }
    }


    // ============================================================
    // RENDER NOTIFICATION MATRIX
    // ============================================================

    function renderMatrix(
        matrix = {}
    ) {

        const body =
            $("#notifyMatrixBody");

        if (!body) {
            return;
        }


        body.innerHTML = CATEGORIES.map(
            (category) => {

                const values =
                    matrix[category.key] || {};


                const email =
                    values.email === true;


                const slack =
                    values.slack === true;


                const sms =
                    values.sms === true;


                return `
                    <tr
                        data-category="${category.key}"
                    >

                        <td>
                            ${category.name}
                        </td>


                        <td>

                            <input
                                type="checkbox"
                                class="perm-check matrix-email"
                                ${email ? "checked" : ""}
                                aria-label="${category.name} Email"
                            >

                        </td>


                        <td>

                            <input
                                type="checkbox"
                                class="perm-check matrix-slack"
                                ${slack ? "checked" : ""}
                                aria-label="${category.name} Slack"
                            >

                        </td>


                        <td>

                            <input
                                type="checkbox"
                                class="perm-check matrix-sms"
                                ${sms ? "checked" : ""}
                                aria-label="${category.name} SMS"
                            >

                        </td>

                    </tr>
                `;

            }
        ).join("");
    }


    // ============================================================
    // LOAD SETTINGS
    // ============================================================

    async function loadSettings() {

        try {

            const response =
                await fetch(
                    DATA_URL,
                    {
                        method: "GET",

                        headers: {
                            "Accept":
                                "application/json"
                        },

                        credentials:
                            "same-origin"
                    }
                );


            const data =
                await response.json();


            if (!response.ok ||
                !data.success) {

                throw new Error(
                    data.message ||
                    "Unable to load notification settings."
                );
            }


            const settings =
                data.settings || {};


            // ----------------------------------------------------
            // CHANNELS
            // ----------------------------------------------------

            const email =
                $("#channelEmail");

            const slack =
                $("#channelSlack");

            const sms =
                $("#channelSms");

            const webhook =
                $("#channelWebhook");


            if (email) {
                email.checked =
                    settings.email_enabled !== false;
            }


            if (slack) {
                slack.checked =
                    settings.slack_enabled !== false;
            }


            if (sms) {
                sms.checked =
                    settings.sms_enabled === true;
            }


            if (webhook) {
                webhook.checked =
                    settings.webhook_enabled === true;
            }


            // ----------------------------------------------------
            // SEVERITY
            // ----------------------------------------------------

            const severity =
                $("#minSeverity");


            if (severity &&
                settings.min_severity) {

                severity.value =
                    settings.min_severity;
            }


            // ----------------------------------------------------
            // QUIET HOURS
            // ----------------------------------------------------

            const quietToggle =
                $("#quietHoursToggle");

            const quietFrom =
                $("#quietHoursFrom");

            const quietTo =
                $("#quietHoursTo");


            if (quietToggle) {

                quietToggle.checked =
                    settings.quiet_hours_enabled === true;
            }


            if (quietFrom &&
                settings.quiet_hours_from) {

                quietFrom.value =
                    settings.quiet_hours_from;
            }


            if (quietTo &&
                settings.quiet_hours_to) {

                quietTo.value =
                    settings.quiet_hours_to;
            }


            // ----------------------------------------------------
            // MATRIX
            // ----------------------------------------------------

            renderMatrix(
                settings.notification_matrix || {}
            );


        } catch (error) {

            console.error(
                "Notification settings load failed:",
                error
            );


            showMessage(
                "danger",
                "Unable to load settings",
                error.message
            );
        }
    }


    // ============================================================
    // COLLECT MATRIX
    // ============================================================

    function collectMatrix() {

        const matrix = {};


        document
            .querySelectorAll(
                "#notifyMatrixBody tr[data-category]"
            )
            .forEach(
                (row) => {

                    const key =
                        row.dataset.category;


                    matrix[key] = {

                        email:
                            row.querySelector(
                                ".matrix-email"
                            )?.checked === true,

                        slack:
                            row.querySelector(
                                ".matrix-slack"
                            )?.checked === true,

                        sms:
                            row.querySelector(
                                ".matrix-sms"
                            )?.checked === true

                    };

                }
            );


        return matrix;
    }


    // ============================================================
    // COLLECT SETTINGS
    // ============================================================

    function collectSettings() {

        return {

            // Channels

            email_enabled:
                $("#channelEmail")?.checked === true,

            slack_enabled:
                $("#channelSlack")?.checked === true,

            sms_enabled:
                $("#channelSms")?.checked === true,

            webhook_enabled:
                $("#channelWebhook")?.checked === true,


            // Matrix

            notification_matrix:
                collectMatrix(),


            // Severity

            min_severity:
                $("#minSeverity")?.value ||
                "medium",


            // Quiet hours

            quiet_hours_enabled:
                $("#quietHoursToggle")?.checked === true,

            quiet_hours_from:
                $("#quietHoursFrom")?.value ||
                "20:00",

            quiet_hours_to:
                $("#quietHoursTo")?.value ||
                "07:00"

        };
    }


    // ============================================================
    // SAVE SETTINGS
    // ============================================================

    async function saveSettings() {

        const payload =
            collectSettings();


        setLoading(true);


        try {

            const response =
                await fetch(
                    SAVE_URL,
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json",

                            "Accept":
                                "application/json"
                        },

                        credentials:
                            "same-origin",

                        body:
                            JSON.stringify(
                                payload
                            )
                    }
                );


            const data =
                await response.json();


            if (!response.ok ||
                !data.success) {

                throw new Error(
                    data.message ||
                    "Unable to save notification settings."
                );
            }


            showMessage(
                "success",
                "Settings saved",
                data.message ||
                "Notification preferences saved successfully."
            );


        } catch (error) {

            console.error(
                "Notification settings save failed:",
                error
            );


            showMessage(
                "danger",
                "Save failed",
                error.message
            );


        } finally {

            setLoading(false);

        }
    }


    // ============================================================
    // INITIALIZE
    // ============================================================

    function init() {

        const saveButton =
            $("#saveBtn");


        if (!saveButton) {

            console.error(
                "Notification settings: save button not found."
            );

            return;
        }


        saveButton.addEventListener(
            "click",
            saveSettings
        );


        loadSettings();
    }


    // ============================================================
    // DOM READY
    // ============================================================

    if (
        document.readyState ===
        "loading"
    ) {

        document.addEventListener(
            "DOMContentLoaded",
            init
        );

    } else {

        init();

    }

})();