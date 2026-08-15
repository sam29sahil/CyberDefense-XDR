/*
 * CyberDefense XDR
 * Security Settings
 *
 * Connects the Security Settings page
 * to the Flask backend and PostgreSQL.
 */

(function () {

    "use strict";


    let allowlist = [];

    let settingsLoaded = false;


    // =========================================================
    // ELEMENT HELPERS
    // =========================================================

    function get(id) {
        return document.getElementById(id);
    }


    // =========================================================
    // TOAST
    // =========================================================

    function toast(type, title, msg) {

        if (window.showToast) {

            window.showToast({
                type: type,
                title: title,
                msg: msg || ""
            });

        } else {

            console.log(
                `[${type}] ${title}: ${msg || ""}`
            );

        }
    }


    // =========================================================
    // LOAD SETTINGS
    // =========================================================

    async function loadSettings() {

        try {

            const response = await fetch(
                "/settings/security/data",
                {
                    method: "GET",
                    headers: {
                        "Accept": "application/json"
                    },
                    credentials: "same-origin"
                }
            );


            const data = await response.json();


            if (!response.ok || !data.success) {

                throw new Error(
                    data.message ||
                    "Unable to load security settings."
                );

            }


            const settings =
                data.settings || {};


            // -------------------------------------------------
            // Password policy
            // -------------------------------------------------

            const minLength =
                get("pwMinLength");

            const expiry =
                get("pwExpiry");


            if (minLength) {
                minLength.value =
                    settings.pw_min_length ?? 12;
            }


            if (expiry) {
                expiry.value =
                    settings.pw_expiry ?? 90;
            }


            // -------------------------------------------------
            // Password policy switches
            // -------------------------------------------------

            const switches =
                document.querySelectorAll(
                    ".card .xdr-switch input"
                );


            /*
             * Security page switch order:
             *
             * 0 = Require uppercase/lowercase
             * 1 = Require numbers
             * 2 = Require symbols
             * 3 = Prevent password reuse
             * 4 = Enforce MFA
             */

            if (switches.length >= 5) {

                switches[0].checked =
                    Boolean(
                        settings.require_case
                    );

                switches[1].checked =
                    Boolean(
                        settings.require_numbers
                    );

                switches[2].checked =
                    Boolean(
                        settings.require_symbols
                    );

                switches[3].checked =
                    Boolean(
                        settings.prevent_reuse
                    );

                switches[4].checked =
                    Boolean(
                        settings.enforce_mfa
                    );
            }


            // -------------------------------------------------
            // Maximum sessions
            // -------------------------------------------------

            const maxSessions =
                get("maxSessions");


            if (maxSessions) {

                maxSessions.value =
                    settings.max_sessions || "3";
            }


            // -------------------------------------------------
            // IP allowlist
            // -------------------------------------------------

            allowlist =
                Array.isArray(settings.allowlist)
                    ? settings.allowlist.map(
                        (cidr, index) => ({
                            id:
                                `IP-${index + 1}`,
                            cidr:
                                cidr,
                            label:
                                "Manually added",
                            addedBy:
                                "Current user"
                        })
                    )
                    : [];


            renderAllowlist();


            settingsLoaded = true;


        } catch (error) {

            console.error(
                "Failed to load security settings:",
                error
            );


            toast(
                "danger",
                "Unable to load settings",
                error.message
            );
        }
    }


    // =========================================================
    // RENDER IP ALLOWLIST
    // =========================================================

    function renderAllowlist() {

        const container =
            get("allowlistBody");


        if (!container) {
            return;
        }


        if (!allowlist.length) {

            container.innerHTML = `
                <p class="text-muted text-sm">
                    No IP restrictions configured —
                    access allowed from any network.
                </p>
            `;

            return;
        }


        container.innerHTML =
            allowlist.map(
                (entry) => `
                    <div class="settings-row">

                        <div>

                            <div class="row-label cell-mono">
                                ${escapeHtml(entry.cidr)}
                            </div>

                            <div class="row-hint">
                                ${escapeHtml(entry.label)}
                                · added by
                                ${escapeHtml(entry.addedBy)}
                            </div>

                        </div>

                        <button
                            type="button"
                            class="btn btn-icon btn-ghost btn-sm remove-cidr-btn"
                            data-id="${entry.id}"
                            title="Remove IP range"
                        >

                            <i class="bi bi-trash"></i>

                        </button>

                    </div>
                `
            )
            .join("");


        document
            .querySelectorAll(".remove-cidr-btn")
            .forEach(
                (button) => {

                    button.addEventListener(
                        "click",
                        function () {

                            const id =
                                this.dataset.id;


                            const entry =
                                allowlist.find(
                                    item =>
                                        item.id === id
                                );


                            allowlist =
                                allowlist.filter(
                                    item =>
                                        item.id !== id
                                );


                            renderAllowlist();


                            if (entry) {

                                toast(
                                    "warning",
                                    "Entry removed",
                                    entry.cidr
                                );

                            }

                        }
                    );

                }
            );
    }


    // =========================================================
    // ADD IP / CIDR
    // =========================================================

    function addCidr() {

        const input =
            get("newCidrInput");


        if (!input) {
            return;
        }


        const value =
            input.value.trim();


        if (!value) {

            toast(
                "warning",
                "Missing IP range",
                "Enter an IP address or CIDR range."
            );

            input.focus();

            return;
        }


        // Basic IPv4 / CIDR validation.
        const cidrPattern =
            /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\/(?:3[0-2]|[12]?\d))?$/;


        if (!cidrPattern.test(value)) {

            toast(
                "danger",
                "Invalid IP range",
                "Enter a valid IPv4 address or CIDR range."
            );

            input.focus();

            return;
        }


        const exists =
            allowlist.some(
                entry =>
                    entry.cidr.toLowerCase() ===
                    value.toLowerCase()
            );


        if (exists) {

            toast(
                "warning",
                "Already exists",
                "That IP range is already in the allowlist."
            );

            return;
        }


        allowlist.push({

            id:
                `IP-${Date.now()}`,

            cidr:
                value,

            label:
                "Manually added",

            addedBy:
                "Current user"

        });


        input.value = "";


        renderAllowlist();


        toast(
            "success",
            "IP range added",
            value
        );
    }


    // =========================================================
    // SAVE SETTINGS
    // =========================================================

    async function saveSettings() {

        if (!settingsLoaded) {

            toast(
                "warning",
                "Please wait",
                "Security settings are still loading."
            );

            return;
        }


        const saveButton =
            get("saveBtn");


        const originalHtml =
            saveButton
                ? saveButton.innerHTML
                : "";


        // -----------------------------------------------------
        // Get password policy values
        // -----------------------------------------------------

        const minLength =
            parseInt(
                get("pwMinLength")?.value || "12",
                10
            );


        const expiry =
            parseInt(
                get("pwExpiry")?.value || "90",
                10
            );


        // -----------------------------------------------------
        // Get switches
        // -----------------------------------------------------

        const switches =
            document.querySelectorAll(
                ".card .xdr-switch input"
            );


        const requireCase =
            switches[0]
                ? switches[0].checked
                : true;


        const requireNumbers =
            switches[1]
                ? switches[1].checked
                : true;


        const requireSymbols =
            switches[2]
                ? switches[2].checked
                : false;


        const preventReuse =
            switches[3]
                ? switches[3].checked
                : true;


        const enforceMfa =
            switches[4]
                ? switches[4].checked
                : true;


        // -----------------------------------------------------
        // Maximum sessions
        // -----------------------------------------------------

        const maxSessions =
            get("maxSessions")?.value || "3";


        // -----------------------------------------------------
        // Validate
        // -----------------------------------------------------

        if (
            Number.isNaN(minLength) ||
            minLength < 8 ||
            minLength > 32
        ) {

            toast(
                "danger",
                "Invalid password length",
                "Minimum length must be between 8 and 32."
            );

            return;
        }


        if (
            Number.isNaN(expiry) ||
            expiry < 0
        ) {

            toast(
                "danger",
                "Invalid password expiry",
                "Expiry cannot be negative."
            );

            return;
        }


        // -----------------------------------------------------
        // Loading state
        // -----------------------------------------------------

        if (saveButton) {

            saveButton.disabled = true;

            saveButton.innerHTML = `
                <span
                    class="spinner-border spinner-border-sm me-2"
                    role="status"
                    aria-hidden="true"
                ></span>
                Saving...
            `;
        }


        try {

            const response =
                await fetch(
                    "/settings/security/save",
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
                            JSON.stringify({

                                pw_min_length:
                                    minLength,

                                pw_expiry:
                                    expiry,

                                require_case:
                                    requireCase,

                                require_numbers:
                                    requireNumbers,

                                require_symbols:
                                    requireSymbols,

                                prevent_reuse:
                                    preventReuse,

                                enforce_mfa:
                                    enforceMfa,

                                max_sessions:
                                    maxSessions,

                                allowlist:
                                    allowlist.map(
                                        entry =>
                                            entry.cidr
                                    )
                            })
                    }
                );


            const data =
                await response.json();


            if (!response.ok || !data.success) {

                throw new Error(
                    data.message ||
                    "Unable to save security settings."
                );
            }


            toast(
                "success",
                "Security settings saved",
                data.message ||
                "Your security settings were updated."
            );


        } catch (error) {

            console.error(
                "Failed to save security settings:",
                error
            );


            toast(
                "danger",
                "Save failed",
                error.message
            );


        } finally {

            if (saveButton) {

                saveButton.disabled = false;

                saveButton.innerHTML =
                    originalHtml;
            }
        }
    }


    // =========================================================
    // HTML ESCAPE
    // =========================================================

    function escapeHtml(value) {

        return String(value)
            .replace(
                /&/g,
                "&amp;"
            )
            .replace(
                /</g,
                "&lt;"
            )
            .replace(
                />/g,
                "&gt;"
            )
            .replace(
                /"/g,
                "&quot;"
            )
            .replace(
                /'/g,
                "&#039;"
            );
    }


    // =========================================================
    // INITIALIZE
    // =========================================================

    document.addEventListener(
        "DOMContentLoaded",
        function () {

            const addButton =
                get("addCidrBtn");


            const saveButton =
                get("saveBtn");


            if (addButton) {

                addButton.addEventListener(
                    "click",
                    addCidr
                );

            }


            if (saveButton) {

                saveButton.addEventListener(
                    "click",
                    saveSettings
                );

            }


            loadSettings();

        }
    );


})();