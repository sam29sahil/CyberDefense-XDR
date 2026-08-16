/* ==========================================================================
   CyberDefense XDR
   API Settings
   Backend-connected API key management
   ========================================================================== */

(function () {

    "use strict";

    const DATA_URL = "/settings/api/data";
    const GENERATE_URL = "/settings/api/generate";
    const REVOKE_URL = "/settings/api/revoke";


    // ============================================================
    // HELPERS
    // ============================================================

    const $ = (selector) =>
        document.querySelector(selector);


    function showToast(type, title, msg = "") {

        if (window.showToast) {

            window.showToast({
                type: type,
                title: title,
                msg: msg
            });

            return;
        }

        console.log(`[${type}] ${title}`, msg);
    }


    function escapeHtml(value) {

        return String(value ?? "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }


    function formatDate(value) {

        if (!value) {
            return "Never";
        }

        const date = new Date(value);

        if (Number.isNaN(date.getTime())) {
            return "—";
        }

        return date.toLocaleString();
    }


    // ============================================================
    // RENDER API KEYS
    // ============================================================

    function render(keys) {

        const body = $("#apiKeysBody");

        if (!body) {
            return;
        }


        if (!keys || keys.length === 0) {

            body.innerHTML = `
                <tr>
                    <td
                        colspan="7"
                        class="text-center text-muted"
                        style="padding: 40px;"
                    >
                        <i
                            class="bi bi-key"
                            style="font-size: 28px;"
                        ></i>

                        <div class="mt-2">
                            No API keys have been generated.
                        </div>
                    </td>
                </tr>
            `;

            return;
        }


        body.innerHTML = keys.map((key) => {

            const status =
                key.status || "active";


            const statusClass =
                status === "active"
                    ? "badge-success"
                    : "badge-neutral";


            const scopes =
                Array.isArray(key.scopes)
                    ? key.scopes
                    : [];


            return `
                <tr>

                    <td style="font-weight:600;">

                        ${escapeHtml(key.name)}

                        <div class="text-xs text-muted">
                            by ${escapeHtml(
                                key.created_by || "Unknown"
                            )}
                        </div>

                    </td>


                    <td class="api-key-value">

                        ${escapeHtml(
                            key.prefix || "xdr_"
                        )}

                        ••••••••••••••

                    </td>


                    <td>

                        ${
                            scopes.length
                                ? scopes.map(
                                    (scope) => `
                                        <span
                                            class="scope-chip"
                                        >
                                            ${escapeHtml(scope)}
                                        </span>
                                    `
                                ).join(" ")
                                : "—"
                        }

                    </td>


                    <td class="text-sm text-muted">
                        ${formatDate(key.created_at)}
                    </td>


                    <td class="text-sm text-muted">
                        ${formatDate(key.last_used)}
                    </td>


                    <td>

                        <span
                            class="badge ${statusClass}"
                        >
                            ${escapeHtml(status)}
                        </span>

                    </td>


                    <td>

                        <button
                            class="btn btn-icon btn-ghost btn-sm revoke-btn"
                            data-id="${escapeHtml(key.id)}"
                            ${
                                status === "revoked"
                                    ? "disabled"
                                    : ""
                            }
                            title="Revoke"
                        >
                            <i class="bi bi-trash"></i>
                        </button>

                    </td>

                </tr>
            `;

        }).join("");


        // --------------------------------------------------------
        // Revoke buttons
        // --------------------------------------------------------

        document
            .querySelectorAll(".revoke-btn")
            .forEach((button) => {

                button.addEventListener(
                    "click",
                    () => {

                        const keyId =
                            button.dataset.id;


                        const key =
                            keys.find(
                                (item) =>
                                    String(item.id) ===
                                    String(keyId)
                            );


                        if (!key) {
                            return;
                        }


                        const name =
                            $("#revokeKeyName");


                        const confirmButton =
                            $("#confirmRevokeBtn");


                        if (name) {
                            name.textContent =
                                key.name;
                        }


                        if (confirmButton) {

                            confirmButton.dataset.id =
                                key.id;
                        }


                        if (
                            window.xdrOpenModal
                        ) {

                            window.xdrOpenModal(
                                "revokeKeyModal"
                            );

                        }

                    }
                );

            });

    }


    // ============================================================
    // LOAD API KEYS
    // ============================================================

    async function loadKeys() {

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


            if (
                !response.ok ||
                !data.success
            ) {

                throw new Error(
                    data.message ||
                    "Unable to load API keys."
                );
            }


            render(
                data.keys || []
            );


        } catch (error) {

            console.error(
                "API key loading error:",
                error
            );


            showToast(
                "danger",
                "Unable to load API keys",
                error.message
            );

        }

    }


    // ============================================================
    // GENERATE API KEY
    // ============================================================

    async function generateKey() {

        const nameInput =
            $("#newKeyName");


        const name =
            nameInput
                ? nameInput.value.trim()
                : "";


        if (!name) {

            showToast(
                "warning",
                "Key name required",
                "Enter a name for the API key."
            );

            return;
        }


        const scopeInputs =
            document.querySelectorAll(
                "#newKeyModal input[type='checkbox']:checked"
            );


        const scopes =
            Array.from(scopeInputs)
                .map(
                    (input) =>
                        input.value
                );


        const finalScopes =
            scopes.length
                ? scopes
                : ["read:alerts"];


        const button =
            $("#generateKeyConfirm");


        if (button) {

            button.disabled = true;

            button.dataset.originalHtml =
                button.innerHTML;

            button.innerHTML = `
                <span
                    class="spinner-border spinner-border-sm me-2"
                ></span>
                Generating...
            `;
        }


        try {

            const response =
                await fetch(
                    GENERATE_URL,
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
                                name: name,
                                scopes: finalScopes
                            })
                    }
                );


            const data =
                await response.json();


            if (
                !response.ok ||
                !data.success
            ) {

                throw new Error(
                    data.message ||
                    "Unable to generate API key."
                );
            }


            // ----------------------------------------------------
            // Clear form
            // ----------------------------------------------------

            if (nameInput) {
                nameInput.value = "";
            }


            document
                .querySelectorAll(
                    "#newKeyModal input[type='checkbox']"
                )
                .forEach(
                    (input) => {
                        input.checked =
                            input.value ===
                            "read:alerts";
                    }
                );


            // ----------------------------------------------------
            // Show one-time key
            // ----------------------------------------------------

            const revealed =
                $("#revealedKeyText");


            if (revealed) {

                revealed.textContent =
                    data.key || "—";
            }


            // ----------------------------------------------------
            // Refresh table
            // ----------------------------------------------------

            await loadKeys();


            // ----------------------------------------------------
            // Open reveal modal
            // ----------------------------------------------------

            if (
                window.xdrOpenModal
            ) {

                window.xdrOpenModal(
                    "revealKeyModal"
                );

            }


            showToast(
                "success",
                "API key generated",
                "Copy the key now. It will not be shown again."
            );


        } catch (error) {

            console.error(
                "API key generation error:",
                error
            );


            showToast(
                "danger",
                "Key generation failed",
                error.message
            );


        } finally {

            if (button) {

                button.disabled = false;

                button.innerHTML =
                    button.dataset.originalHtml ||
                    "Generate Key";
            }

        }

    }


    // ============================================================
    // REVOKE API KEY
    // ============================================================

    async function revokeKey() {

        const button =
            $("#confirmRevokeBtn");


        if (!button) {
            return;
        }


        const keyId =
            button.dataset.id;


        if (!keyId) {
            return;
        }


        button.disabled = true;


        try {

            const response =
                await fetch(
                    REVOKE_URL,
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
                                id: keyId
                            })
                    }
                );


            const data =
                await response.json();


            if (
                !response.ok ||
                !data.success
            ) {

                throw new Error(
                    data.message ||
                    "Unable to revoke API key."
                );
            }


            await loadKeys();


            showToast(
                "danger",
                "API key revoked",
                data.message ||
                "The API key has been revoked."
            );


        } catch (error) {

            console.error(
                "API key revoke error:",
                error
            );


            showToast(
                "danger",
                "Revoke failed",
                error.message
            );


        } finally {

            button.disabled = false;

        }

    }


    // ============================================================
    // INITIALIZE
    // ============================================================

    function init() {

        const generateButton =
            $("#generateKeyConfirm");


        const revokeButton =
            $("#confirmRevokeBtn");


        if (generateButton) {

            generateButton.addEventListener(
                "click",
                generateKey
            );

        }


        if (revokeButton) {

            revokeButton.addEventListener(
                "click",
                revokeKey
            );

        }


        loadKeys();

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