/* ==========================================================================
   integrations.js — CyberDefense XDR
   Backend-connected integrations module

   Endpoints:
   GET  /settings/integrations/data
   POST /settings/integrations/save
   POST /settings/integrations/disconnect
   ========================================================================== */

(function () {

    "use strict";


    /* ================================================================
       ELEMENTS
       ================================================================ */

    const grid =
        document.getElementById("integrationsGrid");

    const summary =
        document.getElementById("integrationsSummary");

    const modalTitle =
        document.getElementById("cfgModalTitle");

    const webhookInput =
        document.getElementById("cfgWebhook");

    const tokenInput =
        document.getElementById("cfgToken");

    const saveConfigBtn =
        document.getElementById("cfgSaveBtn");


    /* ================================================================
       STATE
       ================================================================ */

    let integrations = [];

    let selectedIntegration = null;


    /* ================================================================
       TOAST
       ================================================================ */

    function toast(type, title, msg = "") {

        if (window.showToast) {

            window.showToast({
                type: type,
                title: title,
                msg: msg
            });

        }

    }


    /* ================================================================
       ESCAPE HTML
       ================================================================ */

    function escapeHtml(value) {

        if (value === null || value === undefined) {
            return "";
        }

        return String(value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");

    }


    /* ================================================================
       SUMMARY
       ================================================================ */

    function renderSummary() {

        if (!summary) {
            return;
        }

        const connected =
            integrations.filter(
                integration => integration.connected
            ).length;

        summary.textContent =
            `${connected} of ${integrations.length} integrations connected`;
    }


    /* ================================================================
       STATUS LABEL
       ================================================================ */

    function statusLabel(status) {

        if (!status) {
            return "disconnected";
        }

        return String(status).replace(
            /^./,
            char => char.toUpperCase()
        );
    }


    /* ================================================================
       RENDER
       ================================================================ */

    function render() {

        if (!grid) {
            return;
        }

        if (!integrations.length) {

            grid.innerHTML = `
                <div class="col-12">
                    <div class="card">
                        <div class="card-body text-center py-5">
                            <i class="bi bi-plug fs-1 text-muted"></i>

                            <h3 class="mt-3">
                                No integrations configured
                            </h3>

                            <p class="text-muted mb-0">
                                Integration records will appear here
                                once they are configured.
                            </p>
                        </div>
                    </div>
                </div>
            `;

            renderSummary();

            return;
        }


        grid.innerHTML =
            integrations.map((integration) => {

                const id =
                    escapeHtml(integration.id);

                const name =
                    escapeHtml(integration.name);

                const category =
                    escapeHtml(integration.category);

                const icon =
                    escapeHtml(integration.icon);

                const description =
                    escapeHtml(integration.description);

                const status =
                    escapeHtml(integration.status);

                const buttonClass =
                    integration.connected
                        ? "btn-secondary"
                        : "btn-primary";

                const buttonText =
                    integration.connected
                        ? "Disconnect"
                        : "Connect";


                return `
                    <div class="col-lg-3 col-md-6">

                        <div class="integration-card">

                            <div
                                class="d-flex
                                       justify-content-between
                                       align-items-start"
                            >

                                <span class="integration-icon">
                                    <i class="bi ${icon}"></i>
                                </span>

                                <span
                                    class="text-xs text-muted"
                                >
                                    <span
                                        class="integration-status-dot ${status}"
                                    ></span>

                                    ${statusLabel(status)}
                                </span>

                            </div>


                            <div>

                                <h3 class="fs-inherit-md mb-0">
                                    ${name}
                                </h3>

                                <span
                                    class="text-xs text-muted"
                                >
                                    ${category}
                                </span>

                            </div>


                            <p class="text-muted text-sm mb-0">
                                ${description}
                            </p>


                            <div
                                class="d-flex gap-2 mt-auto"
                            >

                                <button
                                    type="button"
                                    class="btn ${buttonClass}
                                           btn-sm flex-fill
                                           toggle-conn-btn"
                                    data-id="${id}"
                                >
                                    ${buttonText}
                                </button>

                                ${
                                    integration.connected
                                    ?
                                    `
                                    <button
                                        type="button"
                                        class="btn btn-icon
                                               btn-ghost btn-sm
                                               configure-btn"
                                        data-id="${id}"
                                        title="Configure"
                                    >
                                        <i class="bi bi-gear"></i>
                                    </button>
                                    `
                                    :
                                    ""
                                }

                            </div>

                        </div>

                    </div>
                `;

            }).join("");


        bindButtons();

        renderSummary();
    }


    /* ================================================================
       LOAD INTEGRATIONS
       ================================================================ */

    async function loadIntegrations() {

        try {

            const response =
                await fetch(
                    "/settings/integrations/data",
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


            if (!response.ok || !data.success) {

                throw new Error(
                    data.message ||
                    "Unable to load integrations."
                );
            }


            integrations =
                Array.isArray(data.integrations)
                    ? data.integrations
                    : [];


            render();


        } catch (error) {

            console.error(
                "Integration loading error:",
                error
            );


            grid.innerHTML = `
                <div class="col-12">

                    <div class="alert alert-danger">

                        <i class="bi bi-exclamation-triangle me-2"></i>

                        Unable to load integrations.

                    </div>

                </div>
            `;


            toast(
                "danger",
                "Unable to load integrations",
                error.message
            );

        }

    }


    /* ================================================================
       BIND BUTTONS
       ================================================================ */

    function bindButtons() {

        document
            .querySelectorAll(".toggle-conn-btn")
            .forEach((button) => {

                button.addEventListener(
                    "click",
                    async function () {

                        const id =
                            this.dataset.id;

                        const integration =
                            integrations.find(
                                item =>
                                    String(item.id) ===
                                    String(id)
                            );


                        if (!integration) {
                            return;
                        }


                        if (integration.connected) {

                            await disconnectIntegration(
                                integration
                            );

                        } else {

                            openConfigureModal(
                                integration
                            );

                        }

                    }
                );

            });


        document
            .querySelectorAll(".configure-btn")
            .forEach((button) => {

                button.addEventListener(
                    "click",
                    function () {

                        const id =
                            this.dataset.id;

                        const integration =
                            integrations.find(
                                item =>
                                    String(item.id) ===
                                    String(id)
                            );


                        if (!integration) {
                            return;
                        }


                        openConfigureModal(
                            integration
                        );

                    }
                );

            });

    }


    /* ================================================================
       OPEN CONFIGURATION MODAL
       ================================================================ */

    function openConfigureModal(
        integration
    ) {

        selectedIntegration =
            integration;


        if (modalTitle) {

            modalTitle.textContent =
                `Configure ${integration.name}`;

        }


        if (webhookInput) {

            webhookInput.value = "";

        }


        if (tokenInput) {

            tokenInput.value = "";

        }


        if (window.xdrOpenModal) {

            window.xdrOpenModal(
                "configureModal"
            );

        }

    }


    /* ================================================================
       CONNECT / SAVE INTEGRATION
       ================================================================ */

    async function saveIntegration() {

        if (!selectedIntegration) {

            toast(
                "warning",
                "No integration selected"
            );

            return;
        }


        const webhookUrl =
            webhookInput
                ? webhookInput.value.trim()
                : "";


        const token =
            tokenInput
                ? tokenInput.value.trim()
                : "";


        if (!webhookUrl && !token) {

            toast(
                "warning",
                "Configuration required",
                "Enter a webhook URL or API token."
            );

            return;
        }


        if (saveConfigBtn) {

            saveConfigBtn.disabled = true;

            saveConfigBtn.innerHTML = `
                <span
                    class="spinner-border
                           spinner-border-sm
                           me-2"
                ></span>

                Connecting...
            `;

        }


        try {

            const response =
                await fetch(
                    "/settings/integrations/save",
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

                                id:
                                    selectedIntegration.id,

                                webhook_url:
                                    webhookUrl,

                                token:
                                    token

                            })
                    }
                );


            const data =
                await response.json();


            if (!response.ok || !data.success) {

                throw new Error(
                    data.message ||
                    "Unable to connect integration."
                );

            }


            selectedIntegration.connected =
                true;

            selectedIntegration.status =
                "active";


            render();


            if (window.xdrCloseModal) {

                window.xdrCloseModal(
                    "configureModal"
                );

            }


            toast(
                "success",
                "Integration connected",
                selectedIntegration.name
            );


        } catch (error) {

            console.error(
                "Integration save error:",
                error
            );


            toast(
                "danger",
                "Connection failed",
                error.message
            );

        } finally {

            if (saveConfigBtn) {

                saveConfigBtn.disabled = false;

                saveConfigBtn.innerHTML =
                    "Save &amp; Connect";

            }

        }

    }


    /* ================================================================
       DISCONNECT
       ================================================================ */

    async function disconnectIntegration(
        integration
    ) {

        try {

            const response =
                await fetch(
                    "/settings/integrations/disconnect",
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
                                id:
                                    integration.id
                            })
                    }
                );


            const data =
                await response.json();


            if (!response.ok || !data.success) {

                throw new Error(
                    data.message ||
                    "Unable to disconnect integration."
                );

            }


            integration.connected =
                false;

            integration.status =
                "disconnected";


            render();


            toast(
                "warning",
                "Integration disconnected",
                integration.name
            );


        } catch (error) {

            console.error(
                "Integration disconnect error:",
                error
            );


            toast(
                "danger",
                "Disconnect failed",
                error.message
            );

        }

    }


    /* ================================================================
       SAVE BUTTON
       ================================================================ */

    if (saveConfigBtn) {

        saveConfigBtn.addEventListener(
            "click",
            function () {

                saveIntegration();

            }
        );

    }


    /* ================================================================
       INITIAL LOAD
       ================================================================ */

    loadIntegrations();

})();