/* ==========================================================================
   general-settings.js — CyberDefense XDR
   Backend-connected General Settings
   ========================================================================== */

(function () {

    "use strict";


    /* ================================================================
       ELEMENTS
    ================================================================ */

    const saveBtn =
        document.getElementById("saveBtn");

    const uploadLogoBtn =
        document.getElementById("uploadLogoBtn");

    const logoFileInput =
        document.getElementById("logoFileInput");

    const orgName =
        document.getElementById("orgName");

    const timezone =
        document.getElementById("timezone");

    const dateFormat =
        document.getElementById("dateFormat");

    const language =
        document.getElementById("language");

    const defaultLanding =
        document.getElementById("defaultLanding");

    const sessionTimeout =
        document.getElementById("sessionTimeout");

    const compactDensity =
        document.getElementById("compactDensity");


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
       LOAD SETTINGS
    ================================================================ */

    async function loadSettings() {

        try {

            const response =
                await fetch(
                    "/settings/general/data",
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
                    "Unable to load general settings."
                );

            }


            const settings =
                data.settings;


            if (orgName) {

                orgName.value =
                    settings.organization_name || "";

            }


            if (timezone) {

                timezone.value =
                    settings.timezone ||
                    "America/New_York";

            }


            if (dateFormat) {

                dateFormat.value =
                    settings.date_format ||
                    "YYYY-MM-DD";

            }


            if (language) {

                language.value =
                    settings.language ||
                    "en-US";

            }


            if (defaultLanding) {

                defaultLanding.value =
                    settings.default_landing ||
                    "dashboard";

            }


            if (sessionTimeout) {

                sessionTimeout.value =
                    String(
                        settings.session_timeout || 30
                    );

            }


            if (compactDensity) {

                compactDensity.checked =
                    Boolean(
                        settings.compact_density
                    );

            }


        } catch (error) {

            console.error(
                "General settings load error:",
                error
            );


            toast(
                "danger",
                "Unable to load settings",
                error.message
            );

        }

    }


    /* ================================================================
       SAVE SETTINGS
    ================================================================ */

    async function saveSettings() {

        if (!saveBtn) {
            return;
        }


        const payload = {

            organization_name:
                orgName
                    ? orgName.value.trim()
                    : "",

            timezone:
                timezone
                    ? timezone.value
                    : "America/New_York",

            date_format:
                dateFormat
                    ? dateFormat.value
                    : "YYYY-MM-DD",

            language:
                language
                    ? language.value
                    : "en-US",

            default_landing:
                defaultLanding
                    ? defaultLanding.value
                    : "dashboard",

            session_timeout:
                sessionTimeout
                    ? Number(
                        sessionTimeout.value
                    )
                    : 30,

            compact_density:
                compactDensity
                    ? compactDensity.checked
                    : false

        };


        if (!payload.organization_name) {

            toast(
                "warning",
                "Organization name required"
            );

            if (orgName) {
                orgName.focus();
            }

            return;
        }


        saveBtn.disabled = true;

        saveBtn.innerHTML = `
            <span
                class="spinner-border
                       spinner-border-sm
                       me-2"
            ></span>
            Saving...
        `;


        try {

            const response =
                await fetch(
                    "/settings/general/save",
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
                            JSON.stringify(payload)
                    }
                );


            const data =
                await response.json();


            if (!response.ok || !data.success) {

                throw new Error(
                    data.message ||
                    "Unable to save settings."
                );

            }


            toast(
                "success",
                "Settings saved",
                data.message ||
                "General preferences updated."
            );


        } catch (error) {

            console.error(
                "General settings save error:",
                error
            );


            toast(
                "danger",
                "Save failed",
                error.message
            );

        } finally {

            saveBtn.disabled = false;

            saveBtn.innerHTML = `
                <i class="bi bi-check-lg"></i>
                Save Changes
            `;

        }

    }


    /* ================================================================
       LOGO UPLOAD
    ================================================================ */

    if (uploadLogoBtn && logoFileInput) {

        uploadLogoBtn.addEventListener(
            "click",
            function () {

                logoFileInput.click();

            }
        );


        logoFileInput.addEventListener(
            "change",
            function () {

                const file =
                    this.files &&
                    this.files[0];


                if (!file) {
                    return;
                }


                const maxSize =
                    2 * 1024 * 1024;


                const allowedTypes = [
                    "image/png",
                    "image/svg+xml"
                ];


                if (
                    !allowedTypes.includes(
                        file.type
                    )
                ) {

                    toast(
                        "warning",
                        "Invalid logo format",
                        "Only PNG or SVG files are allowed."
                    );

                    this.value = "";

                    return;
                }


                if (file.size > maxSize) {

                    toast(
                        "warning",
                        "Logo is too large",
                        "Maximum allowed size is 2MB."
                    );

                    this.value = "";

                    return;
                }


                toast(
                    "info",
                    "Logo selected",
                    file.name
                );

            }
        );

    }


    /* ================================================================
       SAVE BUTTON
    ================================================================ */

    if (saveBtn) {

        saveBtn.addEventListener(
            "click",
            saveSettings
        );

    }


    /* ================================================================
       INITIALIZE
    ================================================================ */

    loadSettings();

})();