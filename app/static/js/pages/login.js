/*
==========================================================================
CyberDefense XDR
Login Page
==========================================================================
*/

document.addEventListener("DOMContentLoaded", function () {

    const form = document.getElementById("loginForm");

    if (!form) {
        return;
    }


    form.addEventListener("submit", async function (event) {

        event.preventDefault();


        // ================================================================
        // INPUTS
        // ================================================================

        const emailInput =
            document.getElementById("loginEmail");

        const passwordInput =
            document.getElementById("loginPassword");

        const rememberInput =
            document.getElementById("remember");

        const submitButton =
            form.querySelector('button[type="submit"]');


        const email =
            emailInput
                ? emailInput.value.trim()
                : "";

        const password =
            passwordInput
                ? passwordInput.value
                : "";

        const remember =
            rememberInput
                ? rememberInput.checked
                : false;


        // ================================================================
        // VALIDATION
        // ================================================================

        if (!email || !password) {

            if (typeof showToast === "function") {

                showToast({
                    type: "warning",
                    title: "Missing information",
                    msg: "Enter your email and password."
                });

            } else {

                alert(
                    "Enter your email and password."
                );

            }

            return;
        }


        // ================================================================
        // SAVE ORIGINAL BUTTON
        // ================================================================

        const originalText =
            submitButton
                ? submitButton.innerHTML
                : "Sign In";


        // ================================================================
        // LOADING STATE
        // ================================================================

        if (submitButton) {

            submitButton.disabled = true;

            submitButton.innerHTML = `
                <span
                    class="spinner-border spinner-border-sm me-2"
                    role="status"
                    aria-hidden="true"
                ></span>
                Signing in...
            `;
        }


        try {

            // ============================================================
            // LOGIN REQUEST
            // ============================================================

            const response = await fetch(
                "/auth/login",
                {
                    method: "POST",

                    headers: {
                        "Content-Type": "application/json",
                        "Accept": "application/json"
                    },

                    credentials: "same-origin",

                    body: JSON.stringify({
                        email: email,
                        password: password,
                        remember: remember
                    })
                }
            );


            // ============================================================
            // READ RESPONSE
            // ============================================================

            const data =
                await response.json();


            // ============================================================
            // SUCCESS
            // ============================================================

            if (response.ok && data.success) {

                if (typeof showToast === "function") {

                    showToast({
                        type: "success",
                        title: "Welcome back",
                        msg:
                            data.message ||
                            "Login successful."
                    });

                }


                // Flask returns /dashboard/
                window.location.href =
                    data.redirect ||
                    "/dashboard/";

                return;
            }


            // ============================================================
            // AUTHENTICATION ERROR
            // ============================================================

            if (typeof showToast === "function") {

                showToast({
                    type: "danger",
                    title: "Sign in failed",
                    msg:
                        data.message ||
                        "Invalid email or password."
                });

            } else {

                alert(
                    data.message ||
                    "Invalid email or password."
                );
            }


        } catch (error) {

            console.error(
                "Login request failed:",
                error
            );


            if (typeof showToast === "function") {

                showToast({
                    type: "danger",
                    title: "Connection error",
                    msg:
                        "Unable to connect to the authentication server."
                });

            } else {

                alert(
                    "Unable to connect to the authentication server."
                );
            }


        } finally {

            // Don't restore the button if the page is
            // already navigating to the dashboard.

            if (
                submitButton &&
                document.visibilityState !== "hidden"
            ) {

                submitButton.disabled = false;

                submitButton.innerHTML =
                    originalText;
            }
        }

    });

});