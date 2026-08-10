/* ==========================================================================
   CyberDefense XDR
   Registration Page
   ========================================================================== */

document.addEventListener("DOMContentLoaded", function () {

    const form =
        document.getElementById("registerForm");

    if (!form) {
        return;
    }


    form.addEventListener("submit", async function (event) {

        event.preventDefault();


        // ==================================================================
        // INPUTS
        // ==================================================================

        const firstNameInput =
            document.getElementById("regFirst");

        const lastNameInput =
            document.getElementById("regLast");

        const emailInput =
            document.getElementById("regEmail");

        const companyInput =
            document.getElementById("regCompany");

        const passwordInput =
            document.getElementById("regPassword");

        const termsInput =
            document.getElementById("terms");

        const submitButton =
            form.querySelector(
                'button[type="submit"]'
            );


        const firstName =
            firstNameInput
                ? firstNameInput.value.trim()
                : "";


        const lastName =
            lastNameInput
                ? lastNameInput.value.trim()
                : "";


        const email =
            emailInput
                ? emailInput.value.trim()
                : "";


        const company =
            companyInput
                ? companyInput.value.trim()
                : "";


        const password =
            passwordInput
                ? passwordInput.value
                : "";


        const terms =
            termsInput
                ? termsInput.checked
                : false;


        // ==================================================================
        // CLIENT VALIDATION
        // ==================================================================

        if (!firstName) {

            showMessage(
                "warning",
                "Missing information",
                "First name is required."
            );

            return;
        }


        if (!lastName) {

            showMessage(
                "warning",
                "Missing information",
                "Last name is required."
            );

            return;
        }


        if (!email) {

            showMessage(
                "warning",
                "Missing information",
                "Work email is required."
            );

            return;
        }


        if (!password) {

            showMessage(
                "warning",
                "Missing information",
                "Password is required."
            );

            return;
        }


        if (password.length < 12) {

            showMessage(
                "warning",
                "Weak password",
                "Password must contain at least 12 characters."
            );

            return;
        }


        if (!terms) {

            showMessage(
                "warning",
                "Terms required",
                "You must accept the Terms of Service and Security Policy."
            );

            return;
        }


        // ==================================================================
        // BUTTON STATE
        // ==================================================================

        const originalButtonText =
            submitButton
                ? submitButton.innerHTML
                : "Request Access";


        if (submitButton) {

            submitButton.disabled = true;

            submitButton.innerHTML = `
                <span
                    class="spinner-border spinner-border-sm me-2"
                    role="status"
                    aria-hidden="true"
                ></span>
                Creating account...
            `;
        }


        // ==================================================================
        // REQUEST
        // ==================================================================

        try {

            const response = await fetch(
                "/auth/register",
                {
                    method: "POST",

                    headers: {
                        "Content-Type": "application/json",
                        "Accept": "application/json"
                    },

                    credentials: "same-origin",

                    body: JSON.stringify({

                        first_name: firstName,

                        last_name: lastName,

                        email: email,

                        company: company,

                        password: password,

                        terms: terms

                    })
                }
            );


            // --------------------------------------------------------------
            // RESPONSE
            // --------------------------------------------------------------

            let data = {};

            try {

                data = await response.json();

            } catch (jsonError) {

                console.error(
                    "Invalid JSON response:",
                    jsonError
                );

            }


            // --------------------------------------------------------------
            // SUCCESS
            // --------------------------------------------------------------

            if (
                response.ok &&
                data.success
            ) {

                showMessage(
                    "success",
                    "Account created",
                    data.message ||
                    "Your account has been created successfully."
                );


                setTimeout(function () {

                    window.location.href =
                        data.redirect ||
                        "/auth/login";

                }, 700);


                return;
            }


            // --------------------------------------------------------------
            // ERROR
            // --------------------------------------------------------------

            showMessage(
                "danger",
                "Registration failed",
                data.message ||
                "Unable to create the account."
            );


        } catch (error) {

            console.error(
                "Registration request failed:",
                error
            );


            showMessage(
                "danger",
                "Connection error",
                "Unable to connect to the authentication server."
            );


        } finally {

            if (submitButton) {

                submitButton.disabled = false;

                submitButton.innerHTML =
                    originalButtonText;

            }

        }

    });


    // ======================================================================
    // TOAST HELPER
    // ======================================================================

    function showMessage(
        type,
        title,
        message
    ) {

        if (typeof showToast === "function") {

            showToast({
                type: type,
                title: title,
                msg: message
            });

        } else {

            alert(
                title + ": " + message
            );

        }

    }

});