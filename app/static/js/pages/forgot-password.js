document.addEventListener("DOMContentLoaded", function () {

    const form = document.getElementById("resetForm");

    if (!form) {
        return;
    }

    const emailInput = document.getElementById("resetEmail");
    const button = document.getElementById("resetButton");
    const buttonText = document.getElementById("resetButtonText");
    const buttonLoading = document.getElementById("resetButtonLoading");
    const messageBox = document.getElementById("messageBox");
    const resetLinkBox = document.getElementById("resetLinkBox");
    const resetLink = document.getElementById("resetLink");


    function showMessage(message, type) {

        if (!messageBox) {
            return;
        }

        messageBox.className =
            "alert alert-" + type + " text-start";

        messageBox.textContent = message;

        messageBox.classList.remove("d-none");
    }


    function setLoading(loading) {

        if (!button) {
            return;
        }

        button.disabled = loading;

        if (buttonText) {
            buttonText.classList.toggle(
                "d-none",
                loading
            );
        }

        if (buttonLoading) {
            buttonLoading.classList.toggle(
                "d-none",
                !loading
            );
        }
    }


    form.addEventListener("submit", async function (event) {

        event.preventDefault();


        const email =
            emailInput
                ? emailInput.value.trim().toLowerCase()
                : "";


        if (!email) {

            showMessage(
                "Please enter your work email address.",
                "warning"
            );

            return;
        }


        if (!email.includes("@")) {

            showMessage(
                "Please enter a valid email address.",
                "warning"
            );

            return;
        }


        setLoading(true);

        if (resetLinkBox) {
            resetLinkBox.classList.add("d-none");
        }


        try {

            const response = await fetch(
                "/auth/forgot-password",
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

                    body: JSON.stringify({
                        email: email
                    })
                }
            );


            const data =
                await response.json();


            if (!response.ok || !data.success) {

                showMessage(
                    data.message ||
                    "Unable to generate reset link.",
                    "danger"
                );

                return;
            }


            showMessage(
                data.message ||
                "Password reset link generated.",
                "success"
            );


            /*
             * Development mode:
             * The backend returns reset_url.
             *
             * In production this should be
             * replaced by an email delivery system.
             */

            if (
                data.reset_url &&
                resetLink &&
                resetLinkBox
            ) {

                resetLink.href =
                    data.reset_url;

                resetLink.textContent =
                    data.reset_url;

                resetLinkBox.classList.remove(
                    "d-none"
                );
            }


        } catch (error) {

            console.error(
                "Forgot password request failed:",
                error
            );


            showMessage(
                "Unable to connect to the authentication server.",
                "danger"
            );


        } finally {

            setLoading(false);

        }

    });

});