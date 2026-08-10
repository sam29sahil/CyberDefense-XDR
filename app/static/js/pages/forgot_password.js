/*
CyberDefense XDR
Forgot Password Page
*/

document.addEventListener("DOMContentLoaded", function () {

    const form = document.getElementById("resetForm");

    const emailInput =
        document.getElementById("resetEmail");

    const messageBox =
        document.getElementById("messageBox");

    const resetButton =
        document.getElementById("resetButton");

    const buttonText =
        document.getElementById("resetButtonText");

    const buttonLoading =
        document.getElementById("resetButtonLoading");

    const resetLinkBox =
        document.getElementById("resetLinkBox");

    const resetLink =
        document.getElementById("resetLink");


    if (!form) {
        return;
    }


    form.addEventListener("submit", async function (event) {

        event.preventDefault();


        const email =
            emailInput.value.trim().toLowerCase();


        /*
        Client validation
        */

        if (!email) {

            showMessage(
                "danger",
                "Email address is required."
            );

            return;
        }


        /*
        Email validation
        */

        if (!emailInput.checkValidity()) {

            showMessage(
                "danger",
                "Enter a valid email address."
            );

            return;
        }


        /*
        Loading state
        */

        resetButton.disabled = true;

        buttonText.classList.add("d-none");

        buttonLoading.classList.remove("d-none");


        resetLinkBox.classList.add("d-none");


        try {

            const response = await fetch(
                "{{ url_for('auth.forgot_password') }}",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json",

                        "Accept":
                            "application/json"
                    },

                    credentials: "same-origin",

                    body: JSON.stringify({
                        email: email
                    })
                }
            );


            const data =
                await response.json();


            /*
            Error
            */

            if (!response.ok || !data.success) {

                showMessage(
                    "danger",
                    data.message ||
                    "Unable to generate reset link."
                );

                return;
            }


            /*
            Success
            */

            showMessage(
                "success",
                data.message ||
                "Password reset link generated."
            );


            /*
            Development reset URL
            */

            if (data.reset_url) {

                resetLink.href =
                    data.reset_url;

                resetLink.textContent =
                    data.reset_url;

                resetLinkBox.classList.remove(
                    "d-none"
                );
            }


            if (typeof showToast === "function") {

                showToast({
                    type: "success",
                    title: "Reset link generated",
                    msg:
                        "Your password reset link is ready."
                });

            }


        } catch (error) {

            console.error(
                "Forgot password request failed:",
                error
            );


            showMessage(
                "danger",
                "Unable to connect to the authentication server."
            );

        } finally {

            resetButton.disabled = false;

            buttonText.classList.remove(
                "d-none"
            );

            buttonLoading.classList.add(
                "d-none"
            );

        }

    });


    function showMessage(type, message) {

        messageBox.className =
            "alert alert-" +
            type +
            " text-start";

        messageBox.textContent =
            message;

        messageBox.classList.remove(
            "d-none"
        );

    }

});