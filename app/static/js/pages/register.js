/*
 * CyberDefense XDR
 * Registration
 */

document.addEventListener("DOMContentLoaded", function () {

    const form = document.getElementById("registerForm");

    if (!form) {
        return;
    }

    form.addEventListener("submit", async function (event) {

        event.preventDefault();

        const firstName =
            document.getElementById("regFirst")?.value.trim();

        const lastName =
            document.getElementById("regLast")?.value.trim();

        const email =
            document.getElementById("regEmail")?.value.trim();

        const company =
            document.getElementById("regCompany")?.value.trim();

        const password =
            document.getElementById("regPassword")?.value;

        const terms =
            document.getElementById("terms")?.checked || false;

        if (!firstName || !lastName || !email || !password) {

            showToast({
                type: "error",
                title: "Registration failed",
                msg: "Please complete all required fields."
            });

            return;
        }

        if (password.length < 12) {

            showToast({
                type: "error",
                title: "Registration failed",
                msg: "Password must contain at least 12 characters."
            });

            return;
        }

        if (!terms) {

            showToast({
                type: "error",
                title: "Terms required",
                msg: "Please accept the Terms of Service and Security Policy."
            });

            return;
        }

        try {

            const response = await fetch("/auth/register", {
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
            });

            const data = await response.json();

            if (!response.ok) {

                showToast({
                    type: "error",
                    title: "Registration failed",
                    msg: data.message || "Unable to create account."
                });

                return;
            }

            showToast({
                type: "success",
                title: "Account created",
                msg: data.message || "Registration successful."
            });

            setTimeout(function () {

                window.location.href =
                    data.redirect || "/auth/login";

            }, 700);

        } catch (error) {

            console.error(
                "Registration error:",
                error
            );

            showToast({
                type: "error",
                title: "Connection error",
                msg: "Unable to connect to CyberDefense XDR."
            });
        }
    });
});