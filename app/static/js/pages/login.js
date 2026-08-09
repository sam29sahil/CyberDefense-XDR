/*
 * CyberDefense XDR
 * Login
 */

document.addEventListener("DOMContentLoaded", function () {

    const form = document.getElementById("loginForm");

    if (!form) {
        return;
    }

    form.addEventListener("submit", async function (event) {

        event.preventDefault();

        const email =
            document.getElementById("loginEmail")?.value.trim();

        const password =
            document.getElementById("loginPassword")?.value;

        const remember =
            document.getElementById("remember")?.checked || false;

        if (!email || !password) {

            showToast({
                type: "error",
                title: "Login failed",
                msg: "Enter your work email and password."
            });

            return;
        }

        try {

            const response = await fetch("/auth/login", {
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
            });

            const data = await response.json();

            if (!response.ok) {

                showToast({
                    type: "error",
                    title: "Login failed",
                    msg: data.message || "Invalid email or password."
                });

                return;
            }

            showToast({
                type: "success",
                title: "Welcome back",
                msg: data.message || "Login successful."
            });

            setTimeout(function () {

                window.location.href =
                    data.redirect || "/";

            }, 500);

        } catch (error) {

            console.error("Login error:", error);

            showToast({
                type: "error",
                title: "Connection error",
                msg: "Unable to connect to CyberDefense XDR."
            });
        }
    });
});