/* ==========================================================================
   register.js — page module for auth/register.html
   ========================================================================== */

   document.addEventListener("DOMContentLoaded", function () {
    const form = document.getElementById("registerForm");
    form?.addEventListener("submit", function (e) {
      e.preventDefault();
      showToast({ type: "success", title: "Request received", msg: "This is a frontend demo — no account was actually created." });
    });
  });
  