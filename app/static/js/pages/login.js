/* ==========================================================================
   login.js — page module for auth/login.html
   ========================================================================== */

   document.addEventListener("DOMContentLoaded", function () {
    const form = document.getElementById("loginForm");
    form?.addEventListener("submit", function (e) {
      e.preventDefault();
      showToast({ type: "info", title: "Frontend demo only", msg: "Authentication isn't wired up — head straight to the dashboard." });
      setTimeout(() => { window.location.href = "../app/dashboard.html"; }, 900);
    });
  });
  