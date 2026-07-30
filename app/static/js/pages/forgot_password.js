/* ==========================================================================
   forgot-password.js — page module for auth/forgot-password.html
   ========================================================================== */

   document.addEventListener("DOMContentLoaded", function () {
    const form = document.getElementById("resetForm");
    const card = document.getElementById("authCard");
  
    form?.addEventListener("submit", function (e) {
      e.preventDefault();
      if (!card) return;
      card.innerHTML = `
        <div class="auth-icon-circle success"><i class="bi bi-envelope-check"></i></div>
        <h1 class="reset-confirm-heading">Check your inbox</h1>
        <p class="text-muted mb-4">If an account exists for that email, a reset link is on its way.</p>
        <a href="login.html" class="btn btn-secondary w-100">Back to sign in</a>`;
    });
  });
  