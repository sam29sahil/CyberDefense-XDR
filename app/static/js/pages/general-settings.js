/* ==========================================================================
   general-settings.js — page module for app/general-settings.html
   ========================================================================== */

   (function () {
    document.getElementById("uploadLogoBtn").addEventListener("click", () => {
      if (window.showToast) window.showToast({ type: "info", title: "Upload disabled in preview", msg: "This is a static frontend demo — file upload isn't wired to a backend yet." });
    });
    document.getElementById("saveBtn").addEventListener("click", () => {
      if (window.showToast) window.showToast({ type: "success", title: "Settings saved", msg: "General preferences updated." });
    });
  })();
  