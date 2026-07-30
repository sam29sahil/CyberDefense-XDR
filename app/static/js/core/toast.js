/* ==========================================================================
   toast.js — reusable toast notifications, top-right stack, auto-dismiss
   ========================================================================== */

   (function () {
    function ensureStack() {
      let stack = document.getElementById("xdrToastStack");
      if (!stack) {
        stack = document.createElement("div");
        stack.className = "xdr-toast-stack";
        stack.id = "xdrToastStack";
        document.body.appendChild(stack);
      }
      return stack;
    }
  
    const ICONS = {
      info: "bi-info-circle-fill",
      success: "bi-check-circle-fill",
      warning: "bi-exclamation-triangle-fill",
      danger: "bi-shield-exclamation",
    };
  
    window.showToast = function ({ type = "info", title = "", msg = "", duration = 5000 } = {}) {
      const stack = ensureStack();
      const el = document.createElement("div");
      el.className = `xdr-toast toast-${type} fade-in`;
      el.innerHTML = `
        <i class="bi ${ICONS[type] || ICONS.info}" style="color:var(--${type === 'danger' ? 'danger' : type === 'warning' ? 'warning' : type === 'success' ? 'success' : 'info'});"></i>
        <div style="flex:1;min-width:0;">
          <div style="font-weight:600;font-size:var(--fs-sm);">${title}</div>
          ${msg ? `<div style="font-size:var(--fs-xs);color:var(--text-muted);margin-top:2px;">${msg}</div>` : ""}
        </div>
        <button aria-label="Dismiss" style="background:none;border:0;color:var(--text-muted);cursor:pointer;flex:none;">
          <i class="bi bi-x-lg" style="font-size:.75rem;"></i>
        </button>`;
      el.querySelector("button").addEventListener("click", () => el.remove());
      stack.appendChild(el);
      if (duration) setTimeout(() => el.remove(), duration);
    };
  })();
  