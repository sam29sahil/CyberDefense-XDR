/* ==========================================================================
   app.js — shared utility functions used across page-level modules.
   Load this before any assets/js/pages/*.js file.
   ========================================================================== */

   const XDRUtils = {
    /** Debounce a function call — used by search inputs across the app. */
    debounce(fn, wait = 250) {
      let t;
      return (...args) => {
        clearTimeout(t);
        t = setTimeout(() => fn.apply(this, args), wait);
      };
    },
  
    /** Escape a string for safe HTML interpolation in dynamically rendered rows. */
    escapeHtml(str) {
      const div = document.createElement("div");
      div.textContent = String(str ?? "");
      return div.innerHTML;
    },
  
    /** Format an ISO date into a short relative-ish label. */
    formatTime(isoString) {
      const d = new Date(isoString);
      if (isNaN(d)) return isoString;
      return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
    },
  
    /** Read a CSS custom property value from :root. */
    cssVar(name) {
      return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    },
  
    /** Severity metadata used everywhere a severity badge/dot/icon is rendered. */
    severity: {
      critical: { label: "Critical", icon: "bi-skull" },
      high: { label: "High", icon: "bi-exclamation-triangle-fill" },
      medium: { label: "Medium", icon: "bi-dash-circle-fill" },
      low: { label: "Low", icon: "bi-arrow-down-circle-fill" },
      info: { label: "Info", icon: "bi-info-circle-fill" },
    },
  
    /** Render a severity badge's inner HTML for a given severity key. */
    severityBadge(sevKey) {
      const meta = this.severity[sevKey] || this.severity.info;
      return `<span class="badge badge-sev-${sevKey}"><i class="bi ${meta.icon}"></i> ${meta.label}</span>`;
    },
  };
  