/* ==========================================================================
   design-system.js — page module for app/design-system.html
   Renders color-token swatches and the demo table; binds demo toast buttons
   (no inline onclick — event listeners bound here instead).
   ========================================================================== */

   document.addEventListener("DOMContentLoaded", function () {
    // ---- Color token swatches ----
    const tokens = [
      ["--bg", "Background"], ["--sidebar", "Sidebar"], ["--card", "Card"], ["--border", "Border"],
      ["--primary", "Primary"], ["--success", "Success"], ["--warning", "Warning"], ["--danger", "Danger"], ["--info", "Info"],
      ["--sev-critical", "Sev. Critical"], ["--sev-high", "Sev. High"], ["--sev-medium", "Sev. Medium"], ["--sev-low", "Sev. Low"],
    ];
    const row = document.getElementById("colorSwatchRow");
    if (row) {
      row.innerHTML = tokens.map(([varName, label]) => `
        <div class="col-6 col-md-3 col-lg-2">
          <div class="swatch-block" style="background:var(${varName});"></div>
          <div class="text-sm swatch-label" style="color:var(--text)">${label}</div>
          <div class="text-xs text-muted font-mono">${varName}</div>
        </div>`).join("");
      // Note: the per-swatch background is intentionally set via CSS var reference
      // in a style attribute because the color itself is the data being displayed —
      // identical in spirit to setting a Chart.js dataset color from JS.
    }
  
    // ---- Demo table ----
    const demoData = [
      { name: "WEB-PROD-03", ip: "10.0.4.12", sev: "critical", status: "Open" },
      { name: "DB-PROD-01", ip: "10.0.2.5", sev: "high", status: "Investigating" },
      { name: "APP-STAGE-02", ip: "10.0.9.44", sev: "medium", status: "Resolved" },
      { name: "MAIL-EDGE-01", ip: "10.0.1.19", sev: "low", status: "Resolved" },
      { name: "VPN-GATE-02", ip: "10.0.0.2", sev: "high", status: "Open" },
    ];
    const tableEl = document.getElementById("dsTable");
    if (tableEl) {
      new XDRTable({
        tableEl,
        searchInput: document.getElementById("dsSearch"),
        paginationEl: document.getElementById("dsPagination"),
        data: demoData,
        pageSize: 5,
        searchKeys: ["name", "ip"],
        columns: [
          { key: "name", label: "Asset", sortable: true },
          { key: "ip", label: "IP Address", sortable: true, render: r => `<span class="cell-mono">${r.ip}</span>` },
          { key: "sev", label: "Severity", sortable: true, render: r => XDRUtils.severityBadge(r.sev) },
          { key: "status", label: "Status", sortable: true },
        ],
      });
    }
  
    // ---- Demo toast / modal triggers (event listeners, not inline onclick) ----
    document.getElementById("demoToastSuccess")?.addEventListener("click", () => {
      showToast({ type: "success", title: "Scan complete", msg: "0 critical findings on WEB-PROD-03" });
    });
    document.getElementById("demoToastDanger")?.addEventListener("click", () => {
      showToast({ type: "danger", title: "Agent offline", msg: "DB-PROD-01 stopped reporting 4m ago" });
    });
  });
  