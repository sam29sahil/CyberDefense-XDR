/* ==========================================================================
   shell.js — renders the sidebar + navbar into every app page from one
   config, so navigation and active-state are identical everywhere.
   Each page sets `window.XDR_ACTIVE = "dashboard"` before this loads.
   ========================================================================== */

   (function () {
    const NAV = [
      { section: "Overview", items: [
        { key: "dashboard", label: "Dashboard", icon: "bi-speedometer2", href: "dashboard.html" },
      ]},
      { section: "Assets", items: [
        { key: "assets", label: "Asset Management", icon: "bi-hdd-network", href: "assets.html" },
      ]},
      { section: "SIEM", items: [
        { key: "siem", label: "SIEM Dashboard", icon: "bi-bar-chart-steps", href: "siem.html" },
        { key: "log-explorer", label: "Log Explorer", icon: "bi-terminal", href: "log-explorer.html" },
      ]},
      { section: "Detection", items: [
        { key: "detection-engine", label: "Detection Engine", icon: "bi-cpu", href: "detection-engine.html" },
        { key: "alert-center", label: "Alert Center", icon: "bi-bell", href: "alert-center.html", badge: "12" },
      ]},
      { section: "SOC", items: [
        { key: "soc-dashboard", label: "SOC Dashboard", icon: "bi-shield-check", href: "soc-dashboard.html" },
        { key: "incident-response", label: "Incident Response", icon: "bi-clipboard2-pulse", href: "incident-response.html" },
      ]},
      { section: "Scanner", items: [
        { key: "vuln-scanner", label: "Vulnerability Scanner", icon: "bi-search", href: "vuln-scanner.html" },
        { key: "scan-history", label: "Scan History", icon: "bi-clock-history", href: "scan-history.html" },
      ]},
      { section: "Threat Intel", items: [
        { key: "threat-intel", label: "Threat Intelligence", icon: "bi-globe2", href: "threat-intel.html" },
        { key: "ioc-database", label: "IOC Database", icon: "bi-database", href: "ioc-database.html" },
      ]},
      { section: "IDS", items: [
        { key: "network-ids", label: "Network IDS", icon: "bi-diagram-3", href: "network-ids.html" },
        { key: "packet-analysis", label: "Packet Analysis", icon: "bi-activity", href: "packet-analysis.html" },
      ]},
      { section: "Insights", items: [
        { key: "reports", label: "Reports", icon: "bi-file-earmark-text", href: "reports.html" },
        { key: "ai-assistant", label: "AI Assistant", icon: "bi-stars", href: "ai-assistant.html" },
        { key: "analytics", label: "Analytics", icon: "bi-graph-up-arrow", href: "analytics.html" },
      ]},
      { section: "Administration", items: [
        { key: "user-management", label: "User Management", icon: "bi-people", href: "user-management.html" },
        { key: "audit-logs", label: "Audit Logs", icon: "bi-journal-text", href: "audit-logs.html" },
        { key: "settings", label: "Settings", icon: "bi-gear", href: "/settings/profile" },
      ]},
    ];
  
    function renderSidebar(active) {
      const sections = NAV.map(sec => `
        <div class="nav-section">
          <div class="nav-section-label">${sec.section}</div>
          ${sec.items.map(it => `
            <a href="${it.href}" class="nav-item ${it.key === active ? 'active' : ''}">
              <i class="bi ${it.icon}"></i>
              <span class="nav-label">${it.label}</span>
              ${it.badge ? `<span class="badge badge-danger nav-badge">${it.badge}</span>` : ''}
              <span class="tooltip-label">${it.label}</span>
            </a>`).join('')}
        </div>`).join('');
  
      return `
        <aside class="xdr-sidebar" id="xdrSidebar">
          <div class="sidebar-brand">
            <div class="brand-mark"><i class="bi bi-shield-lock-fill"></i></div>
            <span class="brand-text">CyberDefense <span style="color:var(--info)">XDR</span></span>
          </div>
          <nav class="sidebar-nav">${sections}</nav>
          <div class="sidebar-footer">
            <a href="/auth/logout" class="nav-item">
              <i class="bi bi-box-arrow-left"></i>
              <span class="nav-label">Logout</span>
              <span class="tooltip-label">Logout</span>
            </a>
          </div>
        </aside>
        <div class="sidebar-scrim" id="sidebarScrim"></div>`;
    }
  
    function renderNavbar(pageTitle) {
      return `
        <header class="xdr-navbar glass">
          <button class="sidebar-toggle-btn" id="sidebarToggle" aria-label="Toggle sidebar">
            <i class="bi bi-list"></i>
          </button>
          <div class="navbar-search">
            <i class="bi bi-search search-icon"></i>
            <input type="text" placeholder="Search assets, alerts, IOCs, CVEs…" id="globalSearchInput">
            <span class="kbd-hint"><span class="kbd">⌘K</span></span>
          </div>
          <div class="navbar-actions">
            <button class="navbar-icon-btn" id="themeToggle" aria-label="Toggle theme">
              <i class="bi bi-moon-stars"></i>
            </button>
            <div style="position:relative;">
              <button class="navbar-icon-btn" id="notifBtn" aria-label="Notifications">
                <i class="bi bi-bell"></i><span class="badge-dot"></span>
              </button>
            </div>
            <button class="navbar-icon-btn" aria-label="Messages">
              <i class="bi bi-chat-dots"></i>
            </button>
            <div style="width:1px;height:24px;background:var(--border);margin:0 4px;"></div>
            <div class="navbar-profile" id="profileMenuBtn">
              <div class="avatar">AR</div>
              <div class="profile-meta">
                <span class="profile-name">Aria Reyes</span>
                <span class="profile-role">SOC Analyst · Tier 2</span>
              </div>
              <i class="bi bi-chevron-down text-muted" style="font-size:11px;"></i>
            </div>
          </div>
        </header>`;
    }
  
    function init() {
      const body = document.body;
      const active = body.dataset.page || "";
      const title = body.dataset.title || "";
      const sidebarRoot = document.getElementById("sidebar-root");
      const navbarRoot = document.getElementById("navbar-root");
      if (sidebarRoot) sidebarRoot.outerHTML = renderSidebar(active);
      if (navbarRoot) navbarRoot.outerHTML = renderNavbar(title);
  
      // Sidebar collapse (desktop) / drawer (mobile)
      const sidebar = document.getElementById("xdrSidebar");
      const scrim = document.getElementById("sidebarScrim");
      const toggle = document.getElementById("sidebarToggle");
      const isMobile = () => window.innerWidth <= 992;
  
      const collapsedSaved = localStorage.getItem("xdr_sidebar_collapsed") === "1";
      if (collapsedSaved && !isMobile()) {
        sidebar.classList.add("collapsed");
        document.body.classList.add("sidebar-collapsed");
      }
  
      toggle?.addEventListener("click", () => {
        if (isMobile()) {
          sidebar.classList.toggle("mobile-open");
          scrim.classList.toggle("show");
        } else {
          sidebar.classList.toggle("collapsed");
          document.body.classList.toggle("sidebar-collapsed");
          localStorage.setItem("xdr_sidebar_collapsed", sidebar.classList.contains("collapsed") ? "1" : "0");
        }
      });
      scrim?.addEventListener("click", () => {
        sidebar.classList.remove("mobile-open");
        scrim.classList.remove("show");
      });
  
      // Keyboard shortcut for search
      document.addEventListener("keydown", (e) => {
        if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
          e.preventDefault();
          document.getElementById("globalSearchInput")?.focus();
        }
      });
  
      // Theme toggle (visual affordance — product is dark-first by design)
      document.getElementById("themeToggle")?.addEventListener("click", function () {
        document.body.classList.toggle("theme-light-preview");
        const icon = this.querySelector("i");
        icon.classList.toggle("bi-moon-stars");
        icon.classList.toggle("bi-sun");
        if (window.showToast) {
          window.showToast({ type: "info", title: "Theme preference saved", msg: "Interface will use this on next load." });
        }
      });
    }
  
    document.addEventListener("DOMContentLoaded", init);
  })();
  