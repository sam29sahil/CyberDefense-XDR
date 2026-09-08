/**
 * asset_details.js — Asset Details Controller for CyberDefense XDR
 * Integrates real database records, correlated scanner findings, Alert Center alerts,
 * network IDS events, and SIEM activity logs.
 */

(function () {
  "use strict";

  const assetId = window.ASSET_ID || extractAssetIdFromPath();
  if (!assetId) {
    console.error("No asset ID found for asset details page.");
    return;
  }

  const TYPE_ICONS = {
    "Server": "bi-hdd-rack",
    "Database": "bi-database",
    "Workstation": "bi-pc-display",
    "Firewall": "bi-bricks",
    "Router": "bi-router",
    "Switch": "bi-hdd-network",
    "Cloud Instance": "bi-cloud",
    "Domain Controller": "bi-diagram-2",
    "Mail Gateway": "bi-envelope",
    "Container Host": "bi-boxes",
    "Load Balancer": "bi-signpost-split",
    "Other": "bi-hdd-network"
  };

  document.addEventListener("DOMContentLoaded", () => {
    loadAssetData();
    loadVulnerabilities();
    loadAlerts();
    loadNetworkData();
    loadActivityData();
    initActionButtons();
  });

  function extractAssetIdFromPath() {
    const parts = window.location.pathname.split("/").filter(Boolean);
    const lastPart = parts[parts.length - 1];
    if (lastPart && lastPart.startsWith("AST-")) {
      return lastPart;
    }
    const params = new URLSearchParams(window.location.search);
    return params.get("id");
  }

  function escapeHtml(str) {
    if (!str && str !== 0) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function formatDateTime(isoString) {
    if (!isoString) return "-";
    try {
      const d = new Date(isoString);
      return isNaN(d.getTime()) ? isoString : d.toISOString().replace("T", " ").substring(0, 19) + " UTC";
    } catch {
      return isoString;
    }
  }

  function getSeverityBadge(sev) {
    const s = (sev || "low").toLowerCase();
    if (s === "critical") return `<span class="badge bg-danger text-white text-uppercase fw-semibold">Critical</span>`;
    if (s === "high") return `<span class="badge bg-danger-subtle text-danger text-uppercase fw-semibold">High</span>`;
    if (s === "medium") return `<span class="badge bg-warning-subtle text-warning text-uppercase fw-semibold">Medium</span>`;
    return `<span class="badge bg-success-subtle text-success text-uppercase fw-semibold">Low</span>`;
  }

  /* ----------------------------------------------------
   * Load Asset Details & Dynamic Profile
   * ---------------------------------------------------- */
  async function loadAssetData() {
    try {
      const res = await fetch(`/assets/api/${encodeURIComponent(assetId)}`);
      if (!res.ok) throw new Error(`Asset not found (${res.status})`);
      const asset = await res.json();

      // Update stat cards dynamically
      const riskEl = document.getElementById("statRiskScore");
      if (riskEl) riskEl.textContent = `${asset.risk_score} / 100`;

      const riskSevEl = document.getElementById("statRiskSev");
      if (riskSevEl) {
        riskSevEl.textContent = asset.risk_severity;
        riskSevEl.className = `text-uppercase fw-semibold ${
          asset.risk_severity === 'critical' || asset.risk_severity === 'high' ? 'text-danger' :
          asset.risk_severity === 'medium' ? 'text-warning' : 'text-success'
        }`;
      }

      const iconEl = document.getElementById("assetTypeIcon");
      if (iconEl) {
        const iconClass = TYPE_ICONS[asset.asset_type] || "bi-hdd-network";
        iconEl.innerHTML = `<i class="bi ${iconClass}"></i>`;
      }
    } catch (err) {
      console.warn("Could not refresh live asset details:", err);
    }
  }

  /* ----------------------------------------------------
   * Load Correlated Vulnerabilities
   * ---------------------------------------------------- */
  async function loadVulnerabilities() {
    const tbody = document.getElementById("vulnsTableBody");
    if (!tbody) return;

    try {
      const res = await fetch(`/assets/api/${encodeURIComponent(assetId)}/vulnerabilities`);
      if (!res.ok) throw new Error("Failed to load vulnerabilities");
      const data = await res.json();
      const vulns = data.vulnerabilities || [];

      // Update counter badges
      const countEl = document.getElementById("statVulnsCount");
      if (countEl) countEl.textContent = vulns.length;
      const tabBadge = document.getElementById("tabVulnsBadge");
      if (tabBadge) tabBadge.textContent = vulns.length;

      if (vulns.length === 0) {
        tbody.innerHTML = `
          <tr>
            <td colspan="7" class="text-center text-muted py-4">
              <i class="bi bi-shield-check text-success fs-3 d-block mb-2"></i>
              No open vulnerability findings correlated with this asset.
            </td>
          </tr>`;
        return;
      }

      tbody.innerHTML = vulns.map(v => `
        <tr>
          <td>${getSeverityBadge(v.severity)}</td>
          <td>
            <div class="fw-semibold text-light">${escapeHtml(v.title || v.cve_id || 'Untitled Finding')}</div>
            ${v.cve_id ? `<span class="badge bg-secondary-subtle text-muted cell-mono">${escapeHtml(v.cve_id)}</span>` : ''}
          </td>
          <td class="cell-mono fw-semibold ${v.cvss_score >= 7.0 ? 'text-danger' : v.cvss_score >= 4.0 ? 'text-warning' : 'text-info'}">
            ${v.cvss_score != null ? v.cvss_score.toFixed(1) : '-'}
          </td>
          <td><span class="badge bg-secondary-subtle text-light">${escapeHtml(v.category || 'General')}</span></td>
          <td class="cell-mono small text-info">${escapeHtml(v.host || '-')}</td>
          <td class="cell-mono small">${v.port ? `${v.port}/${escapeHtml(v.protocol || 'tcp')}` : '-'}</td>
          <td><span class="badge bg-secondary-subtle text-capitalize">${escapeHtml(v.status || 'open')}</span></td>
        </tr>
      `).join("");
    } catch (err) {
      console.error(err);
      tbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger py-3">Error loading vulnerabilities: ${escapeHtml(err.message)}</td></tr>`;
    }
  }

  /* ----------------------------------------------------
   * Load Correlated Alerts
   * ---------------------------------------------------- */
  async function loadAlerts() {
    const tbody = document.getElementById("alertsTableBody");
    if (!tbody) return;

    try {
      const res = await fetch(`/assets/api/${encodeURIComponent(assetId)}/alerts`);
      if (!res.ok) throw new Error("Failed to load alerts");
      const data = await res.json();
      const alerts = data.alerts || [];

      // Update counter badges
      const countEl = document.getElementById("statAlertsCount");
      if (countEl) countEl.textContent = alerts.length;
      const tabBadge = document.getElementById("tabAlertsBadge");
      if (tabBadge) tabBadge.textContent = alerts.length;

      if (alerts.length === 0) {
        tbody.innerHTML = `
          <tr>
            <td colspan="6" class="text-center text-muted py-4">
              <i class="bi bi-bell-slash text-muted fs-3 d-block mb-2"></i>
              No active security alerts linked to this host or IP.
            </td>
          </tr>`;
        return;
      }

      tbody.innerHTML = alerts.map(a => `
        <tr>
          <td>${getSeverityBadge(a.severity)}</td>
          <td>
            <div class="fw-semibold text-light">${escapeHtml(a.title || 'Security Alert')}</div>
            <div class="small text-muted cell-mono">${escapeHtml(a.alert_id || '')}</div>
          </td>
          <td><span class="badge bg-secondary-subtle text-light">${escapeHtml(a.category || 'Threat')}</span></td>
          <td><span class="badge bg-info-subtle text-info">${escapeHtml(a.source || 'Detection')}</span></td>
          <td><span class="badge bg-secondary-subtle text-capitalize">${escapeHtml(a.status || 'new')}</span></td>
          <td class="small text-muted cell-mono">${formatDateTime(a.created_at)}</td>
        </tr>
      `).join("");
    } catch (err) {
      console.error(err);
      tbody.innerHTML = `<tr><td colspan="6" class="text-center text-danger py-3">Error loading alerts: ${escapeHtml(err.message)}</td></tr>`;
    }
  }

  /* ----------------------------------------------------
   * Load Network Ports & IDS Events
   * ---------------------------------------------------- */
  async function loadNetworkData() {
    const portsBody = document.getElementById("networkPortsBody");
    const idsBody = document.getElementById("idsEventsBody");

    try {
      const res = await fetch(`/assets/api/${encodeURIComponent(assetId)}/network`);
      if (!res.ok) throw new Error("Failed to load network data");
      const data = await res.json();

      // Render ports
      if (portsBody) {
        const ports = data.discovered_ports || [];
        if (ports.length === 0) {
          portsBody.innerHTML = `<tr><td colspan="3" class="text-center text-muted py-3">No open port observations recorded yet. Run a Vulnerability Scan to discover open ports.</td></tr>`;
        } else {
          portsBody.innerHTML = ports.map(p => `
            <tr>
              <td class="text-info fw-bold">${escapeHtml(p.port)}</td>
              <td><span class="badge bg-secondary-subtle text-light">${escapeHtml(p.proto || 'tcp')}</span></td>
              <td>${escapeHtml(p.service || 'unknown')}</td>
            </tr>
          `).join("");
        }
      }

      // Render IDS events
      if (idsBody) {
        const events = data.ids_events || [];
        if (events.length === 0) {
          idsBody.innerHTML = `<tr><td colspan="4" class="text-center text-muted py-3">No IDS traffic signatures captured for this host IP.</td></tr>`;
        } else {
          idsBody.innerHTML = events.map(e => `
            <tr>
              <td>${getSeverityBadge(e.severity || 'low')}</td>
              <td class="fw-semibold text-light">${escapeHtml(e.signature || 'IDS Event')}</td>
              <td><span class="badge bg-secondary-subtle text-muted">${escapeHtml(e.category || 'Traffic')}</span></td>
              <td class="cell-mono text-muted">${formatDateTime(e.timestamp)}</td>
            </tr>
          `).join("");
        }
      }
    } catch (err) {
      console.error(err);
      if (portsBody) portsBody.innerHTML = `<tr><td colspan="3" class="text-center text-danger py-2">Error loading ports</td></tr>`;
      if (idsBody) idsBody.innerHTML = `<tr><td colspan="4" class="text-center text-danger py-2">Error loading IDS events</td></tr>`;
    }
  }

  /* ----------------------------------------------------
   * Load Activity & Incidents
   * ---------------------------------------------------- */
  async function loadActivityData() {
    const incBody = document.getElementById("incidentsBody");
    const siemBody = document.getElementById("siemEventsBody");

    try {
      const res = await fetch(`/assets/api/${encodeURIComponent(assetId)}/activity`);
      if (!res.ok) throw new Error("Failed to load activity");
      const data = await res.json();

      // Render incidents
      if (incBody) {
        const incidents = data.incidents || [];
        if (incidents.length === 0) {
          incBody.innerHTML = `<tr><td colspan="4" class="text-center text-muted py-3">No formal incidents escalated for this asset.</td></tr>`;
        } else {
          incBody.innerHTML = incidents.map(i => `
            <tr>
              <td>${getSeverityBadge(i.severity)}</td>
              <td>
                <a href="/incidents/${encodeURIComponent(i.incident_id)}" class="fw-semibold text-primary">
                  ${escapeHtml(i.title || i.incident_id)}
                </a>
              </td>
              <td><span class="badge bg-secondary-subtle">${escapeHtml(i.status || 'open')}</span></td>
              <td class="cell-mono text-muted">${formatDateTime(i.created_at)}</td>
            </tr>
          `).join("");
        }
      }

      // Render SIEM events
      if (siemBody) {
        const siemEvents = data.siem_events || [];
        if (siemEvents.length === 0) {
          siemBody.innerHTML = `<tr><td colspan="3" class="text-center text-muted py-3">No SIEM logs recorded for this host.</td></tr>`;
        } else {
          siemBody.innerHTML = siemEvents.map(s => `
            <tr>
              <td><span class="badge bg-secondary-subtle text-light">${escapeHtml(s.source || 'SIEM')}</span></td>
              <td class="text-break">${escapeHtml(s.message || '-')}</td>
              <td class="text-muted text-nowrap">${formatDateTime(s.timestamp)}</td>
            </tr>
          `).join("");
        }
      }
    } catch (err) {
      console.error(err);
      if (incBody) incBody.innerHTML = `<tr><td colspan="4" class="text-center text-danger py-2">Error loading incidents</td></tr>`;
      if (siemBody) siemBody.innerHTML = `<tr><td colspan="3" class="text-center text-danger py-2">Error loading SIEM logs</td></tr>`;
    }
  }

  /* ----------------------------------------------------
   * Action Buttons: Scan Now & Delete Asset
   * ---------------------------------------------------- */
  function initActionButtons() {
    const scanBtn = document.getElementById("btnScanNow");
    if (scanBtn) {
      scanBtn.addEventListener("click", async () => {
        if (!confirm(`Trigger an authorized Vulnerability Scan for asset ${assetId}?`)) {
          return;
        }

        scanBtn.disabled = true;
        const originalText = scanBtn.innerHTML;
        scanBtn.innerHTML = `<span class="spinner-border spinner-border-sm me-1" role="status"></span>Scanning...`;

        try {
          const res = await fetch(`/assets/api/${encodeURIComponent(assetId)}/scan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" }
          });
          const result = await res.json();

          if (!res.ok) {
            throw new Error(result.error || "Failed to trigger scan");
          }

          alert(`Scan initiated successfully! Scan ID: ${result.scan_id || 'Active'}\nCheck the Vulnerability Scanner module to view real-time execution.`);
          loadAssetData();
          loadVulnerabilities();
          loadNetworkData();
        } catch (err) {
          alert(`Error initiating scan: ${err.message}`);
        } finally {
          scanBtn.disabled = false;
          scanBtn.innerHTML = originalText;
        }
      });
    }

    const deleteBtn = document.getElementById("btnDeleteAsset");
    if (deleteBtn) {
      deleteBtn.addEventListener("click", async () => {
        if (!confirm(`Are you sure you want to permanently delete asset ${assetId}? This action cannot be undone.`)) {
          return;
        }

        deleteBtn.disabled = true;
        try {
          const res = await fetch(`/assets/api/${encodeURIComponent(assetId)}`, {
            method: "DELETE"
          });
          const result = await res.json();
          if (!res.ok) {
            throw new Error(result.error || "Failed to delete asset");
          }

          alert("Asset deleted successfully.");
          window.location.href = "/assets/";
        } catch (err) {
          alert(`Error deleting asset: ${err.message}`);
          deleteBtn.disabled = false;
        }
      });
    }
  }

})();