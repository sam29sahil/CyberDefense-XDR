/* ==========================================================================
   network-ids.js — Network IDS (Suricata) Dashboard Controller
   ========================================================================== */

(function () {
  "use strict";

  let protocolChartInstance = null;
  let isPolling = false;
  let pollTimer = null;

  function escapeHtml(val) {
    if (val === null || val === undefined) return "";
    return String(val)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function showToast(type, title, msg) {
    if (window.showToast) {
      window.showToast({ type, title, msg });
    }
  }

  // Update sensor control buttons and badge based on sensor state
  function updateSensorState(sensor) {
    const statusPill = document.getElementById("sensorStatusPill");
    const versionBadge = document.getElementById("versionBadge");
    const pidEl = document.getElementById("sensorPid");
    const lastSeenEl = document.getElementById("sensorLastSeen");
    const rulesCountEl = document.getElementById("rulesCount");
    const ifaceEl = document.getElementById("sensorInterface");
    const subtextEl = document.getElementById("sensorSubtext");

    const btnStart = document.getElementById("btnStartSensor");
    const btnStop = document.getElementById("btnStopSensor");
    const btnRestart = document.getElementById("btnRestartSensor");

    if (!sensor) return;

    if (ifaceEl && sensor.interface) ifaceEl.textContent = sensor.interface;
    if (versionBadge && sensor.suricata_version) versionBadge.textContent = sensor.suricata_version;
    if (rulesCountEl && sensor.active_rules_count !== undefined) {
      rulesCountEl.textContent = Number(sensor.active_rules_count).toLocaleString();
    }

    if (sensor.pid) {
      if (pidEl) pidEl.textContent = sensor.pid;
    } else {
      if (pidEl) pidEl.textContent = "—";
    }

    if (statusPill) {
      statusPill.className = "status-pill";
      if (sensor.status === "running") {
        statusPill.classList.add("st-running");
        statusPill.innerHTML = `<span class="dot"></span>ONLINE`;
        if (subtextEl) subtextEl.textContent = `Suricata PID ${sensor.pid || "Active"} actively inspecting interface ${sensor.interface || "eth0"}`;
        if (lastSeenEl) lastSeenEl.textContent = `Started: ${sensor.started_at ? new Date(sensor.started_at).toLocaleTimeString() : "active"}`;
        if (btnStart) btnStart.disabled = true;
        if (btnStop) btnStop.disabled = false;
        if (btnRestart) btnRestart.disabled = false;
      } else {
        statusPill.classList.add("st-stopped");
        statusPill.innerHTML = `<span class="dot"></span>STOPPED`;
        if (subtextEl) subtextEl.textContent = "Sensor engine offline. Click 'Start Sensor' to begin traffic capture.";
        if (lastSeenEl) lastSeenEl.textContent = "Status: offline";
        if (btnStart) btnStart.disabled = false;
        if (btnStop) btnStop.disabled = true;
        if (btnRestart) btnRestart.disabled = true;
      }
    }
  }

  // Update KPI counters
  function updateKpis(kpis) {
    if (!kpis) return;
    const totalEl = document.getElementById("totalEventsToday");
    const alertsEl = document.getElementById("alertsToday");
    const critEl = document.getElementById("criticalAlerts");
    const highEl = document.getElementById("highAlerts");

    if (totalEl) totalEl.textContent = Number(kpis.total_events_today || 0).toLocaleString();
    if (alertsEl) alertsEl.textContent = Number(kpis.alerts_today || 0).toLocaleString();
    if (critEl) critEl.textContent = Number(kpis.critical_alerts_today || 0).toLocaleString();
    if (highEl) highEl.textContent = Number(kpis.high_alerts_today || 0).toLocaleString();
  }

  // Render or update Chart.js protocol breakdown doughnut
  function updateProtocolChart(protoDist) {
    const canvas = document.getElementById("protocolChart");
    if (!canvas || typeof Chart === "undefined") return;

    const labels = Object.keys(protoDist || {});
    const dataValues = Object.values(protoDist || {});

    if (labels.length === 0) {
      labels.push("None");
      dataValues.push(1);
    }

    const bgColors = [
      "#3b82f6", // Blue
      "#10b981", // Emerald
      "#f59e0b", // Amber
      "#ef4444", // Red
      "#8b5cf6", // Violet
      "#06b6d4", // Cyan
      "#64748b"  // Slate
    ];

    if (protocolChartInstance) {
      protocolChartInstance.data.labels = labels;
      protocolChartInstance.data.datasets[0].data = dataValues;
      protocolChartInstance.data.datasets[0].backgroundColor = bgColors.slice(0, labels.length);
      protocolChartInstance.update();
      return;
    }

    const ctx = canvas.getContext("2d");
    protocolChartInstance = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: labels,
        datasets: [{
          data: dataValues,
          backgroundColor: bgColors.slice(0, labels.length),
          borderWidth: 1,
          borderColor: "#1e293b"
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "68%",
        plugins: {
          legend: {
            position: "right",
            labels: {
              boxWidth: 10,
              usePointStyle: true,
              color: "#94a3b8",
              font: { size: 11 }
            }
          },
          tooltip: {
            callbacks: {
              label: function (ctx) {
                const label = ctx.label || "";
                const val = ctx.raw || 0;
                return ` ${label}: ${Number(val).toLocaleString()} events`;
              }
            }
          }
        }
      }
    });
  }

  // Render Top Signatures table
  function renderTopSignatures(sigs) {
    const tbody = document.getElementById("topSignaturesBody");
    if (!tbody) return;

    if (!sigs || sigs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="4" class="text-center text-muted py-3">No intrusion signatures detected yet</td></tr>`;
      return;
    }

    tbody.innerHTML = sigs.map(s => {
      const sevClass = s.severity ? `badge-sev-${s.severity.toLowerCase()}` : "badge-neutral";
      return `<tr>
        <td class="fw-semibold text-truncate" style="max-width: 260px;" title="${escapeHtml(s.signature)}">${escapeHtml(s.signature)}</td>
        <td><span class="badge ${sevClass}">${escapeHtml(s.severity ? s.severity.toUpperCase() : 'INFO')}</span></td>
        <td class="text-muted text-sm text-truncate" style="max-width: 140px;">${escapeHtml(s.category || '—')}</td>
        <td class="text-end font-mono fw-bold text-primary">${Number(s.count).toLocaleString()}</td>
      </tr>`;
    }).join("");
  }

  // Render Top IPs
  function renderTopIps(containerId, ips, emptyMsg) {
    const tbody = document.getElementById(containerId);
    if (!tbody) return;

    if (!ips || ips.length === 0) {
      tbody.innerHTML = `<tr><td colspan="2" class="text-center text-muted py-3">${emptyMsg}</td></tr>`;
      return;
    }

    tbody.innerHTML = ips.map(item => `<tr>
      <td class="cell-mono text-sm">${escapeHtml(item.ip)}</td>
      <td class="text-end font-mono">${Number(item.count).toLocaleString()}</td>
    </tr>`).join("");
  }

  // Render Recent Alerts table
  function renderRecentAlerts(alerts) {
    const tbody = document.getElementById("recentAlertsBody");
    if (!tbody) return;

    if (!alerts || alerts.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" class="text-center text-muted py-4"><i class="bi bi-shield-check text-success d-block mb-1 fs-3"></i>No security alerts recorded</td></tr>`;
      return;
    }

    tbody.innerHTML = alerts.map(a => {
      const sevClass = a.severity ? `badge-sev-${a.severity.toLowerCase()}` : "badge-neutral";
      const ts = a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : "—";
      const src = a.src_ip ? `${escapeHtml(a.src_ip)}${a.src_port ? ':' + a.src_port : ''}` : "—";
      const dest = a.dest_ip ? `${escapeHtml(a.dest_ip)}${a.dest_port ? ':' + a.dest_port : ''}` : "—";
      return `<tr>
        <td class="cell-mono text-xs">${ts}</td>
        <td><span class="badge ${sevClass}">${escapeHtml((a.severity || 'info').toUpperCase())}</span></td>
        <td class="fw-semibold text-truncate" style="max-width: 250px;" title="${escapeHtml(a.signature)}">${escapeHtml(a.signature || 'Suricata Alert')}</td>
        <td class="cell-mono text-xs">${src}</td>
        <td class="cell-mono text-xs">${dest}</td>
        <td><span class="badge bg-dark border text-xs">${escapeHtml(a.protocol || 'IP')}</span></td>
        <td><span class="badge bg-${a.action === 'blocked' ? 'danger' : 'success'}-subtle text-${a.action === 'blocked' ? 'danger' : 'success'}">${escapeHtml((a.action || 'allowed').toUpperCase())}</span></td>
        <td class="text-end"><a href="/network-ids/events/${a.id}" class="btn btn-secondary btn-sm py-0 px-2" title="Inspect Event"><i class="bi bi-search"></i></a></td>
      </tr>`;
    }).join("");
  }

  // Render Recent Network Events table
  function renderRecentEvents(events) {
    const tbody = document.getElementById("recentEventsBody");
    if (!tbody) return;

    if (!events || events.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted py-4">No events captured yet</td></tr>`;
      return;
    }

    tbody.innerHTML = events.map(e => {
      const ts = e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : "—";
      const src = e.src_ip ? `${escapeHtml(e.src_ip)}${e.src_port ? ':' + e.src_port : ''}` : "—";
      const dest = e.dest_ip ? `${escapeHtml(e.dest_ip)}${e.dest_port ? ':' + e.dest_port : ''}` : "—";
        const isDiag = e.classification === 'diagnostic' || e.is_diagnostic || (e.signature_id === 2200074);
        const typeBadge = isDiag
          ? `<span class="badge bg-info-subtle text-info text-xs fw-semibold" title="NIC Checksum / Offload Diagnostic"><i class="bi bi-gear-wide-connected me-1"></i>DIAGNOSTIC</span>`
          : `<span class="badge bg-secondary text-xs">${escapeHtml((e.event_type || 'flow').toUpperCase())}</span>`;
        return `<tr>
          <td class="cell-mono text-xs">${ts}</td>
          <td>${typeBadge}</td>
        <td class="cell-mono text-xs">${src}</td>
        <td class="cell-mono text-xs">${dest}</td>
        <td><span class="badge bg-dark border text-xs">${escapeHtml(e.protocol || 'IP')}</span></td>
        <td class="cell-mono text-xs text-truncate" style="max-width: 140px;">${escapeHtml(e.flow_id ? String(e.flow_id) : '—')}</td>
        <td class="text-end"><a href="/network-ids/events/${e.id}" class="btn btn-secondary btn-sm py-0 px-2" title="Inspect Event"><i class="bi bi-search"></i></a></td>
      </tr>`;
    }).join("");
  }

  // Fetch Dashboard Telemetry and Refresh View
  async function fetchDashboard() {
    try {
      const res = await fetch("/network-ids/api/dashboard", { cache: "no-store" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (!data.success) return;

      updateSensorState(data.sensor);
      updateKpis(data.kpis);
      updateProtocolChart(data.protocol_distribution);
      renderTopSignatures(data.top_signatures);
      renderTopIps("topSrcIpsBody", data.top_source_ips, "No active source IPs");
      renderTopIps("topDestIpsBody", data.top_destination_ips, "No active destination IPs");
      renderRecentAlerts(data.recent_alerts);
      renderRecentEvents(data.recent_events);
    } catch (err) {
      console.warn("[Network IDS] Telemetry poll failed:", err);
    }
  }

  // Bind Actions: Start, Stop, Restart, Update Rules
  function bindSensorControls() {
    const btnStart = document.getElementById("btnStartSensor");
    const btnStop = document.getElementById("btnStopSensor");
    const btnRestart = document.getElementById("btnRestartSensor");
    const btnUpdateRules = document.getElementById("btnUpdateRules");

    if (btnStart) {
      btnStart.addEventListener("click", async () => {
        btnStart.disabled = true;
        btnStart.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span>Starting...`;
        try {
          const res = await fetch("/network-ids/api/sensor/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ interface: "eth0" })
          });
          const data = await res.json();
          if (data.success) {
            showToast("success", "Sensor Started", data.message);
          } else {
            showToast("error", "Startup Failed", data.message);
          }
        } catch (err) {
          showToast("error", "Error", String(err));
        } finally {
          btnStart.innerHTML = `<i class="bi bi-play-fill me-1"></i>Start Sensor`;
          fetchDashboard();
        }
      });
    }

    if (btnStop) {
      btnStop.addEventListener("click", async () => {
        btnStop.disabled = true;
        btnStop.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span>Stopping...`;
        try {
          const res = await fetch("/network-ids/api/sensor/stop", { method: "POST" });
          const data = await res.json();
          if (data.success) {
            showToast("info", "Sensor Stopped", data.message);
          } else {
            showToast("error", "Stop Failed", data.message);
          }
        } catch (err) {
          showToast("error", "Error", String(err));
        } finally {
          btnStop.innerHTML = `<i class="bi bi-stop-fill me-1"></i>Stop`;
          fetchDashboard();
        }
      });
    }

    if (btnRestart) {
      btnRestart.addEventListener("click", async () => {
        btnRestart.disabled = true;
        btnRestart.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span>Restarting...`;
        try {
          const res = await fetch("/network-ids/api/sensor/restart", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ interface: "eth0" })
          });
          const data = await res.json();
          if (data.success) {
            showToast("success", "Sensor Restarted", data.message);
          } else {
            showToast("error", "Restart Failed", data.message);
          }
        } catch (err) {
          showToast("error", "Error", String(err));
        } finally {
          btnRestart.innerHTML = `<i class="bi bi-arrow-repeat me-1"></i>Restart`;
          fetchDashboard();
        }
      });
    }

    if (btnUpdateRules) {
      btnUpdateRules.addEventListener("click", async () => {
        btnUpdateRules.disabled = true;
        btnUpdateRules.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span>Updating Rules...`;
        showToast("info", "Suricata Update", "Fetching and verifying latest threat rules...");
        try {
          const res = await fetch("/network-ids/api/rules/update", { method: "POST" });
          const data = await res.json();
          if (data.success) {
            showToast("success", "Rules Updated", data.message);
          } else {
            showToast("error", "Rule Update Failed", data.message);
          }
        } catch (err) {
          showToast("error", "Error", String(err));
        } finally {
          btnUpdateRules.disabled = false;
          btnUpdateRules.innerHTML = `<i class="bi bi-shield-check me-1"></i>Update Rules`;
          fetchDashboard();
        }
      });
    }
  }

  // Setup periodic polling
  function startPolling() {
    if (isPolling) return;
    isPolling = true;
    pollTimer = setInterval(fetchDashboard, 5000);
  }

  document.addEventListener("DOMContentLoaded", () => {
    bindSensorControls();
    fetchDashboard();
    startPolling();
  });

  window.addEventListener("beforeunload", () => {
    if (pollTimer) clearInterval(pollTimer);
  });
})();

