/**
 * CyberDefense XDR
 * Packet Analysis Dashboard Frontend JavaScript
 */

document.addEventListener("DOMContentLoaded", () => {
  const kpiTotalAnalyses = document.getElementById("kpiTotalAnalyses");
  const kpiCompletedAnalyses = document.getElementById("kpiCompletedAnalyses");
  const kpiRunningAnalyses = document.getElementById("kpiRunningAnalyses");
  const kpiTotalPackets = document.getElementById("kpiTotalPackets");
  const tableBody = document.getElementById("analysesTableBody");
  const searchInput = document.getElementById("searchAnalyses");
  const btnRefresh = document.getElementById("btnRefreshDashboard");

  let pollInterval = null;

  async function fetchDashboardStats() {
    try {
      const res = await fetch("/packet-analysis/api/dashboard");
      const data = await res.json();
      if (data.success && data.kpis) {
        kpiTotalAnalyses.textContent = data.kpis.totalAnalyses.toLocaleString();
        kpiCompletedAnalyses.textContent = data.kpis.completedAnalyses.toLocaleString();
        kpiRunningAnalyses.textContent = data.kpis.runningAnalyses.toLocaleString();
        kpiTotalPackets.textContent = data.kpis.totalPackets.toLocaleString();

        // Check if any analysis is currently running, if so keep polling
        if (data.kpis.runningAnalyses > 0 && !pollInterval) {
          pollInterval = setInterval(fetchDashboardStats, 3000);
        } else if (data.kpis.runningAnalyses === 0 && pollInterval) {
          clearInterval(pollInterval);
          pollInterval = null;
        }
      }
    } catch (err) {
      console.error("Failed to load dashboard KPIs:", err);
    }
  }

  async function fetchAnalyses(searchTerm = "") {
    try {
      const url = searchTerm 
        ? `/packet-analysis/api/analyses?search=${encodeURIComponent(searchTerm)}`
        : "/packet-analysis/api/analyses";

      const res = await fetch(url);
      const data = await res.json();

      if (data.success) {
        renderAnalysesTable(data.items || []);
      } else {
        tableBody.innerHTML = `<tr><td colspan="8" class="text-center text-danger py-3">Error: ${data.error}</td></tr>`;
      }
    } catch (err) {
      tableBody.innerHTML = `<tr><td colspan="8" class="text-center text-danger py-3">Failed to load analyses.</td></tr>`;
    }
  }

  function renderAnalysesTable(items) {
    if (!items.length) {
      tableBody.innerHTML = `<tr><td colspan="8" class="text-center text-muted py-4">No PCAP analysis sessions recorded yet. Upload a PCAP to begin.</td></tr>`;
      return;
    }

    tableBody.innerHTML = items.map(item => {
      const statusBadge = getStatusBadge(item.status);
      const shortHash = item.sha256 ? `${item.sha256.substring(0, 10)}...${item.sha256.substring(item.sha256.length - 6)}` : "-";
      const durationStr = item.duration ? `${item.duration.toFixed(2)}s` : "-";
      const createdStr = item.created_at ? new Date(item.created_at).toLocaleString() : "-";

      return `
        <tr>
          <td>${statusBadge}</td>
          <td>
            <a href="/packet-analysis/analyses/${item.id}" class="fw-semibold text-decoration-none">
              ${escapeHtml(item.filename)}
            </a>
            <span class="badge bg-secondary-subtle text-muted ms-1 small">${escapeHtml(item.file_type || 'pcap').toUpperCase()}</span>
          </td>
          <td class="cell-mono small text-muted">${item.fileSizeFormatted || (item.file_size + ' B')}</td>
          <td class="cell-mono fw-semibold">${(item.packet_count || 0).toLocaleString()}</td>
          <td class="cell-mono small">${durationStr}</td>
          <td>
            <code class="cell-mono text-muted small" title="${item.sha256}">${shortHash}</code>
          </td>
          <td class="small text-muted">${createdStr}</td>
          <td class="text-end">
            <a href="/packet-analysis/analyses/${item.id}" class="btn btn-outline-primary btn-xs me-1">
              <i class="bi bi-eye"></i> Inspect
            </a>
            <button class="btn btn-outline-danger btn-xs btn-delete-analysis" data-id="${item.id}">
              <i class="bi bi-trash"></i>
            </button>
          </td>
        </tr>
      `;
    }).join("");

    // Attach delete listeners
    document.querySelectorAll(".btn-delete-analysis").forEach(btn => {
      btn.addEventListener("click", async (e) => {
        const id = e.currentTarget.getAttribute("data-id");
        if (confirm("Are you sure you want to delete this PCAP analysis and stored capture?")) {
          await deleteAnalysis(id);
        }
      });
    });
  }

  function getStatusBadge(status) {
    switch ((status || "").toLowerCase()) {
      case "completed":
        return `<span class="badge bg-success-subtle text-success"><i class="bi bi-check-circle me-1"></i>Completed</span>`;
      case "running":
        return `<span class="badge bg-warning-subtle text-warning"><i class="bi bi-arrow-repeat spin me-1"></i>Running</span>`;
      case "failed":
        return `<span class="badge bg-danger-subtle text-danger"><i class="bi bi-x-circle me-1"></i>Failed</span>`;
      case "uploaded":
      case "queued":
        return `<span class="badge bg-info-subtle text-info"><i class="bi bi-clock me-1"></i>Queued</span>`;
      default:
        return `<span class="badge bg-secondary-subtle text-secondary">${escapeHtml(status)}</span>`;
    }
  }

  async function deleteAnalysis(id) {
    try {
      const res = await fetch(`/packet-analysis/api/analyses/${id}`, { method: "DELETE" });
      const data = await res.json();
      if (data.success) {
        fetchDashboardStats();
        fetchAnalyses(searchInput.value.trim());
      } else {
        alert("Delete failed: " + (data.error || "Unknown error"));
      }
    } catch (err) {
      alert("Delete failed: " + err.message);
    }
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  let searchTimeout = null;
  searchInput.addEventListener("input", () => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
      fetchAnalyses(searchInput.value.trim());
    }, 300);
  });

  btnRefresh.addEventListener("click", () => {
    fetchDashboardStats();
    fetchAnalyses(searchInput.value.trim());
  });

  // Initial load
  fetchDashboardStats();
  fetchAnalyses();
});

