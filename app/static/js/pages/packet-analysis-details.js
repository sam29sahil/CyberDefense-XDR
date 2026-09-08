/**
 * CyberDefense XDR
 * Packet Analysis Details & Wireshark Inspector JavaScript
 */

document.addEventListener("DOMContentLoaded", () => {
  const analysisId = window.ANALYSIS_ID;
  if (!analysisId) return;

  // Overview Tab elements
  const protocolHierarchyBody = document.getElementById("protocolHierarchyBody");
  const conversationsTableBody = document.getElementById("conversationsTableBody");
  const endpointsTableBody = document.getElementById("endpointsTableBody");

  // Packet Inspector elements
  const filterForm = document.getElementById("filterForm");
  const displayFilterInput = document.getElementById("displayFilterInput");
  const btnClearFilter = document.getElementById("btnClearFilter");
  const packetsTableBody = document.getElementById("packetsTableBody");
  const packetRangeText = document.getElementById("packetRangeText");
  const packetPageText = document.getElementById("packetPageText");
  const btnPrevPackets = document.getElementById("btnPrevPackets");
  const btnNextPackets = document.getElementById("btnNextPackets");

  // Dissection & Hexdump elements
  const selectedPacketBadge = document.getElementById("selectedPacketBadge");
  const dissectionTreeContainer = document.getElementById("dissectionTreeContainer");
  const hexdumpContainer = document.getElementById("hexdumpContainer");

  // Actions
  const btnRerun = document.getElementById("btnRerunAnalysis");
  const btnDelete = document.getElementById("btnDeleteAnalysis");

  let currentPage = 1;
  const perPage = 50;
  let totalPages = 1;
  let activeFilter = "";
  let selectedPacketNumber = null;

  // ============================================================================
  // Tab 1 & 2: Overview, Protocols, Conversations, Endpoints
  // ============================================================================

  async function loadAnalysisDetails() {
    try {
      const res = await fetch(`/packet-analysis/api/analyses/${analysisId}`);
      const data = await res.json();
      if (!data.success || !data.analysis) return;

      const a = data.analysis;

      // Render Protocol Hierarchy
      renderProtocolHierarchy(a.protocol_stats || a.protocolStats || {});

      // Render Conversations
      renderConversations(a.conversation_stats || a.conversationStats || []);

      // Render Endpoints
      renderEndpoints(a.endpoint_stats || a.endpointStats || []);

    } catch (err) {
      console.error("Failed to fetch analysis details:", err);
    }
  }

  function renderProtocolHierarchy(protoData) {
    const protocols = protoData.protocols || [];
    if (!protocols.length) {
      protocolHierarchyBody.innerHTML = `<tr><td colspan="4" class="text-center text-muted py-3">No protocol hierarchy extracted.</td></tr>`;
      return;
    }

    protocolHierarchyBody.innerHTML = protocols.map(p => {
      const indentPx = (p.depth || 0) * 16;
      const pct = p.percent || 0;
      return `
        <tr>
          <td>
            <div style="padding-left: ${indentPx}px;">
              <i class="bi bi-diagram-3 text-muted me-1 small"></i>
              <span class="cell-mono fw-semibold">${escapeHtml(p.name)}</span>
            </div>
          </td>
          <td class="cell-mono">${(p.frames || 0).toLocaleString()}</td>
          <td class="cell-mono text-muted small">${formatBytes(p.bytes || 0)}</td>
          <td>
            <div class="d-flex align-items-center gap-2">
              <div class="progress flex-grow-1" style="height: 6px;">
                <div class="progress-bar bg-primary" style="width: ${pct}%;"></div>
              </div>
              <span class="small text-muted cell-mono" style="min-width: 45px;">${pct}%</span>
            </div>
          </td>
        </tr>
      `;
    }).join("");
  }

  function renderConversations(convs) {
    if (!convs.length) {
      conversationsTableBody.innerHTML = `<tr><td colspan="6" class="text-center text-muted py-3">No conversations detected.</td></tr>`;
      return;
    }

    conversationsTableBody.innerHTML = convs.slice(0, 20).map(c => `
      <tr>
        <td class="cell-mono">${escapeHtml(c.source)}</td>
        <td class="text-muted"><i class="bi bi-arrow-left-right"></i></td>
        <td class="cell-mono">${escapeHtml(c.destination)}</td>
        <td><span class="badge bg-secondary-subtle text-secondary">${escapeHtml(c.protocol || 'IP')}</span></td>
        <td class="cell-mono">${(c.frames || 0).toLocaleString()}</td>
        <td class="cell-mono text-muted small">${formatBytes(c.bytes || 0)}</td>
      </tr>
    `).join("");
  }

  function renderEndpoints(endpoints) {
    if (!endpoints.length) {
      endpointsTableBody.innerHTML = `<tr><td colspan="3" class="text-center text-muted py-3">No endpoints detected.</td></tr>`;
      return;
    }

    endpointsTableBody.innerHTML = endpoints.slice(0, 20).map(e => `
      <tr>
        <td class="cell-mono">${escapeHtml(e.ip)}</td>
        <td class="cell-mono">${(e.packets || 0).toLocaleString()}</td>
        <td class="cell-mono text-muted small">${formatBytes(e.bytes || 0)}</td>
      </tr>
    `).join("");
  }

  // ============================================================================
  // Tab 3: Wireshark Packet Inspector
  // ============================================================================

  async function loadPackets(page = 1) {
    packetsTableBody.innerHTML = `<tr><td colspan="7" class="text-center text-muted py-4"><span class="spinner-border spinner-border-sm me-2"></span>Filtering & loading packets...</td></tr>`;

    try {
      let url = `/packet-analysis/api/analyses/${analysisId}/packets?page=${page}&per_page=${perPage}`;
      if (activeFilter) {
        url += `&filter=${encodeURIComponent(activeFilter)}`;
      }

      const res = await fetch(url);
      const data = await res.json();

      if (!data.success) {
        packetsTableBody.innerHTML = `<tr><td colspan="7" class="text-center text-danger py-3">Filter error: ${escapeHtml(data.error)}</td></tr>`;
        return;
      }

      currentPage = data.page || 1;
      totalPages = data.pages || 1;
      const totalItems = data.total || 0;

      // Update range & page indicators
      const start = totalItems > 0 ? (currentPage - 1) * perPage + 1 : 0;
      const end = Math.min(currentPage * perPage, totalItems);
      packetRangeText.textContent = `Showing ${start}-${end} of ${totalItems.toLocaleString()}`;
      packetPageText.textContent = `Page ${currentPage} / ${totalPages}`;

      btnPrevPackets.disabled = !data.has_prev;
      btnNextPackets.disabled = !data.has_next;

      renderPacketsTable(data.items || []);

      // Auto-select first packet if none selected yet
      if (data.items && data.items.length > 0 && !selectedPacketNumber) {
        selectPacket(data.items[0].number);
      }

    } catch (err) {
      packetsTableBody.innerHTML = `<tr><td colspan="7" class="text-center text-danger py-3">Failed to load packets: ${err.message}</td></tr>`;
    }
  }

  function renderPacketsTable(packets) {
    if (!packets.length) {
      packetsTableBody.innerHTML = `<tr><td colspan="7" class="text-center text-muted py-4">No packets matched the current filter.</td></tr>`;
      return;
    }

    packetsTableBody.innerHTML = packets.map(pkt => {
      const isSelected = pkt.number === selectedPacketNumber;
      return `
        <tr class="packet-row ${isSelected ? 'table-active' : ''}" data-packet-no="${pkt.number}">
          <td class="text-muted">${pkt.number}</td>
          <td class="small text-muted">${escapeHtml(pkt.time ? pkt.time.split(' ')[3] || pkt.time : '-')}</td>
          <td>${escapeHtml(pkt.source)}</td>
          <td>${escapeHtml(pkt.destination)}</td>
          <td><span class="badge ${getProtocolBadgeClass(pkt.protocol)}">${escapeHtml(pkt.protocol)}</span></td>
          <td class="text-muted small">${pkt.length}</td>
          <td class="text-truncate" style="max-width: 320px;" title="${escapeHtml(pkt.info)}">${escapeHtml(pkt.info)}</td>
        </tr>
      `;
    }).join("");

    // Attach row click handlers
    document.querySelectorAll(".packet-row").forEach(row => {
      row.addEventListener("click", () => {
        const no = parseInt(row.getAttribute("data-packet-no"), 10);
        selectPacket(no);
      });
    });
  }

  function getProtocolBadgeClass(proto) {
    const p = (proto || "").toUpperCase();
    if (p.includes("TCP")) return "bg-primary-subtle text-primary";
    if (p.includes("UDP") || p.includes("DNS")) return "bg-info-subtle text-info";
    if (p.includes("HTTP")) return "bg-success-subtle text-success";
    if (p.includes("TLS") || p.includes("SSL")) return "bg-warning-subtle text-warning";
    if (p.includes("ICMP") || p.includes("ARP")) return "bg-secondary-subtle text-secondary";
    return "bg-secondary-subtle text-muted";
  }

  async function selectPacket(packetNumber) {
    selectedPacketNumber = packetNumber;
    selectedPacketBadge.textContent = `Packet #${packetNumber}`;

    // Highlight row
    document.querySelectorAll(".packet-row").forEach(row => {
      const no = parseInt(row.getAttribute("data-packet-no"), 10);
      if (no === packetNumber) {
        row.classList.add("table-active");
      } else {
        row.classList.remove("table-active");
      }
    });

    dissectionTreeContainer.innerHTML = `<div class="text-center py-3 text-muted"><span class="spinner-border spinner-border-sm me-2"></span>Dissecting packet #${packetNumber}...</div>`;
    hexdumpContainer.textContent = "Loading raw bytes...";

    try {
      const res = await fetch(`/packet-analysis/api/analyses/${analysisId}/packets/${packetNumber}`);
      const data = await res.json();

      if (!data.success) {
        dissectionTreeContainer.innerHTML = `<div class="text-danger py-2">Failed: ${escapeHtml(data.error)}</div>`;
        hexdumpContainer.textContent = "Error loading hex dump.";
        return;
      }

      renderDissectionTree(data.layers || {});
      hexdumpContainer.textContent = data.hexdump || "No raw packet data available.";

    } catch (err) {
      dissectionTreeContainer.innerHTML = `<div class="text-danger py-2">Error: ${err.message}</div>`;
      hexdumpContainer.textContent = "Error loading hex dump.";
    }
  }

  function renderDissectionTree(layers) {
    const layerKeys = Object.keys(layers);
    if (!layerKeys.length) {
      dissectionTreeContainer.innerHTML = `<div class="text-muted small">No dissection layers available for this packet.</div>`;
      return;
    }

    const layerLabels = {
      frame: "Frame (Physical / Link Layer)",
      eth: "Ethernet II",
      ip: "Internet Protocol Version 4",
      ipv6: "Internet Protocol Version 6",
      tcp: "Transmission Control Protocol",
      udp: "User Datagram Protocol",
      icmp: "Internet Control Message Protocol",
      dns: "Domain Name System",
      http: "Hypertext Transfer Protocol",
      tls: "Transport Layer Security",
      arp: "Address Resolution Protocol",
    };

    let html = `<div class="accordion accordion-flush" id="dissectionAccordion">`;

    layerKeys.forEach((key, idx) => {
      const layerObj = layers[key];
      const title = layerLabels[key] || `Protocol: ${key.toUpperCase()}`;
      const collapseId = `collapseLayer_${idx}`;

      // Build key-value list of fields inside layer
      let fieldRows = "";
      if (typeof layerObj === "object" && layerObj !== null) {
        fieldRows = Object.entries(layerObj).map(([fKey, fVal]) => {
          if (typeof fVal === "object") return ""; // Skip subtrees for brevity
          return `
            <div class="d-flex justify-content-between py-1 border-bottom border-secondary-subtle">
              <span class="text-muted small cell-mono">${escapeHtml(fKey)}</span>
              <span class="cell-mono text-break small">${escapeHtml(String(fVal))}</span>
            </div>
          `;
        }).join("");
      }

      html += `
        <div class="accordion-item bg-transparent border-secondary-subtle">
          <h2 class="accordion-header" id="heading_${idx}">
            <button class="accordion-button py-2 small fw-semibold ${idx === 0 ? '' : 'collapsed'}" type="button" data-bs-toggle="collapse" data-bs-target="#${collapseId}">
              <i class="bi bi-chevron-right me-2 small"></i>${escapeHtml(title)}
            </button>
          </h2>
          <div id="${collapseId}" class="accordion-collapse collapse ${idx === 0 ? 'show' : ''}" data-bs-parent="#dissectionAccordion">
            <div class="accordion-body p-2 bg-dark-subtle">
              ${fieldRows || '<div class="text-muted small">No direct fields</div>'}
            </div>
          </div>
        </div>
      `;
    });

    html += `</div>`;
    dissectionTreeContainer.innerHTML = html;
  }

  // Filter Form Submit
  filterForm.addEventListener("submit", (e) => {
    e.preventDefault();
    activeFilter = displayFilterInput.value.trim();
    loadPackets(1);
  });

  btnClearFilter.addEventListener("click", () => {
    displayFilterInput.value = "";
    activeFilter = "";
    loadPackets(1);
  });

  // Pagination buttons
  btnPrevPackets.addEventListener("click", () => {
    if (currentPage > 1) {
      loadPackets(currentPage - 1);
    }
  });

  btnNextPackets.addEventListener("click", () => {
    if (currentPage < totalPages) {
      loadPackets(currentPage + 1);
    }
  });

  // Re-run Button
  btnRerun.addEventListener("click", async () => {
    btnRerun.disabled = true;
    btnRerun.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span>Running...`;
    try {
      const res = await fetch(`/packet-analysis/api/analyses/${analysisId}/run`, { method: "POST" });
      const data = await res.json();
      if (data.success) {
        location.reload();
      } else {
        alert("Re-analysis failed: " + (data.error || "Unknown error"));
        btnRerun.disabled = false;
        btnRerun.innerHTML = `<i class="bi bi-arrow-repeat me-1"></i>Re-run TShark`;
      }
    } catch (err) {
      alert("Error: " + err.message);
      btnRerun.disabled = false;
      btnRerun.innerHTML = `<i class="bi bi-arrow-repeat me-1"></i>Re-run TShark`;
    }
  });

  // Delete Button
  btnDelete.addEventListener("click", async () => {
    if (confirm("Are you sure you want to delete this PCAP analysis session?")) {
      try {
        const res = await fetch(`/packet-analysis/api/analyses/${analysisId}`, { method: "DELETE" });
        const data = await res.json();
        if (data.success) {
          window.location.href = "/packet-analysis/";
        } else {
          alert("Delete failed: " + (data.error || "Unknown error"));
        }
      } catch (err) {
        alert("Delete failed: " + err.message);
      }
    }
  });

  // Helper formatting
  function formatBytes(num) {
    if (!num) return "0 B";
    let n = parseFloat(num);
    const units = ["B", "KB", "MB", "GB"];
    for (const u of units) {
      if (Math.abs(n) < 1024.0) return `${n.toFixed(1)} ${u}`;
      n /= 1024.0;
    }
    return `${n.toFixed(1)} TB`;
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

  // Initial Data Load
  loadAnalysisDetails();
  loadPackets(1);
});

