/* ==========================================================================
   evidence.js — page module for app/evidence.html
   Depends on: INCIDENTS_DATA (data/incident-data.js)
   ========================================================================== */

   (function () {
    const TYPE_META = {
      log: { icon: "bi-file-earmark-text", label: "Log Bundle" },
      pcap: { icon: "bi-diagram-3", label: "Network Capture" },
      mem: { icon: "bi-cpu", label: "Memory Dump" },
      img: { icon: "bi-image", label: "Screenshot" },
      bin: { icon: "bi-bug", label: "Malware Sample" },
    };
  
    const params = new URLSearchParams(window.location.search);
    const id = params.get("id");
    const incident = INCIDENTS_DATA.find((i) => i.id === id) || INCIDENTS_DATA[0];
  
    document.getElementById("breadcrumbIncLink").textContent = incident.title;
    document.getElementById("breadcrumbIncLink").href = `incident-details.html?id=${incident.id}`;
    document.getElementById("evidenceSummary").textContent = `${incident.evidence.length} items collected for ${incident.id} — ${incident.title}`;
  
    document.getElementById("statLogs").textContent = incident.evidence.filter((e) => e.type === "log").length;
    document.getElementById("statPcap").textContent = incident.evidence.filter((e) => e.type === "pcap").length;
    document.getElementById("statMem").textContent = incident.evidence.filter((e) => e.type === "mem").length;
    document.getElementById("statOther").textContent = incident.evidence.filter((e) => e.type === "img" || e.type === "bin").length;
  
    document.getElementById("evidenceGrid").innerHTML = incident.evidence.length
      ? incident.evidence.map((e) => {
          const meta = TYPE_META[e.type] || { icon: "bi-file-earmark", label: "File" };
          return `
          <div class="evidence-card">
            <div class="evidence-icon"><i class="bi ${meta.icon}"></i></div>
            <div class="evidence-meta">
              <div class="d-flex justify-content-between align-items-start flex-wrap gap-2">
                <div>
                  <div class="evidence-name">${e.name}</div>
                  <div class="text-xs text-muted">${meta.label} · ${e.size} · collected by ${e.collectedBy} on ${XDRUtils.formatTime(e.collectedAt)}</div>
                  <div class="evidence-hash mt-1">SHA-256: ${e.hash}</div>
                </div>
                <div class="d-flex gap-2">
                  <button class="btn btn-icon btn-ghost btn-sm" title="Download (dummy)"><i class="bi bi-download"></i></button>
                  <button class="btn btn-icon btn-ghost btn-sm" title="Preview (dummy)"><i class="bi bi-eye"></i></button>
                </div>
              </div>
            </div>
          </div>`;
        }).join("")
      : `<div class="empty-state"><i class="bi bi-inbox"></i><h3>No evidence collected</h3><p>Artifacts collected during investigation will appear here.</p></div>`;
  
    document.getElementById("uploadBtn").addEventListener("click", () => {
      if (window.showToast) window.showToast({ type: "info", title: "Upload disabled in preview", msg: "This is a static frontend demo — file upload isn't wired to a backend yet." });
    });
  })();
  