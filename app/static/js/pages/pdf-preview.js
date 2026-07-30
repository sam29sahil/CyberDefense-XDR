/* ==========================================================================
   pdf-preview.js — page module for app/pdf-preview.html
   Reads ?id= (a REPORTS_DATA id) or ?type=executive|technical for a quick
   preview and renders a simplified single-page mock of the document.
   ========================================================================== */

   (function () {
    const params = new URLSearchParams(window.location.search);
    const id = params.get("id");
    const type = params.get("type");
  
    const report = id ? REPORTS_DATA.find((r) => r.id === id) : null;
    const title = report ? report.name : (type === "technical" ? "Technical Deep Dive — Preview" : "Executive Summary — Preview");
    const now = new Date("2026-07-24T09:58:00Z");
  
    document.getElementById("previewTitle").textContent = `${title} · ${report ? report.format : "PDF"}`;
    document.title = `PDF Preview — ${title}`;
  
    const pageCount = report ? report.pages : 6;
    document.getElementById("pageIndicator").textContent = `Page 1 of ${pageCount}`;
  
    document.getElementById("previewPaper").innerHTML = `
      <div class="report-header">
        <div class="d-flex justify-content-between align-items-start">
          <div>
            <h1 style="font-size:22px;margin-bottom:4px;">CyberDefense XDR</h1>
            <div class="report-meta">${title} · Generated ${XDRUtils.formatTime(now.toISOString())}${report ? ` by ${report.generatedBy}` : ""}</div>
          </div>
          <div class="report-icon-tile"><i class="bi bi-file-earmark-pdf"></i></div>
        </div>
      </div>
      <div class="kpi-strip">
        <div class="kpi-block"><div class="num">${pageCount}</div><div class="lbl">Pages</div></div>
        <div class="kpi-block"><div class="num">${report ? report.type : (type === "technical" ? "Technical" : "Executive")}</div><div class="lbl">Report Type</div></div>
        <div class="kpi-block"><div class="num">${report ? report.format : "PDF"}</div><div class="lbl">Format</div></div>
      </div>
      <p>This is a preview render of the document. The full paginated report is available once generation completes and can be downloaded from the Reports table.</p>
      <table>
        <thead><tr><th>Section</th><th>Included</th></tr></thead>
        <tbody>
          <tr><td>Executive overview</td><td>Yes</td></tr>
          <tr><td>Incident summary</td><td>Yes</td></tr>
          <tr><td>Detection &amp; vulnerability detail</td><td>${(report ? report.type : type) === "Technical Deep Dive" || type === "technical" ? "Yes" : "Summary only"}</td></tr>
          <tr><td>Recommendations</td><td>Yes</td></tr>
        </tbody>
      </table>
      <p class="report-meta mt-4">Confidential — internal distribution only.</p>
    `;
  
    document.getElementById("printBtn").addEventListener("click", () => window.print());
    document.getElementById("downloadBtn").addEventListener("click", () => {
      if (window.showToast) window.showToast({ type: "success", title: "Download started", msg: `${title}.pdf` });
    });
  })();
  