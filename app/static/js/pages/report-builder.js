/* ==========================================================================
   report-builder.js — page module for app/report-builder.html
   ========================================================================== */

   (function () {
    function selectedSections() {
      return [...document.querySelectorAll("#sectionsGrid input:checked")].map((c) => c.value);
    }
  
    function updatePreview() {
      document.getElementById("prevType").textContent = document.getElementById("rptType").value;
      document.getElementById("prevFormat").textContent = document.getElementById("rptFormat").value;
      document.getElementById("prevRange").textContent = `${document.getElementById("rptFrom").value} → ${document.getElementById("rptTo").value}`;
      const sections = selectedSections();
      document.getElementById("prevSections").textContent = sections.length ? sections.join(", ") : "None selected";
    }
  
    ["rptType", "rptFormat", "rptFrom", "rptTo"].forEach((id) => document.getElementById(id).addEventListener("change", updatePreview));
    document.querySelectorAll("#sectionsGrid input").forEach((cb) => cb.addEventListener("change", updatePreview));
    updatePreview();
  
    document.getElementById("generateBtn").addEventListener("click", () => {
      const name = document.getElementById("rptName").value.trim();
      if (!name) {
        if (window.showToast) window.showToast({ type: "warning", title: "Report name required" });
        document.getElementById("rptName").focus();
        return;
      }
      if (!selectedSections().length) {
        if (window.showToast) window.showToast({ type: "warning", title: "Select at least one section" });
        return;
      }
      if (window.showToast) window.showToast({ type: "success", title: "Report generation started", msg: `"${name}" will appear in Reports once ready.` });
      setTimeout(() => { window.location.href = "reports-dashboard.html"; }, 1000);
    });
  })();
  