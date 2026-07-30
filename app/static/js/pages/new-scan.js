/* ==========================================================================
   new-scan.js — page module for app/new-scan.html
   Depends on: TARGETS_DATA (data/targets-data.js)
   ========================================================================== */

   (function () {
    const selected = new Set();
  
    document.getElementById("targetPicker").innerHTML = TARGETS_DATA.map((t) => `
      <label class="target-pick-chip" data-id="${t.id}">
        <input type="checkbox" value="${t.id}">
        <i class="bi bi-crosshair"></i> ${t.name} <span class="text-muted">(${t.assetCount})</span>
      </label>`).join("");
  
    function updateSummary() {
      const targets = TARGETS_DATA.filter((t) => selected.has(t.id));
      document.getElementById("summaryType").textContent = document.getElementById("scanType").value;
      document.getElementById("summaryTargetCount").textContent = targets.length;
      document.getElementById("summaryAssetCount").textContent = targets.reduce((s, t) => s + t.assetCount, 0);
      document.getElementById("summarySchedule").textContent = document.getElementById("scheduleMode").value === "now" ? "Run now" : (document.getElementById("scheduleTime").value || "Not set");
    }
  
    document.querySelectorAll(".target-pick-chip").forEach((chip) => {
      chip.addEventListener("click", (e) => {
        if (e.target.tagName !== "INPUT") e.preventDefault();
        const id = chip.dataset.id;
        const cb = chip.querySelector("input");
        if (selected.has(id)) { selected.delete(id); cb.checked = false; chip.classList.remove("selected"); }
        else { selected.add(id); cb.checked = true; chip.classList.add("selected"); }
        updateSummary();
      });
    });
  
    document.getElementById("scanType").addEventListener("change", updateSummary);
    document.getElementById("scheduleMode").addEventListener("change", (e) => {
      const isScheduled = e.target.value === "scheduled";
      document.getElementById("scheduleTime").disabled = !isScheduled;
      updateSummary();
    });
    document.getElementById("scheduleTime").addEventListener("change", updateSummary);
    updateSummary();
  
    document.getElementById("launchScanBtn").addEventListener("click", () => {
      if (selected.size === 0) {
        if (window.showToast) window.showToast({ type: "warning", title: "Select at least one target", msg: "Choose one or more targets before launching the scan." });
        return;
      }
      const isScheduled = document.getElementById("scheduleMode").value === "scheduled";
      if (isScheduled) {
        if (window.showToast) window.showToast({ type: "success", title: "Scan scheduled", msg: `Will run at ${document.getElementById("scheduleTime").value || "the selected time"}.` });
        setTimeout(() => { window.location.href = "scan-history.html"; }, 900);
        return;
      }
  
      const btn = document.getElementById("launchScanBtn");
      btn.disabled = true;
      btn.innerHTML = `<i class="bi bi-hourglass-split"></i> Scanning…`;
      document.getElementById("scanProgressWrap").classList.add("show");
  
      const steps = [
        [15, "Initializing scan engine…"], [35, "Discovering live hosts…"], [55, "Enumerating services and versions…"],
        [75, "Matching known CVEs…"], [92, "Compiling findings…"], [100, "Finalizing report…"],
      ];
      let i = 0;
      const bar = document.getElementById("scanProgressBar");
      const label = document.getElementById("scanProgressLabel");
      const interval = setInterval(() => {
        if (i >= steps.length) {
          clearInterval(interval);
          if (window.showToast) window.showToast({ type: "success", title: "Scan complete", msg: "Findings are ready in Scan History." });
          setTimeout(() => { window.location.href = "scan-history.html"; }, 700);
          return;
        }
        const [pct, msg] = steps[i];
        bar.style.width = `${pct}%`;
        label.textContent = msg;
        i++;
      }, 550);
    });
  })();
  