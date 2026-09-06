/* ==========================================================================
   new-scan.js — page module for app/new-scan.html
   Multi-Tool Vulnerability Scanner: Nmap, WhatWeb, Nikto, Nuclei, testssl
   ========================================================================== */

(function () {
  let targetsData = typeof TARGETS_DATA !== "undefined" ? [...TARGETS_DATA] : [];
  const selectedTargets = new Map(); // id -> target object
  const customTargets = new Set();

  const targetPicker = document.getElementById("targetPicker");
  const scanTypeSelect = document.getElementById("scanType");
  const scanProfileSelect = document.getElementById("scanProfile");
  const scheduleModeSelect = document.getElementById("scheduleMode");
  const scheduleTimeInput = document.getElementById("scheduleTime");
  const launchScanBtn = document.getElementById("launchScanBtn");
  const customTargetInput = document.getElementById("customTargetInput");
  const addCustomTargetBtn = document.getElementById("addCustomTargetBtn");
  const customTargetsList = document.getElementById("customTargetsList");
  const authConfirmCheck = document.getElementById("authConfirmCheck");

  // Fetch scanner tools availability
  function fetchToolCapabilities() {
    fetch("/scanner/api/tools")
      .then((res) => (res.ok ? res.json() : Promise.reject(res)))
      .then((res) => {
        const tools = (res && res.tools) || (res && res.data) || {};
        updateToolBadge("toolNmapStatus", tools.nmap);
        updateToolBadge("toolWhatwebStatus", tools.whatweb);
        updateToolBadge("toolNiktoStatus", tools.nikto);
        updateToolBadge("toolNucleiStatus", tools.nuclei);
        updateToolBadge("toolTestsslStatus", tools.testssl);
      })
      .catch(() => {
        // Fallback default
        updateToolBadge("toolNmapStatus", { available: true, version: "Local" });
        updateToolBadge("toolWhatwebStatus", { available: true, version: "Installed" });
        updateToolBadge("toolNiktoStatus", { available: true, version: "Installed" });
        updateToolBadge("toolNucleiStatus", { available: false, version: null });
        updateToolBadge("toolTestsslStatus", { available: false, version: null });
      });
  }

  function updateToolBadge(elementId, toolInfo) {
    const el = document.getElementById(elementId);
    if (!el) return;
    if (toolInfo && toolInfo.available) {
      el.className = "badge bg-success-subtle text-success";
      el.innerHTML = `<i class="bi bi-check-circle me-1"></i>Ready${toolInfo.version ? ` (${toolInfo.version.split(' ')[0]})` : ''}`;
    } else {
      el.className = "badge bg-secondary-subtle text-secondary";
      el.innerHTML = `<i class="bi bi-dash-circle me-1"></i>Not Installed`;
    }
  }

  function renderPicker() {
    if (!targetPicker) return;
    targetPicker.innerHTML = targetsData.map((t) => {
      const isChecked = selectedTargets.has(t.id);
      const targetLabel = t.targetInput || t.name;
      return `
        <label class="target-pick-chip ${isChecked ? "selected" : ""}" data-id="${t.id}">
          <input type="checkbox" value="${t.id}" ${isChecked ? "checked" : ""}>
          <i class="bi bi-crosshair"></i> ${t.name} <span class="text-muted">(${targetLabel})</span>
        </label>`;
    }).join("");

    targetPicker.querySelectorAll(".target-pick-chip").forEach((chip) => {
      chip.addEventListener("click", (e) => {
        if (e.target.tagName !== "INPUT") e.preventDefault();
        const id = chip.dataset.id;
        const cb = chip.querySelector("input");
        const targetObj = targetsData.find((t) => t.id === id);

        if (selectedTargets.has(id)) {
          selectedTargets.delete(id);
          cb.checked = false;
          chip.classList.remove("selected");
        } else if (targetObj) {
          selectedTargets.set(id, targetObj);
          cb.checked = true;
          chip.classList.add("selected");
        }
        updateSummary();
      });
    });
  }

  function renderCustomTargets() {
    if (!customTargetsList) return;
    customTargetsList.innerHTML = Array.from(customTargets).map((t) => `
      <span class="badge bg-dark border text-light p-2 d-inline-flex align-items-center gap-1">
        <i class="bi bi-hdd-network text-primary"></i> ${t}
        <button type="button" class="btn-close btn-close-white ms-1" style="font-size:0.65rem;" data-val="${t}"></button>
      </span>
    `).join("");

    customTargetsList.querySelectorAll("button.btn-close").forEach((btn) => {
      btn.addEventListener("click", () => {
        const val = btn.dataset.val;
        customTargets.delete(val);
        renderCustomTargets();
        updateSummary();
      });
    });
  }

  function addCustomTarget() {
    const val = customTargetInput ? customTargetInput.value.trim() : "";
    if (!val) return;
    customTargets.add(val);
    if (customTargetInput) customTargetInput.value = "";
    renderCustomTargets();
    updateSummary();
  }

  if (addCustomTargetBtn) {
    addCustomTargetBtn.addEventListener("click", addCustomTarget);
  }
  if (customTargetInput) {
    customTargetInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        addCustomTarget();
      }
    });
  }

  function updateSummary() {
    const configuredList = Array.from(selectedTargets.values());
    const totalCount = configuredList.length + customTargets.size;
    const type = scanTypeSelect?.value || "Standard Scan";
    const profile = scanProfileSelect?.value || "STANDARD";
    const mode = scheduleModeSelect?.value || "now";

    const summaryProfile = document.getElementById("summaryProfile");
    const summaryType = document.getElementById("summaryType");
    const summaryTargetCount = document.getElementById("summaryTargetCount");
    const summaryAssetCount = document.getElementById("summaryAssetCount");
    const summarySchedule = document.getElementById("summarySchedule");

    if (summaryProfile) summaryProfile.textContent = profile;
    if (summaryType) summaryType.textContent = type;
    if (summaryTargetCount) summaryTargetCount.textContent = totalCount;
    if (summaryAssetCount) {
      const configuredAssets = configuredList.reduce((s, t) => s + (t.assetCount || 1), 0);
      summaryAssetCount.textContent = configuredAssets + customTargets.size;
    }
    if (summarySchedule) {
      summarySchedule.textContent = mode === "now" ? "Run now" : (scheduleTimeInput?.value || "Scheduled");
    }
  }

  // Event listeners
  if (scanTypeSelect) scanTypeSelect.addEventListener("change", updateSummary);
  if (scanProfileSelect) scanProfileSelect.addEventListener("change", updateSummary);
  if (scheduleModeSelect) {
    scheduleModeSelect.addEventListener("change", (e) => {
      const isScheduled = e.target.value === "scheduled";
      if (scheduleTimeInput) scheduleTimeInput.disabled = !isScheduled;
      updateSummary();
    });
  }
  if (scheduleTimeInput) scheduleTimeInput.addEventListener("change", updateSummary);

  // Fetch targets from API
  fetch("/scanner/api/targets")
    .then((res) => (res.ok ? res.json() : Promise.reject(res)))
    .then((data) => {
      if (data && Array.isArray(data.targets) && data.targets.length) {
        targetsData = data.targets;
        // Default select the first target if available
        if (targetsData.length > 0 && selectedTargets.size === 0) {
          selectedTargets.set(targetsData[0].id, targetsData[0]);
        }
      }
      renderPicker();
      updateSummary();
    })
    .catch(() => {
      renderPicker();
      updateSummary();
    });

  fetchToolCapabilities();

  // Launch scan handler
  if (launchScanBtn) {
    launchScanBtn.addEventListener("click", () => {
      const configuredList = Array.from(selectedTargets.values()).map((t) => t.targetInput || t.name);
      const allTargets = [...configuredList, ...Array.from(customTargets)];

      if (allTargets.length === 0) {
        if (window.showToast) window.showToast({ type: "warning", title: "Target required", msg: "Please select or enter at least one authorized target to scan." });
        return;
      }

      if (authConfirmCheck && !authConfirmCheck.checked) {
        if (window.showToast) window.showToast({ type: "danger", title: "Authorization Required", msg: "You must confirm you have explicit authorization to scan the targets." });
        return;
      }

      const scanNameInput = document.getElementById("scanName");
      const scanType = scanTypeSelect?.value || "Standard Scan";
      const profile = scanProfileSelect?.value || "STANDARD";
      const defaultName = `${scanType} (${profile}) — ${new Date().toLocaleDateString("en-US", { month: "short", day: "numeric" })}`;
      const name = scanNameInput?.value?.trim() || defaultName;

      const scheduleMode = scheduleModeSelect?.value || "now";
      const scheduledTime = scheduleTimeInput?.value || null;

      const options = {
        service_detection: document.getElementById("optService")?.checked ?? true,
        cve_matching: document.getElementById("optCve")?.checked ?? true,
        web_checks: document.getElementById("optWeb")?.checked ?? true,
        nikto_scan: document.getElementById("optNikto")?.checked ?? false,
        threat_intel: document.getElementById("optThreatIntel")?.checked ?? true,
        safe_checks: document.getElementById("optSafe")?.checked ?? true,
      };

      launchScanBtn.disabled = true;
      launchScanBtn.innerHTML = `<i class="bi bi-hourglass-split"></i> Scanning…`;
      const progressWrap = document.getElementById("scanProgressWrap");
      const progressBar = document.getElementById("scanProgressBar");
      const progressLabel = document.getElementById("scanProgressLabel");
      if (progressWrap) progressWrap.classList.add("show");

      let pct = 10;
      if (progressBar) progressBar.style.width = `${pct}%`;
      if (progressLabel) progressLabel.textContent = "Initializing multi-tool scan pipeline…";

      const stepTimer = setInterval(() => {
        if (pct < 90) {
          pct += 12;
          if (progressBar) progressBar.style.width = `${pct}%`;
          if (pct === 22 && progressLabel) progressLabel.textContent = "Resolving DNS & validating targets…";
          if (pct === 34 && progressLabel) progressLabel.textContent = "Executing Nmap port & version discovery…";
          if (pct === 50 && progressLabel) progressLabel.textContent = "Running WhatWeb fingerprinting…";
          if (pct === 66 && progressLabel) progressLabel.textContent = "Querying Threat Intelligence IOCs…";
          if (pct === 78 && progressLabel) progressLabel.textContent = "Deduplicating & scoring CVE findings…";
          if (pct >= 88 && progressLabel) progressLabel.textContent = "Finalizing scan report & syncing alerts…";
        }
      }, 500);

      fetch("/scanner/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name,
          type: scanType,
          profile,
          targets: allTargets,
          options,
          schedule_mode: scheduleMode,
          scheduled_time: scheduledTime,
          initiated_by: "Security Analyst",
        }),
      })
        .then((res) => res.json().then((data) => ({ status: res.status, body: data })))
        .then(({ status, body }) => {
          clearInterval(stepTimer);
          if (status >= 200 && status < 300 && (body.scan || body.data)) {
            const scanObj = body.scan || body.data;
            if (progressBar) progressBar.style.width = "100%";
            if (progressLabel) progressLabel.textContent = "Scan completed successfully!";
            if (window.showToast) {
              window.showToast({
                type: "success",
                title: "Scan Completed",
                msg: `Scan ${scanObj.id} finished with ${scanObj.totalFindings || 0} finding(s).`,
              });
            }
            setTimeout(() => {
              window.location.href = `/scanner/details/${scanObj.id}`;
            }, 800);
          } else {
            if (progressBar) progressBar.style.width = "0%";
            launchScanBtn.disabled = false;
            launchScanBtn.innerHTML = `<i class="bi bi-play-fill"></i> Launch Scan`;
            if (window.showToast) {
              window.showToast({
                type: "danger",
                title: "Scan Failed",
                msg: body.error || body.message || "Failed to launch scan.",
              });
            }
          }
        })
        .catch((err) => {
          clearInterval(stepTimer);
          launchScanBtn.disabled = false;
          launchScanBtn.innerHTML = `<i class="bi bi-play-fill"></i> Launch Scan`;
          if (window.showToast) {
            window.showToast({
              type: "danger",
              title: "Network Error",
              msg: err.message || "Could not reach scan service.",
            });
          }
        });
    });
  }
})();