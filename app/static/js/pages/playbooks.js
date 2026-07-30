/* ==========================================================================
   playbooks.js — page module for app/playbooks.html
   Playbook definitions are small and static, so they live inline here
   rather than in a separate data/*.js file.
   ========================================================================== */

   (function () {
    const PLAYBOOKS = [
      { id: "PB-01", name: "Ransomware Containment", category: "Ransomware", icon: "bi-lock-fill",
        description: "Isolate affected hosts, preserve evidence, and coordinate recovery from clean backups.",
        steps: ["Isolate affected endpoints from the network", "Identify patient-zero and initial access vector", "Preserve volatile memory and disk evidence", "Disable compromised credentials", "Restore from last known-good backup", "Validate integrity before reconnecting hosts"] },
      { id: "PB-02", name: "Data Breach Response", category: "Data Breach", icon: "bi-shield-x",
        description: "Contain exposure, assess scope, and meet regulatory notification obligations.",
        steps: ["Identify and contain the exposed data source", "Determine scope and sensitivity of exposed data", "Engage legal and compliance teams", "Notify affected parties per regulatory timelines", "Rotate any exposed credentials or keys", "Document root cause and remediation"] },
      { id: "PB-03", name: "Phishing Campaign Response", category: "Phishing", icon: "bi-envelope-exclamation",
        description: "Contain a phishing wave, identify affected users, and harden email defenses.",
        steps: ["Block sender domain and malicious URLs", "Search and purge phishing emails org-wide", "Identify users who clicked or submitted credentials", "Force password reset for affected accounts", "Notify staff with awareness reminder", "Tune email gateway rules to prevent recurrence"] },
      { id: "PB-04", name: "Insider Threat Investigation", category: "Insider Threat", icon: "bi-person-exclamation",
        description: "Investigate suspicious internal activity while preserving chain of custody.",
        steps: ["Preserve relevant logs before access is revoked", "Coordinate with HR and Legal before action", "Review access and data movement history", "Suspend access if risk is confirmed", "Interview relevant stakeholders", "Document findings for potential legal action"] },
      { id: "PB-05", name: "DDoS Mitigation", category: "DDoS", icon: "bi-lightning-charge",
        description: "Restore service availability during a volumetric or application-layer attack.",
        steps: ["Confirm attack pattern via traffic analysis", "Engage upstream DDoS scrubbing provider", "Apply rate limiting and WAF rules", "Scale affected services if possible", "Monitor for attack pattern changes", "Conduct post-incident capacity review"] },
      { id: "PB-06", name: "Account Compromise Response", category: "Account Compromise", icon: "bi-key",
        description: "Regain control of a compromised account and assess downstream impact.",
        steps: ["Disable the compromised account immediately", "Review recent account activity and sessions", "Force credential and token rotation", "Enable/verify MFA on the account", "Review for lateral movement or data access", "Restore access with monitoring in place"] },
      { id: "PB-07", name: "Malware Outbreak Response", category: "Malware Outbreak", icon: "bi-bug",
        description: "Contain and eradicate malware spreading across multiple endpoints.",
        steps: ["Isolate affected endpoint segment", "Collect malware sample for analysis", "Identify indicators of compromise (IOCs)", "Deploy updated detection signatures", "Remediate and re-image affected endpoints", "Validate eradication before reconnecting"] },
      { id: "PB-08", name: "Cloud Misconfiguration Remediation", category: "Cloud Misconfiguration", icon: "bi-cloud-slash",
        description: "Close exposure from a misconfigured cloud resource and assess data access.",
        steps: ["Restrict public access on the affected resource", "Review access logs for unauthorized retrieval", "Rotate any exposed credentials or keys", "Apply least-privilege IAM policy corrections", "Enable configuration drift monitoring", "Document and share lessons learned"] },
    ];
  
    function renderGrid(list) {
      document.getElementById("playbookGrid").innerHTML = list.length ? list.map((pb) => `
        <div class="col-lg-4 col-md-6">
          <div class="playbook-card" data-id="${pb.id}" role="button">
            <div class="playbook-icon"><i class="bi ${pb.icon}"></i></div>
            <div>
              <h3 class="fs-inherit-md mb-1">${pb.name}</h3>
              <span class="badge badge-neutral">${pb.category}</span>
            </div>
            <p class="text-muted text-sm mb-0">${pb.description}</p>
            <div class="playbook-steps-count mt-auto"><i class="bi bi-list-check"></i> ${pb.steps.length} steps</div>
          </div>
        </div>`).join("")
        : `<div class="col-12"><div class="empty-state"><i class="bi bi-inbox"></i><h3>No playbooks found</h3><p>Try a different search term.</p></div></div>`;
  
      document.querySelectorAll(".playbook-card").forEach((card) => {
        card.addEventListener("click", () => openPlaybook(PLAYBOOKS.find((p) => p.id === card.dataset.id)));
      });
    }
    renderGrid(PLAYBOOKS);
  
    function openPlaybook(pb) {
      document.getElementById("pbModalTitle").textContent = pb.name;
      document.getElementById("pbModalDesc").textContent = pb.description;
      document.getElementById("pbModalSteps").innerHTML = pb.steps.map((s, i) => `
        <div class="playbook-step-row"><span class="playbook-step-num">${i + 1}</span><span class="text-sm">${s}</span></div>`).join("");
      window.xdrOpenModal("playbookModal");
    }
  
    document.getElementById("pbApplyBtn").addEventListener("click", () => {
      if (window.showToast) window.showToast({ type: "success", title: "Playbook applied", msg: "Steps added to the active incident checklist." });
    });
  
    document.getElementById("playbookSearch").addEventListener("input", (e) => {
      const q = e.target.value.trim().toLowerCase();
      renderGrid(!q ? PLAYBOOKS : PLAYBOOKS.filter((p) => p.name.toLowerCase().includes(q) || p.category.toLowerCase().includes(q)));
    });
  })();
  