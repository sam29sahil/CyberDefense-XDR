/* ==========================================================================
   create-rule.js — page module for app/create-rule.html
   Handles both "create" mode (no ?id=) and "edit" mode (?id=DET-xxxx).
   Depends on: DETECTION_RULES_DATA (data/detection-rules-data.js)
   ========================================================================== */

   (function () {
    const MITRE = [
      ["T1059.001", "PowerShell"], ["T1110", "Brute Force"], ["T1046", "Network Service Discovery"],
      ["T1190", "Exploit Public-Facing Application"], ["T1055", "Process Injection"],
      ["T1003", "OS Credential Dumping"], ["T1021.001", "Remote Desktop Protocol"],
      ["T1567", "Exfiltration Over Web Service"], ["T1548", "Abuse Elevation Control Mechanism"],
      ["T1053.005", "Scheduled Task"], ["T1071.001", "Web Protocols"], ["T1486", "Data Encrypted for Impact"],
      ["T1078", "Valid Accounts"], ["T1136", "Create Account"],
    ];
    const FIELD_OPTIONS = ["event.category", "event.source", "event.severity", "event.host", "event.user", "process.name", "network.dst_port"];
    const OPERATOR_OPTIONS = ["==", "!=", "contains", ">=", "in"];
  
    const mitreSel = document.getElementById("ruleMitre");
    mitreSel.innerHTML = MITRE.map(([id, name]) => `<option value="${id}" data-name="${name}">${id} — ${name}</option>`).join("");
  
    const params = new URLSearchParams(window.location.search);
    const editId = params.get("id");
    const existing = editId ? DETECTION_RULES_DATA.find((r) => r.id === editId) : null;
  
    let conditions = [];
    let actions = [];
    let tags = [];
  
    if (existing) {
      document.getElementById("pageTitle").textContent = "Edit Rule";
      document.getElementById("breadcrumbMode").textContent = "Edit Rule";
      document.title = `Edit Rule — CyberDefense XDR`;
      document.getElementById("duplicateBtn").style.display = "";
      document.getElementById("ruleName").value = existing.name;
      document.getElementById("ruleDescription").value = existing.description;
      document.getElementById("ruleSeverity").value = existing.severity;
      document.getElementById("ruleCategory").value = existing.category;
      mitreSel.value = existing.mitreId;
      document.getElementById("ruleStatus").value = existing.status;
      conditions = existing.conditions.map(parseConditionString);
      actions = existing.actions.slice();
      tags = existing.tags.slice();
    } else {
      conditions = [{ field: "event.category", op: "==", value: "" }];
      actions = ["Create Alert"];
    }
  
    function parseConditionString(str) {
      const m = str.match(/^(\S+)\s+(==|!=|contains|>=|in)\s+(.*)$/);
      return m ? { field: m[1], op: m[2], value: m[3] } : { field: "event.category", op: "==", value: str };
    }
  
    // ---------- Conditions ----------
    function renderConditions() {
      document.getElementById("conditionsList").innerHTML = conditions.map((c, i) => `
        <div class="condition-row" data-idx="${i}">
          <select class="form-select cond-field">${FIELD_OPTIONS.map((f) => `<option ${f === c.field ? "selected" : ""}>${f}</option>`).join("")}</select>
          <select class="form-select cond-op">${OPERATOR_OPTIONS.map((o) => `<option ${o === c.op ? "selected" : ""}>${o}</option>`).join("")}</select>
          <input class="form-control cond-value" value="${XDRUtils.escapeHtml(c.value)}" placeholder="value">
          <button class="btn btn-icon btn-ghost btn-sm remove-cond" ${conditions.length === 1 ? "disabled" : ""}><i class="bi bi-trash"></i></button>
        </div>`).join("");
  
      document.querySelectorAll(".condition-row").forEach((rowEl) => {
        const idx = parseInt(rowEl.dataset.idx, 10);
        rowEl.querySelector(".cond-field").addEventListener("change", (e) => { conditions[idx].field = e.target.value; updateSummary(); });
        rowEl.querySelector(".cond-op").addEventListener("change", (e) => { conditions[idx].op = e.target.value; updateSummary(); });
        rowEl.querySelector(".cond-value").addEventListener("input", (e) => { conditions[idx].value = e.target.value; updateSummary(); });
        rowEl.querySelector(".remove-cond").addEventListener("click", () => {
          conditions.splice(idx, 1);
          renderConditions();
          updateSummary();
        });
      });
    }
    document.getElementById("addConditionBtn").addEventListener("click", () => {
      conditions.push({ field: FIELD_OPTIONS[0], op: "==", value: "" });
      renderConditions();
      updateSummary();
    });
    renderConditions();
  
    // ---------- Actions ----------
    document.querySelectorAll("#actionsGrid input[type=checkbox]").forEach((cb) => {
      cb.checked = actions.includes(cb.value);
      cb.addEventListener("change", () => {
        actions = [...document.querySelectorAll("#actionsGrid input:checked")].map((c) => c.value);
        updateSummary();
      });
    });
  
    // ---------- Tags ----------
    function renderTags() {
      document.getElementById("tagInputWrap").querySelectorAll(".chip").forEach((el) => el.remove());
      const input = document.getElementById("tagInput");
      tags.forEach((t) => {
        const chip = document.createElement("span");
        chip.className = "chip";
        chip.innerHTML = `${XDRUtils.escapeHtml(t)} <button type="button" aria-label="Remove tag"><i class="bi bi-x"></i></button>`;
        chip.querySelector("button").addEventListener("click", () => {
          tags = tags.filter((tg) => tg !== t);
          renderTags();
          updateSummary();
        });
        input.before(chip);
      });
    }
    document.getElementById("tagInput").addEventListener("keydown", (e) => {
      if (e.key === "Enter" && e.target.value.trim()) {
        e.preventDefault();
        const val = e.target.value.trim();
        if (!tags.includes(val)) tags.push(val);
        e.target.value = "";
        renderTags();
        updateSummary();
      }
    });
    renderTags();
  
    // ---------- Live summary ----------
    function updateSummary() {
      const sev = document.getElementById("ruleSeverity").value;
      document.getElementById("summarySeverity").innerHTML = XDRUtils.severityBadge(sev);
      document.getElementById("summaryCategory").textContent = document.getElementById("ruleCategory").value;
      const opt = mitreSel.options[mitreSel.selectedIndex];
      document.getElementById("summaryMitre").innerHTML = `<span class="mitre-chip">${mitreSel.value} <span class="tname">${opt?.dataset.name || ""}</span></span>`;
      document.getElementById("summaryConditions").textContent = `${conditions.length} defined`;
      document.getElementById("summaryActions").textContent = actions.length ? actions.join(", ") : "None selected";
    }
    document.getElementById("ruleSeverity").addEventListener("change", updateSummary);
    document.getElementById("ruleCategory").addEventListener("change", updateSummary);
    mitreSel.addEventListener("change", updateSummary);
    updateSummary();
  
    // ---------- Save / Duplicate ----------
    document.getElementById("saveRuleBtn").addEventListener("click", () => {
      const name = document.getElementById("ruleName").value.trim();
      if (!name) {
        if (window.showToast) window.showToast({ type: "warning", title: "Rule name required", msg: "Give this rule a descriptive name before saving." });
        document.getElementById("ruleName").focus();
        return;
      }
      if (window.showToast) {
        window.showToast({
          type: "success",
          title: existing ? "Rule updated" : "Rule created",
          msg: `"${name}" saved as ${document.getElementById("ruleStatus").value}.`,
        });
      }
      setTimeout(() => { window.location.href = "detection-rules.html"; }, 900);
    });
  
    document.getElementById("duplicateBtn").addEventListener("click", () => {
      if (window.showToast) window.showToast({ type: "success", title: "Rule duplicated", msg: "A copy has been created in Testing status." });
      setTimeout(() => { window.location.href = "detection-rules.html"; }, 900);
    });
  })();
  