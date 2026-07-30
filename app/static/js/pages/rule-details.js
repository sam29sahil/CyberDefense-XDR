/* ==========================================================================
   rule-details.js — page module for app/rule-details.html
   Depends on: DETECTION_RULES_DATA, DETECTION_HISTORY_DATA,
   XDR_CHART_DEFAULTS, XDR_PALETTE, xdrGradient
   ========================================================================== */

   (function () {
    const STATUS_LABEL = { active: "Active", disabled: "Disabled", testing: "Testing" };
  
    const params = new URLSearchParams(window.location.search);
    const id = params.get("id");
    const rule = DETECTION_RULES_DATA.find((r) => r.id === id) || DETECTION_RULES_DATA[0];
  
    document.getElementById("breadcrumbRuleId").textContent = rule.name;
    document.getElementById("ruleName").textContent = rule.name;
    document.getElementById("ruleDesc").textContent = rule.description;
    document.getElementById("ruleSevBadge").innerHTML = XDRUtils.severityBadge(rule.severity);
    document.getElementById("ruleStatusPill").innerHTML = `<span class="status-pill st-${rule.status}"><span class="dot"></span>${STATUS_LABEL[rule.status]}</span>`;
    document.getElementById("ruleTagsRow").innerHTML = rule.tags.map((t) => `<span class="badge badge-neutral">${t}</span>`).join("")
      + `<span class="mitre-chip">${rule.mitreId} <span class="tname">${rule.mitreName}</span></span>`;
  
    document.getElementById("statTriggers").textContent = rule.triggers30d;
    document.getElementById("statFpRate").textContent = `${Math.round(rule.falsePositiveRate * 100)}%`;
    document.getElementById("statMitre").textContent = rule.mitreId;
    document.getElementById("statAuthor").textContent = rule.author;
  
    document.getElementById("fpRateLabel").textContent = `${Math.round(rule.falsePositiveRate * 100)}%`;
    document.getElementById("fpMeterFill").style.width = `${Math.round(rule.falsePositiveRate * 100)}%`;
    document.getElementById("statCreated").textContent = XDRUtils.formatTime(rule.createdAt);
    document.getElementById("statModified").textContent = XDRUtils.formatTime(rule.modifiedAt);
    document.getElementById("statCategory").textContent = rule.category;
    document.getElementById("statSource").textContent = rule.source;
  
    document.getElementById("conditionsView").innerHTML = rule.conditions.map((c) => `<div class="log-raw-panel mb-2" style="padding:8px 12px;">${XDRUtils.escapeHtml(c)}</div>`).join("");
    document.getElementById("actionsView").innerHTML = rule.actions.map((a) => `<div class="action-check" style="cursor:default;margin-bottom:8px;"><i class="bi bi-check-circle-fill text-success"></i> ${a}</div>`).join("");
  
    // ---------- Trigger history chart (14 days for this rule) ----------
    const events = DETECTION_HISTORY_DATA.filter((h) => h.ruleId === rule.id);
    const days = [];
    const now = new Date("2026-07-24T09:58:00Z");
    for (let i = 13; i >= 0; i--) days.push(new Date(now.getTime() - i * 86400000).toISOString().slice(0, 10));
    const counts = days.map((day) => events.filter((e) => e.ts.startsWith(day)).length);
  
    const ctx = document.getElementById("triggerHistoryChart").getContext("2d");
    new Chart(ctx, {
      type: "bar",
      data: {
        labels: days.map((d) => d.slice(5)),
        datasets: [{ label: "Triggers", data: counts, backgroundColor: XDR_PALETTE.severity[rule.severity], borderRadius: 3 }],
      },
      options: XDR_CHART_DEFAULTS,
    });
  
    // ---------- Timeline ----------
    const timelineEvents = [
      { ts: rule.createdAt, label: `Rule created by ${rule.author}`, sev: "info" },
      ...(rule.modifiedAt !== rule.createdAt ? [{ ts: rule.modifiedAt, label: "Rule conditions modified", sev: "low" }] : []),
      ...events.slice(0, 8).map((e) => ({ ts: e.ts, label: `Triggered on ${e.host} via ${e.source}`, sev: e.severity })),
    ].sort((a, b) => new Date(b.ts) - new Date(a.ts));
  
    document.getElementById("ruleTimeline").innerHTML = timelineEvents.length
      ? timelineEvents.map((t) => `
          <div class="timeline-item sev-${t.sev}">
            <div class="timeline-time">${XDRUtils.formatTime(t.ts)}</div>
            <strong>${XDRUtils.escapeHtml(t.label)}</strong>
          </div>`).join("")
      : `<div class="empty-state"><i class="bi bi-inbox"></i><h3>No timeline events</h3><p>This rule has no recorded activity yet.</p></div>`;
  
    // ---------- Recent matches ----------
    const recent = events.slice().sort((a, b) => new Date(b.ts) - new Date(a.ts)).slice(0, 12);
    document.getElementById("recentMatchesBody").innerHTML = recent.length
      ? recent.map((e) => `
          <tr>
            <td><span class="cell-mono">${e.ts.replace("T", " ").replace("Z", "")}</span></td>
            <td style="font-weight:600;">${e.host}</td>
            <td>${e.source}</td>
            <td><span class="badge ${e.status === "resolved" ? "badge-success" : e.status === "false_positive" ? "badge-neutral" : e.status === "investigating" ? "badge-warning" : "badge-info"}">${e.status.replace("_", " ")}</span></td>
          </tr>`).join("")
      : `<tr><td colspan="4"><div class="empty-state"><i class="bi bi-inbox"></i><h3>No matches yet</h3><p>This rule hasn't triggered on any events in the current dataset.</p></div></td></tr>`;
  
    // ---------- Tabs ----------
    const tabs = document.querySelectorAll(".xdr-tab");
    const panels = { def: document.getElementById("tabDef"), timeline: document.getElementById("tabTimeline"), matches: document.getElementById("tabMatches") };
    tabs.forEach((tab) => tab.addEventListener("click", () => {
      tabs.forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      Object.values(panels).forEach((p) => p.classList.add("d-none"));
      panels[tab.dataset.tab].classList.remove("d-none");
    }));
  
    // ---------- Actions ----------
    document.getElementById("editRuleBtn").href = `create-rule.html?id=${rule.id}`;
    document.getElementById("toggleStatusBtn").innerHTML = rule.status === "disabled"
      ? `<i class="bi bi-power"></i> Enable Rule` : `<i class="bi bi-power"></i> Disable Rule`;
    document.getElementById("toggleStatusBtn").addEventListener("click", () => {
      const nowDisabled = rule.status !== "disabled";
      rule.status = nowDisabled ? "disabled" : "active";
      document.getElementById("ruleStatusPill").innerHTML = `<span class="status-pill st-${rule.status}"><span class="dot"></span>${STATUS_LABEL[rule.status]}</span>`;
      document.getElementById("toggleStatusBtn").innerHTML = rule.status === "disabled" ? `<i class="bi bi-power"></i> Enable Rule` : `<i class="bi bi-power"></i> Disable Rule`;
      if (window.showToast) window.showToast({ type: nowDisabled ? "warning" : "success", title: nowDisabled ? "Rule disabled" : "Rule enabled", msg: rule.name });
    });
    document.getElementById("duplicateRuleBtn").addEventListener("click", () => {
      if (window.showToast) window.showToast({ type: "success", title: "Rule duplicated", msg: `A copy of "${rule.name}" was created in Testing status.` });
    });
  })();
  