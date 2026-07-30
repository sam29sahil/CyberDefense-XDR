/* ==========================================================================
   scheduled-reports.js — page module for app/scheduled-reports.html
   Depends on: SCHEDULED_REPORTS_DATA (data/reports-data.js), modal-helpers.js
   ========================================================================== */

   (function () {
    let data = SCHEDULED_REPORTS_DATA.map((s) => ({ ...s }));
  
    function renderSummary() {
      document.getElementById("schedSummary").textContent = `${data.length} schedules · ${data.filter((s) => s.status === "active").length} active`;
    }
  
    function render() {
      document.getElementById("scheduleBody").innerHTML = data.map((s) => `
        <tr>
          <td style="font-weight:600;">${s.name}<div class="text-xs text-muted">Owner: ${s.owner}</div></td>
          <td>${s.frequency}</td>
          <td><span class="format-chip">${s.format}</span></td>
          <td class="text-sm">${s.recipients.length} recipient${s.recipients.length === 1 ? "" : "s"}</td>
          <td class="text-sm">${XDRUtils.formatTime(s.nextRun)}</td>
          <td><span class="sched-status-dot ${s.status}"></span> ${s.status[0].toUpperCase() + s.status.slice(1)}</td>
          <td><div class="row-actions">
            <button class="btn btn-icon btn-ghost btn-sm toggle-btn" data-id="${s.id}" title="${s.status === "paused" ? "Resume" : "Pause"}"><i class="bi bi-${s.status === "paused" ? "play-fill" : "pause-fill"}"></i></button>
            <button class="btn btn-icon btn-ghost btn-sm delete-btn" data-id="${s.id}" title="Delete"><i class="bi bi-trash"></i></button>
          </div></td>
        </tr>`).join("");
  
      document.querySelectorAll(".toggle-btn").forEach((btn) => btn.addEventListener("click", () => {
        const s = data.find((x) => x.id === btn.dataset.id);
        s.status = s.status === "paused" ? "active" : "paused";
        render();
        renderSummary();
        if (window.showToast) window.showToast({ type: "info", title: s.status === "paused" ? "Schedule paused" : "Schedule resumed", msg: s.name });
      }));
      document.querySelectorAll(".delete-btn").forEach((btn) => btn.addEventListener("click", () => {
        const s = data.find((x) => x.id === btn.dataset.id);
        document.getElementById("deleteSchedName").textContent = s.name;
        document.getElementById("confirmDeleteSchedBtn").dataset.id = s.id;
        window.xdrOpenModal("deleteScheduleModal");
      }));
    }
  
    document.getElementById("confirmDeleteSchedBtn").addEventListener("click", () => {
      const id = document.getElementById("confirmDeleteSchedBtn").dataset.id;
      const s = data.find((x) => x.id === id);
      data = data.filter((x) => x.id !== id);
      render();
      renderSummary();
      if (window.showToast && s) window.showToast({ type: "danger", title: "Schedule deleted", msg: s.name });
    });
  
    document.getElementById("addScheduleConfirm").addEventListener("click", () => {
      const type = document.getElementById("newSchedType").value;
      const freq = document.getElementById("newSchedFreq").value;
      const format = document.getElementById("newSchedFormat").value;
      const recipientsRaw = document.getElementById("newSchedRecipients").value.trim();
      const recipients = recipientsRaw ? recipientsRaw.split(",").map((r) => r.trim()).filter(Boolean) : ["soc-team@cyberdefensexdr.io"];
      const now = new Date();
      const deltaDays = { Daily: 1, Weekly: 7, "Bi-weekly": 14, Monthly: 30, Quarterly: 90 }[freq];
      const next = new Date(now.getTime() + deltaDays * 86400000);
      data.unshift({
        id: `SCH-${Math.floor(Math.random() * 900 + 100)}`,
        name: `${type} — ${freq}`, type, frequency: freq, format, recipients,
        lastRun: now.toISOString(), nextRun: next.toISOString(), status: "active", owner: "Aria Reyes",
      });
      document.getElementById("newSchedRecipients").value = "";
      render();
      renderSummary();
      if (window.showToast) window.showToast({ type: "success", title: "Schedule created", msg: `${type} — ${freq}` });
    });
  
    renderSummary();
    render();
  })();
  