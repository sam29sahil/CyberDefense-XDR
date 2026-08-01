/* ==========================================================================
   notification-settings.js — page module for app/notification-settings.html
   ========================================================================== */

   (function () {
    const CATEGORIES = [
      { name: "Critical Alerts", email: true, slack: true, sms: true },
      { name: "New Incidents", email: true, slack: true, sms: false },
      { name: "Scan Completed", email: true, slack: false, sms: false },
      { name: "Report Ready", email: true, slack: false, sms: false },
      { name: "System Health", email: false, slack: true, sms: false },
      { name: "User Management Changes", email: true, slack: false, sms: false },
    ];
  
    document.getElementById("notifyMatrixBody").innerHTML = CATEGORIES.map((c) => `
      <tr>
        <td>${c.name}</td>
        <td><input type="checkbox" class="perm-check" ${c.email ? "checked" : ""}></td>
        <td><input type="checkbox" class="perm-check" ${c.slack ? "checked" : ""}></td>
        <td><input type="checkbox" class="perm-check" ${c.sms ? "checked" : ""}></td>
      </tr>`).join("");
  
    document.getElementById("saveBtn").addEventListener("click", () => {
      if (window.showToast) window.showToast({ type: "success", title: "Notification preferences saved" });
    });
  })();
  