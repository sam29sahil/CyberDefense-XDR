/**
 * CyberDefense XDR
 * Notification Details Controller
 */

(function () {
  const btnDismiss = document.getElementById("btnDismissNotif");
  if (btnDismiss) {
    btnDismiss.addEventListener("click", async () => {
      const notifId = btnDismiss.getAttribute("data-id");
      if (!notifId) return;

      if (confirm("Are you sure you want to dismiss this notification?")) {
        try {
          const res = await fetch(`/notifications/api/${notifId}/dismiss`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
          });
          if (res.ok) {
            window.location.href = "/notifications/";
          } else {
            alert("Failed to dismiss notification.");
          }
        } catch (e) {
          console.error("Error dismissing notification:", e);
        }
      }
    });
  }
})();

