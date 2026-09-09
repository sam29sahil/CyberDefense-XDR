/**
 * CyberDefense XDR
 * Audit Record Details Controller
 * Provides interactive utilities such as JSON payload copying and clipboard management.
 */

document.addEventListener("DOMContentLoaded", () => {
  const btnCopyJson = document.getElementById("btnCopyJson");
  const auditJsonPayload = document.getElementById("auditJsonPayload");

  if (btnCopyJson && auditJsonPayload) {
    btnCopyJson.addEventListener("click", async () => {
      const textToCopy = auditJsonPayload.innerText || auditJsonPayload.textContent;
      try {
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(textToCopy);
        } else {
          // Fallback
          const textArea = document.createElement("textarea");
          textArea.value = textToCopy;
          textArea.style.position = "fixed";
          textArea.style.left = "-999999px";
          textArea.style.top = "-999999px";
          document.body.appendChild(textArea);
          textArea.focus();
          textArea.select();
          document.execCommand("copy");
          textArea.remove();
        }

        const originalHtml = btnCopyJson.innerHTML;
        btnCopyJson.innerHTML = `<i class="bi bi-check2 text-success me-1"></i>Copied!`;
        btnCopyJson.classList.replace("btn-outline-primary", "btn-outline-success");

        if (typeof window.showToast === "function") {
          window.showToast("Event JSON copied to clipboard", "success");
        }

        setTimeout(() => {
          btnCopyJson.innerHTML = originalHtml;
          btnCopyJson.classList.replace("btn-outline-success", "btn-outline-primary");
        }, 2000);
      } catch (err) {
        console.error("Failed to copy JSON payload:", err);
        if (typeof window.showToast === "function") {
          window.showToast("Failed to copy JSON to clipboard", "danger");
        }
      }
    });
  }
});

