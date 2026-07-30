/* ==========================================================================
   modal-helpers.js — lightweight open/close for .xdr-modal components
   Usage: <button data-modal-open="deleteAssetModal">
          <div class="xdr-modal-backdrop" data-modal-backdrop="deleteAssetModal">
          <div class="xdr-modal" id="deleteAssetModal">...<button data-modal-close>
   ========================================================================== */

   (function () {
    function openModal(id) {
      document.querySelector(`[data-modal-backdrop="${id}"]`)?.classList.add("show");
      document.getElementById(id)?.classList.add("show");
      document.body.style.overflow = "hidden";
    }
    function closeModal(id) {
      document.querySelector(`[data-modal-backdrop="${id}"]`)?.classList.remove("show");
      document.getElementById(id)?.classList.remove("show");
      document.body.style.overflow = "";
    }
    window.xdrOpenModal = openModal;
    window.xdrCloseModal = closeModal;
  
    document.addEventListener("click", (e) => {
      const openTrigger = e.target.closest("[data-modal-open]");
      if (openTrigger) openModal(openTrigger.dataset.modalOpen);
  
      const closeTrigger = e.target.closest("[data-modal-close]");
      if (closeTrigger) {
        const modal = closeTrigger.closest(".xdr-modal");
        if (modal) closeModal(modal.id);
      }
  
      if (e.target.classList.contains("xdr-modal-backdrop")) {
        const id = e.target.dataset.modalBackdrop;
        if (id) closeModal(id);
      }
    });
  
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        document.querySelectorAll(".xdr-modal.show").forEach(m => closeModal(m.id));
      }
    });
  })();
  