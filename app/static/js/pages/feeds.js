/* ==========================================================================
   feeds.js — page module for app/feeds.html
   Depends on: FEEDS_DATA (data/threat-data.js)
   ========================================================================== */

   (function () {
    let data = FEEDS_DATA.map((f) => ({ ...f }));
  
    function renderSummary() {
      document.getElementById("feedCountSummary").textContent =
        `${data.length} feeds · ${data.filter((f) => f.status === "active").length} active`;
    }
  
    function render() {
      document.getElementById("feedsBody").innerHTML = data.map((f) => `
        <tr>
          <td style="font-weight:600;">${f.name}</td>
          <td class="text-muted">${f.provider}</td>
          <td><span class="badge badge-neutral">${f.type}</span></td>
          <td><span class="feed-status-dot ${f.status}"></span> ${f.status[0].toUpperCase() + f.status.slice(1)}</td>
          <td class="cell-mono">${f.iocCount.toLocaleString()}</td>
          <td class="text-sm text-muted">${XDRUtils.formatTime(f.lastSync)}</td>
          <td class="text-sm">${f.reliability}</td>
          <td><div class="row-actions">
            <button class="btn btn-icon btn-ghost btn-sm sync-btn" data-id="${f.id}" title="Sync now"><i class="bi bi-arrow-repeat"></i></button>
            <button class="btn btn-icon btn-ghost btn-sm toggle-btn" data-id="${f.id}" title="${f.status === "paused" ? "Resume" : "Pause"}"><i class="bi bi-${f.status === "paused" ? "play-fill" : "pause-fill"}"></i></button>
          </div></td>
        </tr>`).join("");
  
      document.querySelectorAll(".sync-btn").forEach((btn) => btn.addEventListener("click", () => {
        const f = data.find((x) => x.id === btn.dataset.id);
        f.lastSync = new Date().toISOString();
        render();
        if (window.showToast) window.showToast({ type: "success", title: "Feed synced", msg: f.name });
      }));
      document.querySelectorAll(".toggle-btn").forEach((btn) => btn.addEventListener("click", () => {
        const f = data.find((x) => x.id === btn.dataset.id);
        f.status = f.status === "paused" ? "active" : "paused";
        render();
        if (window.showToast) window.showToast({ type: "info", title: f.status === "paused" ? "Feed paused" : "Feed resumed", msg: f.name });
      }));
    }
  
    document.getElementById("addFeedConfirm").addEventListener("click", () => {
      const name = document.getElementById("newFeedName").value.trim();
      if (!name) {
        if (window.showToast) window.showToast({ type: "warning", title: "Feed name required" });
        return;
      }
      data.unshift({
        id: `FEED-${Math.floor(Math.random() * 900 + 100)}`, name,
        provider: document.getElementById("newFeedProvider").value.trim() || "Unknown",
        type: document.getElementById("newFeedType").value,
        status: "active", iocCount: 0, lastSync: new Date().toISOString(), reliability: "B - Usually reliable",
      });
      document.getElementById("newFeedName").value = "";
      document.getElementById("newFeedProvider").value = "";
      renderSummary();
      render();
      if (window.showToast) window.showToast({ type: "success", title: "Feed added", msg: name });
    });
  
    renderSummary();
    render();
  })();
  