/* ==========================================================================
   log-explorer.js — page module for app/log-explorer.html
   Depends on: LOGS_DATA (data/logs-data.js), SAVED_SEARCHES_DATA,
   XDRTable (core/datatable.js), XDRUtils (app.js)
   ========================================================================== */

   (function () {
    const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
  
    // Populate source / host / tag filter dropdowns from the dataset
    const sources = [...new Set(LOGS_DATA.map((r) => r.source))].sort();
    const hosts = [...new Set(LOGS_DATA.map((r) => r.host))].sort();
    const tags = [...new Set(LOGS_DATA.flatMap((r) => r.tags))].sort();
  
    const sourceSel = document.getElementById("filterSource");
    sources.forEach((s) => sourceSel.insertAdjacentHTML("beforeend", `<option value="${s}">${s}</option>`));
    const hostSel = document.getElementById("filterHost");
    hosts.forEach((h) => hostSel.insertAdjacentHTML("beforeend", `<option value="${h}">${h}</option>`));
    const tagSel = document.getElementById("filterTag");
    tags.forEach((t) => tagSel.insertAdjacentHTML("beforeend", `<option value="${t}">${t}</option>`));
  
    const columns = [
      { key: "ts", label: "Timestamp", sortable: true,
        render: (r) => `<span class="cell-mono">${r.ts.replace("T", " ").replace("Z", "")}</span>` },
      { key: "sev", label: "Severity", sortable: true, render: (r) => XDRUtils.severityBadge(r.sev) },
      { key: "host", label: "Hostname", sortable: true,
        render: (r) => `<span style="font-weight:600;">${r.host}</span>` },
      { key: "source", label: "Source", sortable: true, render: (r) => `<span class="text-sm">${r.source}</span>` },
      { key: "message", label: "Message", sortable: false,
        render: (r) => `<div class="log-msg-cell"><span class="msg-text">${XDRUtils.escapeHtml(r.message)}</span></div>` },
      { key: "actions", label: "", sortable: false,
        render: (r) => `<div class="row-actions">
            <a href="log-details.html?id=${r.id}" class="btn btn-icon btn-ghost btn-sm" title="View details"><i class="bi bi-eye"></i></a>
          </div>` },
    ];
  
    const table = new XDRTable({
      tableEl: document.getElementById("logsTable"),
      searchInput: document.getElementById("logSearch"),
      paginationEl: document.getElementById("logsPagination"),
      data: LOGS_DATA,
      pageSize: 10,
      searchKeys: ["message", "host", "source", "id"],
      columns,
    });
    table.state.sortKey = "ts";
    table.state.sortDir = -1;
  
    function currentFilters() {
      return {
        sev: document.getElementById("filterSev").value,
        source: document.getElementById("filterSource").value,
        host: document.getElementById("filterHost").value,
        category: document.getElementById("filterCategory").value,
        timeRange: document.getElementById("filterTimeRange").value,
        tag: document.getElementById("filterTag").value,
        query: document.getElementById("logSearch").value.trim(),
      };
    }
  
    function applyFilters() {
      const f = currentFilters();
      const cutoff = f.timeRange ? Date.now() - parseInt(f.timeRange, 10) * 60000 : null;
      table.setFilter((row) =>
        (!f.sev || row.sev === f.sev) &&
        (!f.source || row.source === f.source) &&
        (!f.host || row.host === f.host) &&
        (!f.category || row.category === f.category) &&
        (!f.tag || row.tags.includes(f.tag)) &&
        (!cutoff || new Date(row.ts).getTime() >= cutoff)
      );
      document.getElementById("saveSearchQuery").value = buildQueryString(f);
    }
  
    function buildQueryString(f) {
      const parts = [];
      if (f.sev) parts.push(`sev:${f.sev}`);
      if (f.source) parts.push(`source:"${f.source}"`);
      if (f.host) parts.push(`host:${f.host}`);
      if (f.category) parts.push(`category:${f.category}`);
      if (f.tag) parts.push(`tags:${f.tag}`);
      if (f.timeRange) parts.push(`ts:[now-${f.timeRange}m TO now]`);
      if (f.query) parts.push(`message:"${f.query}"`);
      return parts.length ? parts.join(" AND ") : "*:*";
    }
  
    ["filterSev", "filterSource", "filterHost", "filterCategory", "filterTimeRange", "filterTag"]
      .forEach((id) => document.getElementById(id).addEventListener("change", applyFilters));
    document.getElementById("logSearch").addEventListener("input", () => document.getElementById("saveSearchQuery").value = buildQueryString(currentFilters()));
  
    document.getElementById("advFilterToggle").addEventListener("click", () => {
      document.getElementById("filtersDrawer").classList.toggle("show");
    });
  
    document.getElementById("clearFilters").addEventListener("click", () => {
      document.getElementById("logSearch").value = "";
      ["filterSev", "filterSource", "filterHost", "filterCategory", "filterTimeRange", "filterTag"]
        .forEach((id) => document.getElementById(id).value = "");
      table.state.query = "";
      table.setFilter(null);
      document.getElementById("saveSearchQuery").value = "*:*";
    });
  
    document.getElementById("saveSearchQuery").value = "*:*";
  
    // ---------- Live pause/resume ----------
    const liveIndicator = document.getElementById("liveIndicator");
    const toggleLiveBtn = document.getElementById("toggleLiveBtn");
    let isLive = true;
    toggleLiveBtn.addEventListener("click", () => {
      isLive = !isLive;
      liveIndicator.classList.toggle("is-live", isLive);
      toggleLiveBtn.innerHTML = isLive
        ? `<i class="bi bi-pause-fill"></i> Pause`
        : `<i class="bi bi-play-fill"></i> Resume`;
      if (window.showToast) {
        window.showToast({ type: "info", title: isLive ? "Live tailing resumed" : "Live tailing paused" });
      }
    });
  
    // ---------- Export (CSV, current filtered view) ----------
    document.getElementById("exportBtn").addEventListener("click", () => {
      const rows = LOGS_DATA;
      const header = "id,ts,sev,host,source,category,message\n";
      const body = rows.map((r) =>
        [r.id, r.ts, r.sev, r.host, r.source, r.category, `"${r.message.replace(/"/g, '""')}"`].join(",")
      ).join("\n");
      const blob = new Blob([header + body], { type: "text/csv" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = "siem-log-export.csv";
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
      if (window.showToast) window.showToast({ type: "success", title: "Export ready", msg: "siem-log-export.csv downloaded." });
    });
  
    // ---------- Save search ----------
    document.getElementById("saveSearchConfirm").addEventListener("click", () => {
      const name = document.getElementById("saveSearchName").value.trim();
      if (window.showToast) {
        window.showToast({
          type: "success",
          title: "Search saved",
          msg: name ? `"${name}" added to Saved Searches.` : "Search added to Saved Searches.",
        });
      }
      document.getElementById("saveSearchName").value = "";
    });
  })();
  