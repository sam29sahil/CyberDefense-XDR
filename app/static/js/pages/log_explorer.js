/* ==========================================================================
   log-explorer.js — page module for app/templates/siem/log_explorer.html
   Integrates with backend /siem/api/logs and /siem/api/saved-searches.
   ========================================================================== */

(function () {
  const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
  let logsDataset = typeof LOGS_DATA !== "undefined" ? LOGS_DATA.slice() : [];

  const columns = [
    {
      key: "ts",
      label: "Timestamp",
      sortable: true,
      render: (r) => `<span class="cell-mono">${r.ts ? r.ts.replace("T", " ").replace("Z", "") : "—"}</span>`,
    },
    {
      key: "sev",
      label: "Severity",
      sortable: true,
      render: (r) => XDRUtils.severityBadge(r.sev),
    },
    {
      key: "host",
      label: "Hostname",
      sortable: true,
      render: (r) => `<span style="font-weight:600;">${XDRUtils.escapeHtml(r.host || "—")}</span>`,
    },
    {
      key: "source",
      label: "Source",
      sortable: true,
      render: (r) => `<span class="text-sm">${XDRUtils.escapeHtml(r.source || "—")}</span>`,
    },
    {
      key: "message",
      label: "Message",
      sortable: false,
      render: (r) => `<div class="log-msg-cell"><span class="msg-text">${XDRUtils.escapeHtml(r.message || "")}</span></div>`,
    },
    {
      key: "actions",
      label: "",
      sortable: false,
      render: (r) => `<div class="row-actions">
          <a href="/siem/log-details?id=${r.id}" class="btn btn-icon btn-ghost btn-sm" title="View details"><i class="bi bi-eye"></i></a>
        </div>`,
    },
  ];

  const table = new XDRTable({
    tableEl: document.getElementById("logsTable"),
    searchInput: document.getElementById("logSearch"),
    paginationEl: document.getElementById("logsPagination"),
    data: logsDataset,
    pageSize: 10,
    searchKeys: ["message", "host", "source", "id"],
    columns,
  });
  table.state.sortKey = "ts";
  table.state.sortDir = -1;

  function populateFilterDropdowns(options) {
    if (!options) return;
    const sourceSel = document.getElementById("filterSource");
    const hostSel = document.getElementById("filterHost");
    const tagSel = document.getElementById("filterTag");

    if (sourceSel && options.sources) {
      options.sources.forEach((s) => {
        if (!sourceSel.querySelector(`option[value="${s}"]`)) {
          sourceSel.insertAdjacentHTML("beforeend", `<option value="${s}">${s}</option>`);
        }
      });
    }
    if (hostSel && options.hosts) {
      options.hosts.forEach((h) => {
        if (!hostSel.querySelector(`option[value="${h}"]`)) {
          hostSel.insertAdjacentHTML("beforeend", `<option value="${h}">${h}</option>`);
        }
      });
    }
    if (tagSel && options.tags) {
      options.tags.forEach((t) => {
        if (!tagSel.querySelector(`option[value="${t}"]`)) {
          tagSel.insertAdjacentHTML("beforeend", `<option value="${t}">${t}</option>`);
        }
      });
    }
  }

  function currentFilters() {
    return {
      sev: document.getElementById("filterSev")?.value || "",
      source: document.getElementById("filterSource")?.value || "",
      host: document.getElementById("filterHost")?.value || "",
      category: document.getElementById("filterCategory")?.value || "",
      timeRange: document.getElementById("filterTimeRange")?.value || "",
      tag: document.getElementById("filterTag")?.value || "",
      query: document.getElementById("logSearch")?.value.trim() || "",
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
      (!f.tag || (row.tags && row.tags.includes(f.tag))) &&
      (!cutoff || new Date(row.ts).getTime() >= cutoff)
    );
    const qEl = document.getElementById("saveSearchQuery");
    if (qEl) qEl.value = buildQueryString(f);
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
    .forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.addEventListener("change", applyFilters);
    });

  const searchInput = document.getElementById("logSearch");
  if (searchInput) {
    searchInput.addEventListener("input", () => {
      const qEl = document.getElementById("saveSearchQuery");
      if (qEl) qEl.value = buildQueryString(currentFilters());
    });
  }

  const advToggle = document.getElementById("advFilterToggle");
  if (advToggle) {
    advToggle.addEventListener("click", () => {
      document.getElementById("filtersDrawer")?.classList.toggle("show");
    });
  }

  const clearBtn = document.getElementById("clearFilters");
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      if (searchInput) searchInput.value = "";
      ["filterSev", "filterSource", "filterHost", "filterCategory", "filterTimeRange", "filterTag"]
        .forEach((id) => {
          const el = document.getElementById(id);
          if (el) el.value = "";
        });
      table.state.query = "";
      table.setFilter(null);
      const qEl = document.getElementById("saveSearchQuery");
      if (qEl) qEl.value = "*:*";
    });
  }

  // Load from backend API
  function loadBackendData() {
    // 1. Load Filter options
    fetch("/siem/api/logs/filter-options")
      .then((res) => res.json())
      .then((payload) => {
        if (payload && payload.success && payload.data) {
          populateFilterDropdowns(payload.data);
        }
      })
      .catch((e) => console.warn("Filter options load failed:", e));

    // 2. Load Logs
    fetch("/siem/api/logs?limit=250")
      .then((res) => res.json())
      .then((payload) => {
        if (payload && payload.success && Array.isArray(payload.data) && payload.data.length > 0) {
          logsDataset = payload.data;
          table.data = logsDataset;
          table.render();

          const subEl = document.getElementById("logExplorerSubtitle");
          if (subEl) {
            subEl.textContent = `${payload.pagination.total.toLocaleString()} events indexed · last 24 hours`;
          }

          // Check URL query parameters (e.g. ?host=... or ?query=...)
          const params = new URLSearchParams(window.location.search);
          const hostParam = params.get("host");
          const queryParam = params.get("query");
          if (hostParam) {
            const hEl = document.getElementById("filterHost");
            if (hEl) {
              hEl.value = hostParam;
              document.getElementById("filtersDrawer")?.classList.add("show");
              applyFilters();
            }
          } else if (queryParam) {
            if (searchInput) {
              searchInput.value = queryParam;
              table.state.query = queryParam;
              table.render();
            }
          }
        }
      })
      .catch((e) => console.warn("Backend logs load failed:", e));
  }

  loadBackendData();

  // ---------- Live pause/resume ----------
  const liveIndicator = document.getElementById("liveIndicator");
  const toggleLiveBtn = document.getElementById("toggleLiveBtn");
  let isLive = true;
  if (toggleLiveBtn && liveIndicator) {
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
  }

  // ---------- Export (CSV) ----------
  const exportBtn = document.getElementById("exportBtn");
  if (exportBtn) {
    exportBtn.addEventListener("click", () => {
      const rows = table.filteredData || logsDataset;
      const header = "id,ts,sev,host,source,category,message\n";
      const body = rows.map((r) =>
        [r.id, r.ts, r.sev, r.host, r.source, r.category, `"${(r.message || "").replace(/"/g, '""')}"`].join(",")
      ).join("\n");
      const blob = new Blob([header + body], { type: "text/csv" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = "siem-log-export.csv";
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
      if (window.showToast) window.showToast({ type: "success", title: "Export ready", msg: "siem-log-export.csv downloaded." });
    });
  }

  // ---------- Save search via API ----------
  const saveConfirm = document.getElementById("saveSearchConfirm");
  if (saveConfirm) {
    saveConfirm.addEventListener("click", () => {
      const name = document.getElementById("saveSearchName")?.value.trim();
      const query = document.getElementById("saveSearchQuery")?.value || "*:*";
      const alerting = document.getElementById("saveSearchAlert")?.checked || false;
      const pinned = document.getElementById("saveSearchPin")?.checked || false;

      if (!name) {
        if (window.showToast) window.showToast({ type: "warning", title: "Search name required" });
        return;
      }

      fetch("/siem/api/saved-searches", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name,
          query,
          alerting,
          pinned,
          filters: currentFilters(),
        }),
      })
        .then((res) => res.json())
        .then((resp) => {
          if (resp.success) {
            if (window.showToast) {
              window.showToast({
                type: "success",
                title: "Search saved",
                msg: `"${name}" added to Saved Searches.`,
              });
            }
          }
        })
        .catch((e) => {
          if (window.showToast) {
            window.showToast({ type: "danger", title: "Error saving search" });
          }
        });

      const nameEl = document.getElementById("saveSearchName");
      if (nameEl) nameEl.value = "";
    });
  }
})();