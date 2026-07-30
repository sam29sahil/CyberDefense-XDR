/* ==========================================================================
   log-details.js — page module for app/log-details.html
   Reads ?id=LOG-XXXXXX from the URL and populates the page from LOGS_DATA.
   Falls back to the most recent log when no match is found.
   ========================================================================== */

   (function () {
    const CATEGORY_ICON = {
      Network: "bi-diagram-3", Endpoint: "bi-pc-display", Cloud: "bi-cloud",
      Identity: "bi-person-badge", Application: "bi-window", Correlation: "bi-cpu",
    };
  
    const params = new URLSearchParams(window.location.search);
    const id = params.get("id");
    const sorted = LOGS_DATA.slice().sort((a, b) => new Date(b.ts) - new Date(a.ts));
    const log = LOGS_DATA.find((r) => r.id === id) || sorted[0];
  
    document.getElementById("logId").textContent = log.id;
    document.getElementById("breadcrumbLogId").textContent = log.id;
    document.getElementById("logSevBadge").innerHTML = XDRUtils.severityBadge(log.sev);
    document.getElementById("logMeta").textContent = `${log.ts.replace("T", " ").replace("Z", " UTC")} · ${log.source}`;
    document.getElementById("logSevIcon").innerHTML = `<i class="bi ${CATEGORY_ICON[log.category] || "bi-file-earmark-text"}"></i>`;
    document.getElementById("logTags").innerHTML = log.tags.map((t) => `<span class="badge badge-neutral">${t}</span>`).join("") || `<span class="text-muted text-sm">No tags</span>`;
  
    document.getElementById("statHost").textContent = log.host;
    document.getElementById("statSource").textContent = log.source;
    document.getElementById("statCategory").textContent = log.category;
  
    document.getElementById("rawLogText").textContent = log.raw;
  
    document.getElementById("parsedFieldsList").innerHTML = Object.entries(log.fields).map(([k, v]) => `
      <div class="info-row"><span class="text-muted cell-mono">${k}</span><span class="cell-mono">${v}</span></div>`).join("");
  
    function syntaxHighlightJson(obj) {
      const json = JSON.stringify(obj, null, 2);
      return XDRUtils.escapeHtml(json)
        .replace(/"([^"]+)":/g, '<span class="jk">"$1"</span>:')
        .replace(/: (".*?")/g, ': <span class="jv">$1</span>')
        .replace(/: (\d+)/g, ': <span class="jv">$1</span>');
    }
    document.getElementById("jsonPanel").innerHTML = syntaxHighlightJson({
      id: log.id, ts: log.ts, sev: log.sev, host: log.host,
      source: log.source, category: log.category, message: log.message,
      tags: log.tags, fields: log.fields,
    });
  
    document.getElementById("ctxTs").textContent = log.ts;
    document.getElementById("ctxId").textContent = log.id;
    document.getElementById("ctxSource").textContent = log.source;
    document.getElementById("ctxCategory").textContent = log.category;
    document.getElementById("ctxTags").textContent = log.tags.join(", ") || "—";
  
    // Related events — same host, excluding this log, most recent first
    const related = sorted.filter((r) => r.host === log.host && r.id !== log.id).slice(0, 6);
    document.getElementById("relatedTimeline").innerHTML = related.length
      ? related.map((r) => `
          <div class="timeline-item sev-${r.sev}">
            <div class="timeline-time">${r.ts.slice(11, 19)} UTC</div>
            <strong><a href="log-details.html?id=${r.id}" style="color:var(--text);">${XDRUtils.escapeHtml(r.message)}</a></strong>
            <p class="text-muted mb-0">${r.source}</p>
          </div>`).join("")
      : `<div class="empty-state"><i class="bi bi-inbox"></i><h3>No related events</h3><p>No other events from ${log.host} in the current dataset.</p></div>`;
  
    // Tabs
    const tabs = document.querySelectorAll(".xdr-tab");
    const panels = {
      raw: document.getElementById("tabRaw"),
      parsed: document.getElementById("tabParsed"),
      json: document.getElementById("tabJson"),
    };
    tabs.forEach((tab) => {
      tab.addEventListener("click", () => {
        tabs.forEach((t) => t.classList.remove("active"));
        tab.classList.add("active");
        Object.values(panels).forEach((p) => p.classList.add("d-none"));
        panels[tab.dataset.tab].classList.remove("d-none");
      });
    });
  
    document.getElementById("copyRawBtn").addEventListener("click", () => {
      navigator.clipboard?.writeText(log.raw).then(() => {
        if (window.showToast) window.showToast({ type: "success", title: "Copied", msg: "Raw log line copied to clipboard." });
      }).catch(() => {
        if (window.showToast) window.showToast({ type: "warning", title: "Copy failed", msg: "Clipboard access was blocked." });
      });
    });
  })();
  