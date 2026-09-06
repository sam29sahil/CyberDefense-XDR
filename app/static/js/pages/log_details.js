/* ==========================================================================
   log-details.js — page module for app/templates/siem/log_details.html
   Reads ?id=LOG-XXXXXX from URL, fetches from /siem/api/logs/<id>,
   and falls back to local data if needed.
   ========================================================================== */

(function () {
  const CATEGORY_ICON = {
    Network: "bi-diagram-3",
    Endpoint: "bi-pc-display",
    Cloud: "bi-cloud",
    Identity: "bi-person-badge",
    Application: "bi-window",
    Correlation: "bi-cpu",
  };

  const params = new URLSearchParams(window.location.search);
  const logIdParam = params.get("id") || (window.location.pathname.split("/").pop().startsWith("LOG-") ? window.location.pathname.split("/").pop() : null);

  function syntaxHighlightJson(obj) {
    const json = JSON.stringify(obj, null, 2);
    return XDRUtils.escapeHtml(json)
      .replace(/"([^"]+)":/g, '<span class="jk">"$1"</span>:')
      .replace(/: (".*?")/g, ': <span class="jv">$1</span>')
      .replace(/: (\d+)/g, ': <span class="jv">$1</span>');
  }

  function renderLogDetail(log, relatedList) {
    if (!log) return;

    document.getElementById("logId").textContent = log.id;
    document.getElementById("breadcrumbLogId").textContent = log.id;
    document.getElementById("logSevBadge").innerHTML = XDRUtils.severityBadge(log.sev);
    const tsStr = log.ts ? log.ts.replace("T", " ").replace("Z", " UTC") : "—";
    document.getElementById("logMeta").textContent = `${tsStr} · ${log.source || "System"}`;
    document.getElementById("logSevIcon").innerHTML = `<i class="bi ${CATEGORY_ICON[log.category] || "bi-file-earmark-text"}"></i>`;
    
    const tags = Array.isArray(log.tags) ? log.tags : [];
    document.getElementById("logTags").innerHTML = tags.length
      ? tags.map((t) => `<span class="badge badge-neutral">${XDRUtils.escapeHtml(t)}</span>`).join("")
      : `<span class="text-muted text-sm">No tags</span>`;

    document.getElementById("statHost").textContent = log.host || "—";
    document.getElementById("statSource").textContent = log.source || "—";
    document.getElementById("statCategory").textContent = log.category || "—";

    document.getElementById("rawLogText").textContent = log.raw || log.message || "—";

    const fields = log.fields && typeof log.fields === "object" ? log.fields : {};
    const fieldEntries = Object.entries(fields);
    document.getElementById("parsedFieldsList").innerHTML = fieldEntries.length
      ? fieldEntries.map(([k, v]) => `
          <div class="info-row"><span class="text-muted cell-mono">${XDRUtils.escapeHtml(k)}</span><span class="cell-mono">${XDRUtils.escapeHtml(String(v))}</span></div>
        `).join("")
      : `<p class="text-muted text-sm">No parsed fields available.</p>`;

    document.getElementById("jsonPanel").innerHTML = syntaxHighlightJson({
      id: log.id,
      ts: log.ts,
      sev: log.sev,
      host: log.host,
      source: log.source,
      category: log.category,
      message: log.message,
      tags: log.tags,
      fields: log.fields,
      ioc_match_id: log.ioc_match_id,
      detection_event_id: log.detection_event_id,
    });

    document.getElementById("ctxTs").textContent = log.ts || "—";
    document.getElementById("ctxId").textContent = log.id || "—";
    document.getElementById("ctxSource").textContent = log.source || "—";
    document.getElementById("ctxCategory").textContent = log.category || "—";
    document.getElementById("ctxTags").textContent = tags.join(", ") || "—";

    // Related events
    const relTimeline = document.getElementById("relatedTimeline");
    if (relTimeline) {
      const rel = Array.isArray(relatedList) ? relatedList : [];
      relTimeline.innerHTML = rel.length
        ? rel.map((r) => `
            <div class="timeline-item sev-${r.sev}">
              <div class="timeline-time">${r.ts ? r.ts.slice(11, 19) : "--:--:--"} UTC</div>
              <strong><a href="/siem/log-details?id=${r.id}" style="color:var(--text);">${XDRUtils.escapeHtml(r.message)}</a></strong>
              <p class="text-muted mb-0">${XDRUtils.escapeHtml(r.source)}</p>
            </div>
          `).join("")
        : `<div class="empty-state"><i class="bi bi-inbox"></i><h3>No related events</h3><p>No other recent events from ${XDRUtils.escapeHtml(log.host || "host")}.</p></div>`;
    }
  }

  // Fetch from backend
  if (logIdParam) {
    fetch(`/siem/api/logs/${encodeURIComponent(logIdParam)}`)
      .then((res) => res.json())
      .then((payload) => {
        if (payload && payload.success && payload.data) {
          renderLogDetail(payload.data, payload.data.related || []);
        } else {
          fallbackLocal();
        }
      })
      .catch(() => fallbackLocal());
  } else {
    fallbackLocal();
  }

  function fallbackLocal() {
    if (typeof LOGS_DATA !== "undefined" && LOGS_DATA.length > 0) {
      const sorted = LOGS_DATA.slice().sort((a, b) => new Date(b.ts) - new Date(a.ts));
      const match = (logIdParam ? LOGS_DATA.find((r) => r.id === logIdParam) : null) || sorted[0];
      const related = sorted.filter((r) => r.host === match.host && r.id !== match.id).slice(0, 6);
      renderLogDetail(match, related);
    }
  }

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
      Object.values(panels).forEach((p) => p && p.classList.add("d-none"));
      if (panels[tab.dataset.tab]) {
        panels[tab.dataset.tab].classList.remove("d-none");
      }
    });
  });

  // Action Buttons
  const copyBtn = document.getElementById("copyRawBtn");
  if (copyBtn) {
    copyBtn.addEventListener("click", () => {
      const text = document.getElementById("rawLogText")?.textContent;
      if (text && navigator.clipboard) {
        navigator.clipboard.writeText(text).then(() => {
          if (window.showToast) window.showToast({ type: "success", title: "Copied", msg: "Raw log line copied to clipboard." });
        });
      }
    });
  }

  const createAlertBtn = document.getElementById("createAlertBtn");
  if (createAlertBtn) {
    createAlertBtn.addEventListener("click", () => {
      const id = document.getElementById("logId")?.textContent;
      if (window.showToast) {
        window.showToast({
          type: "success",
          title: "Alert Created",
          msg: `Security alert initiated for event ${id}.`,
        });
      }
    });
  }

  const suppressBtn = document.getElementById("suppressBtn");
  if (suppressBtn) {
    suppressBtn.addEventListener("click", () => {
      const host = document.getElementById("statHost")?.textContent;
      if (window.showToast) {
        window.showToast({
          type: "info",
          title: "Rule Suppressed",
          msg: `Events matching this signature on ${host} temporarily silenced.`,
        });
      }
    });
  }
})();