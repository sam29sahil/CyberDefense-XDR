/**
 * Threat Hunting UI Controller
 * Integrates search console, tab results, timeline rendering, and quick pivoting.
 */
document.addEventListener('DOMContentLoaded', () => {
  let currentQuery = '';
  let currentType = 'auto';

  // Elements
  const huntSearchForm = document.getElementById('huntSearchForm');
  const huntQueryInput = document.getElementById('huntQueryInput');
  const huntSearchType = document.getElementById('huntSearchType');
  const huntTimeRange = document.getElementById('huntTimeRange');
  const huntSeverity = document.getElementById('huntSeverity');
  const huntModule = document.getElementById('huntModule');
  const btnRunHunt = document.getElementById('btnRunHunt');
  const huntSpinIcon = document.getElementById('huntSpinIcon');
  const huntResultsArea = document.getElementById('huntResultsArea');
  const btnSaveHunt = document.getElementById('btnSaveHunt');

  const resQueryText = document.getElementById('resQueryText');
  const resQueryType = document.getElementById('resQueryType');
  const resTotalMatches = document.getElementById('resTotalMatches');

  const btnCorrelateCurrent = document.getElementById('btnCorrelateCurrent');
  const btnAskAiCurrent = document.getElementById('btnAskAiCurrent');
  const btnSoarCurrent = document.getElementById('btnSoarCurrent');

  // Summary counters
  function loadSummary() {
    fetch('/threat-hunting/api/summary')
      .then(res => res.json())
      .then(data => {
        if (data.status === 'success' && data.summary) {
          const s = data.summary;
          const setVal = (id, val) => {
            const el = document.getElementById(id);
            if (el) el.textContent = Number(val || 0).toLocaleString();
          };
          setVal('statAssets', s.total_assets);
          setVal('statAlerts', s.active_alerts);
          setVal('statIdsThreats', s.ids_threat_events);
          setVal('statSiemLogs', s.siem_events_24h);
          setVal('statIocs', s.active_iocs);
        }
      })
      .catch(err => console.error('Failed to load hunting summary:', err));
  }

  // Load recent history
  function loadRecentHistory() {
    fetch('/threat-hunting/api/history?limit=10')
      .then(res => res.json())
      .then(data => {
        const list = document.getElementById('recentQueriesList');
        if (!list) return;
        if (!data.history || data.history.length === 0) {
          list.innerHTML = '<li class="list-group-item bg-transparent text-muted text-center py-2">No recent hunts recorded</li>';
          return;
        }
        list.innerHTML = data.history.map(item => `
          <li class="list-group-item bg-transparent text-light border-secondary d-flex justify-content-between align-items-center py-2 px-2">
            <div class="text-truncate me-2">
              <a href="#" class="history-item text-info text-decoration-none cell-mono" data-query="${escapeHtml(item.query_text)}" data-type="${escapeHtml(item.query_type)}">
                ${escapeHtml(item.query_text)}
              </a>
              <div class="text-muted" style="font-size:0.75rem;">
                <span class="badge bg-secondary me-1">${escapeHtml(item.query_type)}</span>
                ${item.results_count} results &bull; ${formatRelativeTime(item.created_at)}
              </div>
            </div>
          </li>
        `).join('');

        list.querySelectorAll('.history-item').forEach(link => {
          link.addEventListener('click', (e) => {
            e.preventDefault();
            huntQueryInput.value = link.dataset.query;
            huntSearchType.value = link.dataset.type || 'auto';
            runHunt();
          });
        });
      })
      .catch(err => console.error('Failed to load recent history:', err));
  }

  // Load saved hunts
  function loadSavedHunts() {
    fetch('/threat-hunting/api/saved-searches')
      .then(res => res.json())
      .then(data => {
        const list = document.getElementById('savedHuntsList');
        if (!list) return;
        if (!data.saved || data.saved.length === 0) {
          list.innerHTML = '<li class="list-group-item bg-transparent text-muted text-center py-2">No saved hunts yet</li>';
          return;
        }
        list.innerHTML = data.saved.map(item => `
          <li class="list-group-item bg-transparent text-light border-secondary d-flex justify-content-between align-items-center py-2 px-2">
            <div class="text-truncate me-2">
              <a href="#" class="saved-item text-warning text-decoration-none cell-mono" data-query="${escapeHtml(item.query_text)}" data-type="${escapeHtml(item.query_type)}">
                <i class="bi bi-bookmark-star me-1"></i>${escapeHtml(item.name || item.query_text)}
              </a>
              <div class="text-muted" style="font-size:0.75rem;">
                ${escapeHtml(item.query_type)} &bull; ${formatRelativeTime(item.created_at)}
              </div>
            </div>
          </li>
        `).join('');

        list.querySelectorAll('.saved-item').forEach(link => {
          link.addEventListener('click', (e) => {
            e.preventDefault();
            huntQueryInput.value = link.dataset.query;
            huntSearchType.value = link.dataset.type || 'auto';
            runHunt();
          });
        });
      })
      .catch(err => console.error('Failed to load saved hunts:', err));
  }

  // Sample queries
  document.querySelectorAll('.sample-query-badge').forEach(pill => {
    pill.addEventListener('click', () => {
      const q = pill.dataset.query;
      const t = pill.dataset.type || 'auto';
      huntQueryInput.value = q;
      huntSearchType.value = t;
      runHunt();
    });
  });

  // Execute Hunt
  function runHunt() {
    const q = huntQueryInput.value.trim();
    if (!q) return;

    currentQuery = q;
    btnRunHunt.disabled = true;
    huntSpinIcon.className = 'spinner-border spinner-border-sm me-1';

    const payload = {
      query: q,
      search_type: huntSearchType.value,
      time_range: huntTimeRange.value,
      severity: huntSeverity.value,
      module: huntModule.value
    };

    fetch('/threat-hunting/api/search', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    })
      .then(res => res.json())
      .then(data => {
        btnRunHunt.disabled = false;
        huntSpinIcon.className = 'bi bi-crosshair2 me-1';

        if (data.status === 'success') {
          renderHuntResults(data);
          loadRecentHistory();
        } else {
          alert('Hunt query failed: ' + (data.message || 'Unknown error'));
        }
      })
      .catch(err => {
        btnRunHunt.disabled = false;
        huntSpinIcon.className = 'bi bi-crosshair2 me-1';
        console.error('Error running hunt:', err);
        alert('Network or server error executing hunt.');
      });
  }

  huntSearchForm.addEventListener('submit', (e) => {
    e.preventDefault();
    runHunt();
  });

  // Save hunt bookmark
  btnSaveHunt.addEventListener('click', () => {
    if (!currentQuery) {
      alert('Please run a search first before bookmarking.');
      return;
    }
    const name = prompt('Name for this saved hunt:', currentQuery);
    if (!name) return;

    fetch('/threat-hunting/api/search', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        query: currentQuery,
        search_type: currentType,
        save: true,
        name: name
      })
    })
      .then(res => res.json())
      .then(() => {
        alert('Hunt successfully saved!');
        loadSavedHunts();
      })
      .catch(err => console.error('Failed to save hunt:', err));
  });

  // Quick Action Buttons
  btnCorrelateCurrent.addEventListener('click', () => {
    if (!currentQuery) return;
    window.location.href = `/correlation/?q=${encodeURIComponent(currentQuery)}&type=${encodeURIComponent(currentType)}`;
  });

  btnAskAiCurrent.addEventListener('click', () => {
    if (!currentQuery) return;
    const prompt = `Analyze security posture and threat findings for entity ${currentQuery} (${currentType}). Provide risk assessment and defensive recommendations.`;
    window.location.href = `/ai-assistant/?prompt=${encodeURIComponent(prompt)}`;
  });

  btnSoarCurrent.addEventListener('click', () => {
    if (!currentQuery) return;
    window.location.href = `/soar/?q=${encodeURIComponent(currentQuery)}&type=${encodeURIComponent(currentType)}`;
  });

  // Render results
  function renderHuntResults(data) {
    huntResultsArea.classList.remove('d-none');

    resQueryText.textContent = data.query;
    currentType = data.entity_type || 'unknown';
    resQueryType.textContent = currentType.toUpperCase();
    resTotalMatches.textContent = data.total_matches || 0;

    const r = data.results || {};
    const counts = {
      timeline: (data.timeline || []).length,
      alerts: (r.alerts || []).length,
      ids: (r.ids_events || []).length,
      siem: (r.siem_logs || []).length,
      incidents: (r.incidents || []).length,
      vulns: (r.vulnerabilities || []).length,
      iocs: (r.threat_intel || []).length,
      assets: (r.assets || []).length
    };

    // Update Tab Badges
    document.getElementById('count-timeline').textContent = counts.timeline;
    document.getElementById('count-alerts').textContent = counts.alerts;
    document.getElementById('count-ids').textContent = counts.ids;
    document.getElementById('count-siem').textContent = counts.siem;
    document.getElementById('count-incidents').textContent = counts.incidents;
    document.getElementById('count-vulns').textContent = counts.vulns;
    document.getElementById('count-iocs').textContent = counts.iocs;
    document.getElementById('count-assets').textContent = counts.assets;

    // Render Timeline
    renderTimeline(data.timeline || []);

    // Render Domain Tables
    renderAlertsTable(r.alerts || []);
    renderIdsTable(r.ids_events || []);
    renderSiemTable(r.siem_logs || []);
    renderIncidentsTable(r.incidents || []);
    renderVulnsTable(r.vulnerabilities || []);
    renderIocsTable(r.threat_intel || []);
    renderAssetsTable(r.assets || []);

    // Scroll to results
    huntResultsArea.scrollIntoView({ behavior: 'smooth' });
  }

  // Unified Chronological Timeline Renderer
  function renderTimeline(events) {
    const container = document.getElementById('unifiedTimelineContainer');
    if (!container) return;

    if (!events || events.length === 0) {
      container.innerHTML = '<div class="text-center text-muted py-5"><i class="bi bi-clock-history fs-3 d-block mb-2"></i>No chronological telemetry events matching the target entity across modules.</div>';
      return;
    }

    container.innerHTML = events.map(evt => {
      const badgeClass = getModuleBadgeClass(evt.source_module);
      const sevClass = getSeverityBadgeClass(evt.severity);
      return `
        <div class="timeline-item">
          <div class="timeline-badge bg-secondary border border-light"></div>
          <div class="timeline-content p-3">
            <div class="d-flex justify-content-between align-items-center mb-1">
              <div>
                <span class="badge ${badgeClass} me-2 text-uppercase">${escapeHtml(evt.source_module)}</span>
                <span class="badge ${sevClass} me-2">${escapeHtml(evt.severity || 'INFO')}</span>
                <strong class="text-light">${escapeHtml(evt.title)}</strong>
              </div>
              <span class="text-muted cell-mono small">${formatDateTime(evt.timestamp)}</span>
            </div>
            <p class="text-muted mb-2 small">${escapeHtml(evt.description || '')}</p>
            <div class="d-flex gap-2 align-items-center flex-wrap">
              ${evt.entity_value ? `<span class="badge bg-dark border border-secondary text-info cell-mono small">Target: ${escapeHtml(evt.entity_value)}</span>` : ''}
              ${evt.link_url ? `<a href="${evt.link_url}" class="btn btn-outline-secondary btn-xs py-0 px-2 small">View in Module <i class="bi bi-arrow-up-right ms-1"></i></a>` : ''}
            </div>
          </div>
        </div>
      `;
    }).join('');
  }

  // Alerts Table
  function renderAlertsTable(items) {
    const tbody = document.getElementById('tblAlertsBody');
    if (!tbody) return;
    if (!items.length) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-3">No matching security alerts found.</td></tr>';
      return;
    }
    tbody.innerHTML = items.map(a => `
      <tr>
        <td class="cell-mono text-light">${escapeHtml(a.id)}</td>
        <td><strong class="text-light">${escapeHtml(a.title)}</strong></td>
        <td><span class="badge ${getSeverityBadgeClass(a.severity)}">${escapeHtml(a.severity)}</span></td>
        <td><span class="badge bg-secondary">${escapeHtml(a.status || 'NEW')}</span></td>
        <td class="cell-mono small text-info">${escapeHtml(a.source_ip || '-')}</td>
        <td class="cell-mono small text-warning">${escapeHtml(a.dest_ip || '-')}</td>
        <td class="cell-mono small text-muted">${formatDateTime(a.created_at)}</td>
        <td>
          <a href="/alert-center/?alert_id=${encodeURIComponent(a.id)}" class="btn btn-outline-info btn-xs py-0 px-2">Investigate</a>
        </td>
      </tr>
    `).join('');
  }

  // IDS Events Table
  function renderIdsTable(items) {
    const tbody = document.getElementById('tblIdsBody');
    if (!tbody) return;
    if (!items.length) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-3">No matching Network IDS events found.</td></tr>';
      return;
    }
    tbody.innerHTML = items.map(ev => `
      <tr>
        <td class="cell-mono small text-muted">${formatDateTime(ev.timestamp)}</td>
        <td class="cell-mono small text-warning">${escapeHtml(String(ev.signature_id || ''))}</td>
        <td><strong class="text-light">${escapeHtml(ev.signature || 'Suricata Alert')}</strong></td>
        <td><span class="badge ${getSeverityBadgeClass(ev.severity)}">${escapeHtml(ev.severity || 'MED')}</span></td>
        <td class="cell-mono small text-info">${escapeHtml(ev.src_ip || '-')}:${ev.src_port || ''}</td>
        <td class="cell-mono small text-danger">${escapeHtml(ev.dest_ip || '-')}:${ev.dest_port || ''}</td>
        <td class="cell-mono small text-muted">${escapeHtml(ev.protocol || 'TCP')}</td>
        <td>
          <a href="/ids/?q=${encodeURIComponent(ev.src_ip || ev.dest_ip || '')}" class="btn btn-outline-info btn-xs py-0 px-2">View IDS</a>
        </td>
      </tr>
    `).join('');
  }

  // SIEM Logs Table
  function renderSiemTable(items) {
    const tbody = document.getElementById('tblSiemBody');
    if (!tbody) return;
    if (!items.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-3">No matching SIEM event logs found.</td></tr>';
      return;
    }
    tbody.innerHTML = items.map(s => `
      <tr>
        <td class="cell-mono small text-muted">${formatDateTime(s.timestamp)}</td>
        <td><span class="badge bg-secondary">${escapeHtml(s.source_type || 'SYSLOG')}</span></td>
        <td class="cell-mono small text-light">${escapeHtml(s.host || '-')}</td>
        <td class="cell-mono small text-info">${escapeHtml(s.src_ip || '-')}</td>
        <td class="cell-mono small text-warning">${escapeHtml(s.dest_ip || '-')}</td>
        <td class="cell-mono small text-muted text-truncate" style="max-width:300px;">${escapeHtml(s.message || '')}</td>
        <td>
          <a href="/siem/?q=${encodeURIComponent(s.src_ip || s.host || '')}" class="btn btn-outline-info btn-xs py-0 px-2">SIEM Pivot</a>
        </td>
      </tr>
    `).join('');
  }

  // Incidents Table
  function renderIncidentsTable(items) {
    const tbody = document.getElementById('tblIncidentsBody');
    if (!tbody) return;
    if (!items.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-3">No matching security incidents found.</td></tr>';
      return;
    }
    tbody.innerHTML = items.map(inc => `
      <tr>
        <td class="cell-mono text-light">${escapeHtml(inc.id)}</td>
        <td><strong class="text-light">${escapeHtml(inc.title)}</strong></td>
        <td><span class="badge ${getSeverityBadgeClass(inc.severity)}">${escapeHtml(inc.severity)}</span></td>
        <td><span class="badge bg-secondary">${escapeHtml(inc.status || 'OPEN')}</span></td>
        <td class="cell-mono small text-muted">${escapeHtml(inc.assigned_to || 'Unassigned')}</td>
        <td class="cell-mono small text-muted">${formatDateTime(inc.created_at)}</td>
        <td>
          <a href="/incident-response/?incident_id=${encodeURIComponent(inc.id)}" class="btn btn-outline-info btn-xs py-0 px-2">Respond</a>
        </td>
      </tr>
    `).join('');
  }

  // Vulns Table
  function renderVulnsTable(items) {
    const tbody = document.getElementById('tblVulnsBody');
    if (!tbody) return;
    if (!items.length) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-3">No matching vulnerability findings found.</td></tr>';
      return;
    }
    tbody.innerHTML = items.map(v => `
      <tr>
        <td class="cell-mono text-danger fw-bold">${escapeHtml(v.cve_id || 'CVE-UNKNOWN')}</td>
        <td><strong class="text-light">${escapeHtml(v.title || '')}</strong></td>
        <td><span class="badge ${getSeverityBadgeClass(v.severity)}">${escapeHtml(v.severity)}</span></td>
        <td class="cell-mono text-warning">${v.cvss_score ? Number(v.cvss_score).toFixed(1) : '-'}</td>
        <td class="cell-mono small text-info">${escapeHtml(v.target_ip || '-')}</td>
        <td class="cell-mono small text-light">${escapeHtml(v.target_port ? String(v.target_port) : '-')}</td>
        <td class="cell-mono small text-muted">${formatDateTime(v.detected_at || v.created_at)}</td>
        <td>
          <a href="/vulnerability-scanner/?q=${encodeURIComponent(v.cve_id || v.target_ip || '')}" class="btn btn-outline-info btn-xs py-0 px-2">View Scan</a>
        </td>
      </tr>
    `).join('');
  }

  // Threat Intel Table
  function renderIocsTable(items) {
    const tbody = document.getElementById('tblIocsBody');
    if (!tbody) return;
    if (!items.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-3">No matching threat intelligence IOCs found.</td></tr>';
      return;
    }
    tbody.innerHTML = items.map(ioc => `
      <tr>
        <td><span class="badge bg-secondary text-uppercase">${escapeHtml(ioc.ioc_type || 'IOC')}</span></td>
        <td class="cell-mono text-danger fw-bold">${escapeHtml(ioc.ioc_value || '')}</td>
        <td><span class="badge ${getSeverityBadgeClass(ioc.threat_level || 'MED')}">${escapeHtml(ioc.threat_level || 'MED')}</span></td>
        <td class="text-muted small">${escapeHtml(ioc.threat_actor || ioc.source || 'Threat Intel Feed')}</td>
        <td class="cell-mono small text-muted">${formatDateTime(ioc.first_seen || ioc.created_at)}</td>
        <td><span class="badge ${ioc.is_active !== false ? 'bg-danger' : 'bg-secondary'}">${ioc.is_active !== false ? 'ACTIVE' : 'INACTIVE'}</span></td>
        <td>
          <a href="/threat-intelligence/?q=${encodeURIComponent(ioc.ioc_value || '')}" class="btn btn-outline-info btn-xs py-0 px-2">Intel Pivot</a>
        </td>
      </tr>
    `).join('');
  }

  // Assets Table
  function renderAssetsTable(items) {
    const tbody = document.getElementById('tblAssetsBody');
    if (!tbody) return;
    if (!items.length) {
      tbody.innerHTML = '<tr><td colspan="9" class="text-center text-muted py-3">No matching assets found.</td></tr>';
      return;
    }
    tbody.innerHTML = items.map(ast => `
      <tr>
        <td class="cell-mono text-light">${escapeHtml(ast.id)}</td>
        <td><strong class="text-light">${escapeHtml(ast.name || ast.hostname || 'Asset')}</strong></td>
        <td class="cell-mono text-info">${escapeHtml(ast.ip_address || '-')}</td>
        <td class="cell-mono small text-muted">${escapeHtml(ast.mac_address || '-')}</td>
        <td><span class="badge bg-dark border border-secondary text-light">${escapeHtml(ast.os_type || 'Unknown')}</span></td>
        <td><span class="badge ${ast.status === 'online' ? 'bg-success' : 'bg-secondary'}">${escapeHtml(ast.status || 'offline')}</span></td>
        <td class="cell-mono text-warning">${ast.criticality || 'MEDIUM'}</td>
        <td class="cell-mono small text-muted">${formatDateTime(ast.last_seen)}</td>
        <td>
          <a href="/assets/?asset_id=${encodeURIComponent(ast.id)}" class="btn btn-outline-info btn-xs py-0 px-2">Asset 360</a>
        </td>
      </tr>
    `).join('');
  }

  // Helpers
  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function formatDateTime(val) {
    if (!val) return '-';
    try {
      const d = new Date(val);
      if (isNaN(d.getTime())) return String(val);
      return d.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
    } catch {
      return String(val);
    }
  }

  function formatRelativeTime(val) {
    if (!val) return '-';
    try {
      const d = new Date(val);
      const diff = Math.floor((new Date() - d) / 1000);
      if (diff < 60) return `${diff}s ago`;
      if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
      if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
      return `${Math.floor(diff / 86400)}d ago`;
    } catch {
      return '';
    }
  }

  function getSeverityBadgeClass(sev) {
    const s = String(sev || '').toUpperCase();
    if (s === 'CRITICAL') return 'bg-danger';
    if (s === 'HIGH') return 'bg-warning text-dark';
    if (s === 'MEDIUM' || s === 'MED') return 'bg-info text-dark';
    if (s === 'LOW') return 'bg-success';
    return 'bg-secondary';
  }

  function getModuleBadgeClass(mod) {
    const m = String(mod || '').toLowerCase();
    if (m.includes('alert')) return 'bg-danger';
    if (m.includes('ids') || m.includes('suricata')) return 'bg-warning text-dark';
    if (m.includes('siem')) return 'bg-primary';
    if (m.includes('incident')) return 'bg-purple';
    if (m.includes('vuln')) return 'bg-danger text-light';
    if (m.includes('intel') || m.includes('threat')) return 'bg-info text-dark';
    if (m.includes('asset')) return 'bg-success';
    return 'bg-secondary';
  }

  // Check URL params for pre-seeded query
  const urlParams = new URLSearchParams(window.location.search);
  const qParam = urlParams.get('q');
  if (qParam) {
    huntQueryInput.value = qParam;
    const tParam = urlParams.get('type');
    if (tParam) huntSearchType.value = tParam;
    runHunt();
  }

  // Initial loads
  loadSummary();
  loadRecentHistory();
  loadSavedHunts();
});

