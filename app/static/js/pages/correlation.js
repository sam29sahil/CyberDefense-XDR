/**
 * Correlation Engine UI Controller & HTML5 Canvas Graph Renderer
 */
document.addEventListener('DOMContentLoaded', () => {
  let currentEntity = '';
  let currentEntityType = 'auto';

  const correlationForm = document.getElementById('correlationForm');
  const corrQueryInput = document.getElementById('corrQueryInput');
  const corrEntityType = document.getElementById('corrEntityType');
  const btnRunCorrelate = document.getElementById('btnRunCorrelate');
  const corrSpinIcon = document.getElementById('corrSpinIcon');
  const corrResultsArea = document.getElementById('corrResultsArea');

  const campaignsContainer = document.getElementById('campaignsContainer');
  const campaignsBadge = document.getElementById('campaignsBadge');
  const campaignsGrid = document.getElementById('campaignsGrid');

  const corrRiskScore = document.getElementById('corrRiskScore');
  const corrRiskBadge = document.getElementById('corrRiskBadge');
  const corrReasonsList = document.getElementById('corrReasonsList');
  const graphNodesCount = document.getElementById('graphNodesCount');

  const btnPivotThreatHunt = document.getElementById('btnPivotThreatHunt');
  const btnPivotAi = document.getElementById('btnPivotAi');
  const btnPivotSoar = document.getElementById('btnPivotSoar');
  const btnResetGraph = document.getElementById('btnResetGraph');

  // Canvas Graph State
  const canvas = document.getElementById('graphCanvas');
  const ctx = canvas ? canvas.getContext('2d') : null;
  let graphNodes = [];
  let graphLinks = [];
  let animationFrameId = null;
  let draggedNode = null;
  let hoveredNode = null;
  let transform = { x: 0, y: 0, scale: 1 };

  // Load Campaigns
  function loadCampaigns() {
    fetch('/correlation/api/campaigns')
      .then(res => res.json())
      .then(data => {
        if (data.status === 'success' && data.campaigns && data.campaigns.length > 0) {
          campaignsContainer.style.display = 'block';
          campaignsBadge.textContent = data.count;
          campaignsGrid.innerHTML = data.campaigns.map(c => `
            <div class="col-md-6">
              <div class="card campaign-card p-3 h-100">
                <div class="d-flex justify-content-between align-items-center mb-2">
                  <strong class="text-light">${escapeHtml(c.title)}</strong>
                  <span class="badge ${c.severity === 'CRITICAL' ? 'bg-danger' : 'bg-warning text-dark'}">${escapeHtml(c.severity)}</span>
                </div>
                <p class="text-muted small mb-2">${escapeHtml(c.description)}</p>
                <div class="d-flex justify-content-between align-items-center">
                  <span class="badge bg-dark border border-secondary text-info cell-mono small">Target/Source: ${escapeHtml(c.entity)}</span>
                  <button class="btn btn-outline-danger btn-xs py-0 px-2 btn-correlate-camp" data-entity="${escapeHtml(c.entity)}">
                    Investigate Campaign <i class="bi bi-arrow-right ms-1"></i>
                  </button>
                </div>
              </div>
            </div>
          `).join('');

          campaignsGrid.querySelectorAll('.btn-correlate-camp').forEach(btn => {
            btn.addEventListener('click', () => {
              corrQueryInput.value = btn.dataset.entity;
              corrEntityType.value = 'auto';
              runCorrelation();
            });
          });
        } else {
          campaignsContainer.style.display = 'none';
        }
      })
      .catch(err => console.error('Failed to load campaigns:', err));
  }

  // Execute Correlation
  function runCorrelation() {
    const q = corrQueryInput.value.trim();
    if (!q) return;

    currentEntity = q;
    currentEntityType = corrEntityType.value;

    btnRunCorrelate.disabled = true;
    corrSpinIcon.className = 'spinner-border spinner-border-sm me-1';

    fetch('/correlation/api/search', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        query: q,
        entity_type: currentEntityType
      })
    })
      .then(res => res.json())
      .then(data => {
        btnRunCorrelate.disabled = false;
        corrSpinIcon.className = 'bi bi-play-circle me-1';

        if (data.status === 'success' && data.correlation) {
          renderCorrelation(data.correlation);
        } else {
          alert('Correlation query failed: ' + (data.message || 'Unknown error'));
        }
      })
      .catch(err => {
        btnRunCorrelate.disabled = false;
        corrSpinIcon.className = 'bi bi-play-circle me-1';
        console.error('Error executing correlation:', err);
        alert('Network or server error during correlation.');
      });
  }

  correlationForm.addEventListener('submit', (e) => {
    e.preventDefault();
    runCorrelation();
  });

  // Render Correlation
  function renderCorrelation(c) {
    corrResultsArea.classList.remove('d-none');

    // Risk Score
    const risk = c.risk || { score: 0, level: 'CLEAN', reasons: [] };
    corrRiskScore.textContent = risk.score;
    corrRiskBadge.textContent = risk.level;
    setRiskScoreStyle(corrRiskScore, corrRiskBadge, risk.level);

    // Reasons List
    if (risk.reasons && risk.reasons.length > 0) {
      corrReasonsList.innerHTML = risk.reasons.map(r => `
        <div class="reason-item">
          <i class="bi bi-shield-fill-check text-info me-2"></i>${escapeHtml(r)}
        </div>
      `).join('');
    } else {
      corrReasonsList.innerHTML = '<div class="text-muted">No security risk factors triggered.</div>';
    }

    // Tab counts
    const counts = c.counts || {};
    document.getElementById('corr-count-alerts').textContent = counts.alerts || 0;
    document.getElementById('corr-count-ids').textContent = counts.ids_events || 0;
    document.getElementById('corr-count-siem').textContent = counts.siem_logs || 0;
    document.getElementById('corr-count-vulns').textContent = counts.vulnerabilities || 0;
    document.getElementById('corr-count-iocs').textContent = counts.threat_intel || 0;

    // Render Tables
    const details = c.details || {};
    renderAlertsTable(details.alerts || []);
    renderIdsTable(details.ids_events || []);
    renderSiemTable(details.siem_logs || []);
    renderVulnsTable(details.vulnerabilities || []);
    renderIocsTable(details.threat_intel || []);

    // Graph payload
    initGraph(c.graph || { nodes: [], links: [] });

    // Pivot Buttons
    btnPivotThreatHunt.onclick = () => {
      window.location.href = `/threat-hunting/?q=${encodeURIComponent(currentEntity)}&type=${encodeURIComponent(currentEntityType)}`;
    };
    btnPivotAi.onclick = () => {
      const prompt = `Perform cross-module correlation analysis on ${currentEntity} (${currentEntityType}). Calculated risk score is ${risk.score} (${risk.level}). Key factors: ${risk.reasons.join('; ')}. Detail attack timeline, probable adversary techniques, and mitigation steps.`;
      window.location.href = `/ai-assistant/?prompt=${encodeURIComponent(prompt)}`;
    };
    btnPivotSoar.onclick = () => {
      window.location.href = `/soar/?q=${encodeURIComponent(currentEntity)}&type=${encodeURIComponent(currentEntityType)}`;
    };

    corrResultsArea.scrollIntoView({ behavior: 'smooth' });
  }

  function setRiskScoreStyle(scoreEl, badgeEl, level) {
    scoreEl.className = 'risk-number cell-mono mb-2';
    badgeEl.className = 'risk-level-badge';

    switch (level) {
      case 'CRITICAL':
        scoreEl.classList.add('risk-critical');
        badgeEl.classList.add('bg-danger');
        break;
      case 'HIGH':
        scoreEl.classList.add('risk-high');
        badgeEl.classList.add('bg-warning', 'text-dark');
        break;
      case 'MEDIUM':
        scoreEl.classList.add('risk-medium');
        badgeEl.classList.add('bg-info', 'text-dark');
        break;
      case 'LOW':
        scoreEl.classList.add('risk-low');
        badgeEl.classList.add('bg-success');
        break;
      default:
        scoreEl.classList.add('risk-clean');
        badgeEl.classList.add('bg-secondary');
        break;
    }
  }

  // Correlated Tables
  function renderAlertsTable(items) {
    const tbody = document.getElementById('corrTblAlerts');
    if (!tbody) return;
    if (!items.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-3">No correlated alerts.</td></tr>';
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
      </tr>
    `).join('');
  }

  function renderIdsTable(items) {
    const tbody = document.getElementById('corrTblIds');
    if (!tbody) return;
    if (!items.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-3">No correlated IDS events.</td></tr>';
      return;
    }
    tbody.innerHTML = items.map(ev => `
      <tr>
        <td class="cell-mono small text-muted">${formatDateTime(ev.timestamp)}</td>
        <td class="cell-mono small text-warning">${escapeHtml(String(ev.signature_id || ''))}</td>
        <td><strong class="text-light">${escapeHtml(ev.signature || 'Suricata')}</strong></td>
        <td><span class="badge ${getSeverityBadgeClass(ev.severity)}">${escapeHtml(ev.severity || 'MED')}</span></td>
        <td class="cell-mono small text-info">${escapeHtml(ev.src_ip || '-')}:${ev.src_port || ''}</td>
        <td class="cell-mono small text-danger">${escapeHtml(ev.dest_ip || '-')}:${ev.dest_port || ''}</td>
      </tr>
    `).join('');
  }

  function renderSiemTable(items) {
    const tbody = document.getElementById('corrTblSiem');
    if (!tbody) return;
    if (!items.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-3">No correlated SIEM events.</td></tr>';
      return;
    }
    tbody.innerHTML = items.map(s => `
      <tr>
        <td class="cell-mono small text-muted">${formatDateTime(s.timestamp)}</td>
        <td><span class="badge bg-secondary">${escapeHtml(s.source_type || 'SYSLOG')}</span></td>
        <td class="cell-mono small text-light">${escapeHtml(s.host || '-')}</td>
        <td class="cell-mono small text-info">${escapeHtml(s.src_ip || '-')}</td>
        <td class="cell-mono small text-warning">${escapeHtml(s.dest_ip || '-')}</td>
        <td class="cell-mono small text-muted text-truncate" style="max-width:320px;">${escapeHtml(s.message || '')}</td>
      </tr>
    `).join('');
  }

  function renderVulnsTable(items) {
    const tbody = document.getElementById('corrTblVulns');
    if (!tbody) return;
    if (!items.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-3">No correlated vulnerabilities.</td></tr>';
      return;
    }
    tbody.innerHTML = items.map(v => `
      <tr>
        <td class="cell-mono text-danger fw-bold">${escapeHtml(v.cve_id || 'CVE')}</td>
        <td><strong class="text-light">${escapeHtml(v.title || '')}</strong></td>
        <td><span class="badge ${getSeverityBadgeClass(v.severity)}">${escapeHtml(v.severity)}</span></td>
        <td class="cell-mono text-warning">${v.cvss_score ? Number(v.cvss_score).toFixed(1) : '-'}</td>
        <td class="cell-mono small text-info">${escapeHtml(v.target_ip || '-')}</td>
      </tr>
    `).join('');
  }

  function renderIocsTable(items) {
    const tbody = document.getElementById('corrTblIocs');
    if (!tbody) return;
    if (!items.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-3">No correlated threat intel IOCs.</td></tr>';
      return;
    }
    tbody.innerHTML = items.map(i => `
      <tr>
        <td><span class="badge bg-secondary text-uppercase">${escapeHtml(i.ioc_type || 'IOC')}</span></td>
        <td class="cell-mono text-danger fw-bold">${escapeHtml(i.ioc_value || '')}</td>
        <td><span class="badge ${getSeverityBadgeClass(i.threat_level || 'MED')}">${escapeHtml(i.threat_level || 'MED')}</span></td>
        <td class="text-muted small">${escapeHtml(i.threat_actor || 'Threat Intel Feed')}</td>
        <td><span class="badge ${i.is_active !== false ? 'bg-danger' : 'bg-secondary'}">${i.is_active !== false ? 'ACTIVE' : 'INACTIVE'}</span></td>
      </tr>
    `).join('');
  }

  // ==========================================
  // Interactive Canvas Force Graph Simulation
  // ==========================================
  function initGraph(graph) {
    if (!canvas || !ctx) return;

    if (animationFrameId) {
      cancelAnimationFrame(animationFrameId);
    }

    // Resize canvas to parent
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = rect.width;
    canvas.height = rect.height;

    const width = canvas.width;
    const height = canvas.height;

    graphNodes = (graph.nodes || []).map((n, idx) => {
      const angle = (idx / (graph.nodes.length || 1)) * 2 * Math.PI;
      const radius = Math.min(width, height) * 0.35;
      const isPrimary = n.metadata && n.metadata.primary;
      return {
        id: n.id,
        label: n.label,
        type: n.type,
        severity: n.severity,
        metadata: n.metadata,
        radius: isPrimary ? 22 : 15,
        x: isPrimary ? width / 2 : width / 2 + radius * Math.cos(angle) + (Math.random() - 0.5) * 40,
        y: isPrimary ? height / 2 : height / 2 + radius * Math.sin(angle) + (Math.random() - 0.5) * 40,
        vx: 0,
        vy: 0,
      };
    });

    const nodeMap = new Map();
    graphNodes.forEach(n => nodeMap.set(n.id, n));

    graphLinks = (graph.links || []).map(l => {
      return {
        source: nodeMap.get(l.source) || l.source,
        target: nodeMap.get(l.target) || l.target,
        relationship: l.relationship,
        weight: l.weight || 1,
      };
    }).filter(l => typeof l.source === 'object' && typeof l.target === 'object');

    graphNodesCount.textContent = `${graphNodes.length} nodes, ${graphLinks.length} edges`;

    transform = { x: 0, y: 0, scale: 1 };

    // Start simulation loop
    let ticks = 0;
    function simulate() {
      // Apply simple force-directed layout
      if (ticks < 180) {
        for (let i = 0; i < graphNodes.length; i++) {
          const a = graphNodes[i];
          for (let j = i + 1; j < graphNodes.length; j++) {
            const b = graphNodes[j];
            const dx = b.x - a.x;
            const dy = b.y - a.y;
            const dist = Math.sqrt(dx * dx + dy * dy) || 1;
            if (dist < 180) {
              const f = (180 - dist) / dist * 0.04;
              a.vx -= dx * f;
              a.vy -= dy * f;
              b.vx += dx * f;
              b.vy += dy * f;
            }
          }
        }

        // Links spring force
        graphLinks.forEach(l => {
          const dx = l.target.x - l.source.x;
          const dy = l.target.y - l.source.y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const desiredDist = 120;
          const f = (dist - desiredDist) / dist * 0.05;
          l.source.vx += dx * f;
          l.source.vy += dy * f;
          l.target.vx -= dx * f;
          l.target.vy -= dy * f;
        });

        // Center gravity
        const cx = width / 2;
        const cy = height / 2;
        graphNodes.forEach(n => {
          if (!draggedNode || draggedNode !== n) {
            n.vx += (cx - n.x) * 0.005;
            n.vy += (cy - n.y) * 0.005;
            n.x += n.vx;
            n.y += n.vy;
            n.vx *= 0.85;
            n.vy *= 0.85;
          }
        });
        ticks++;
      }

      drawGraph();
      animationFrameId = requestAnimationFrame(simulate);
    }

    simulate();
  }

  function drawGraph() {
    if (!ctx) return;
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    ctx.save();
    ctx.translate(transform.x, transform.y);
    ctx.scale(transform.scale, transform.scale);

    // Draw Links
    ctx.lineWidth = 1.5;
    graphLinks.forEach(l => {
      ctx.beginPath();
      ctx.moveTo(l.source.x, l.source.y);
      ctx.lineTo(l.target.x, l.target.y);
      ctx.strokeStyle = '#2d3748';
      ctx.stroke();

      // Label on link
      const mx = (l.source.x + l.target.x) / 2;
      const my = (l.source.y + l.target.y) / 2;
      ctx.font = '9px JetBrains Mono';
      ctx.fillStyle = '#64748b';
      ctx.textAlign = 'center';
      ctx.fillText(l.relationship || '', mx, my - 3);
    });

    // Draw Nodes
    graphNodes.forEach(n => {
      const color = getNodeColor(n.type);
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.radius, 0, 2 * Math.PI);
      ctx.fillStyle = color;
      ctx.shadowColor = color;
      ctx.shadowBlur = (hoveredNode === n || n.metadata?.primary) ? 14 : 6;
      ctx.fill();
      ctx.shadowBlur = 0;

      ctx.lineWidth = (hoveredNode === n) ? 3 : 1.5;
      ctx.strokeStyle = '#ffffff';
      ctx.stroke();

      // Node label
      ctx.font = '11px Inter, sans-serif';
      ctx.fillStyle = '#f1f5f9';
      ctx.textAlign = 'center';
      ctx.fillText(n.label, n.x, n.y + n.radius + 14);
    });

    ctx.restore();
  }

  function getNodeColor(type) {
    switch (type) {
      case 'asset': return '#10b981'; // green
      case 'alert': return '#ef4444'; // red
      case 'ids': return '#f59e0b';   // yellow/amber
      case 'vulnerability': return '#06b6d4'; // cyan
      case 'ioc': return '#8b5cf6';   // purple
      case 'incident': return '#ec4899'; // pink
      default: return '#3b82f6';      // blue (primary/target)
    }
  }

  // Canvas Interactions (Drag / Hover)
  if (canvas) {
    canvas.addEventListener('mousedown', (e) => {
      const pos = getCanvasMousePos(e);
      draggedNode = getNodeAt(pos.x, pos.y);
    });

    window.addEventListener('mousemove', (e) => {
      const pos = getCanvasMousePos(e);
      if (draggedNode) {
        draggedNode.x = pos.x;
        draggedNode.y = pos.y;
        draggedNode.vx = 0;
        draggedNode.vy = 0;
      } else {
        hoveredNode = getNodeAt(pos.x, pos.y);
        canvas.style.cursor = hoveredNode ? 'pointer' : 'grab';
      }
    });

    window.addEventListener('mouseup', () => {
      draggedNode = null;
    });

    canvas.addEventListener('click', (e) => {
      const pos = getCanvasMousePos(e);
      const clicked = getNodeAt(pos.x, pos.y);
      if (clicked) {
        corrQueryInput.value = clicked.label;
        corrEntityType.value = clicked.type === 'vulnerability' ? 'cve' : (clicked.type || 'auto');
        runCorrelation();
      }
    });
  }

  function getCanvasMousePos(e) {
    const rect = canvas.getBoundingClientRect();
    return {
      x: (e.clientX - rect.left - transform.x) / transform.scale,
      y: (e.clientY - rect.top - transform.y) / transform.scale,
    };
  }

  function getNodeAt(x, y) {
    for (let i = graphNodes.length - 1; i >= 0; i--) {
      const n = graphNodes[i];
      const dx = n.x - x;
      const dy = n.y - y;
      if (Math.sqrt(dx * dx + dy * dy) <= n.radius + 4) {
        return n;
      }
    }
    return null;
  }

  if (btnResetGraph) {
    btnResetGraph.addEventListener('click', () => {
      if (currentEntity) {
        runCorrelation();
      }
    });
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

  function getSeverityBadgeClass(sev) {
    const s = String(sev || '').toUpperCase();
    if (s === 'CRITICAL') return 'bg-danger';
    if (s === 'HIGH') return 'bg-warning text-dark';
    if (s === 'MEDIUM' || s === 'MED') return 'bg-info text-dark';
    if (s === 'LOW') return 'bg-success';
    return 'bg-secondary';
  }

  // Pre-seed from URL parameters
  const urlParams = new URLSearchParams(window.location.search);
  const qParam = urlParams.get('q');
  if (qParam) {
    corrQueryInput.value = qParam;
    const tParam = urlParams.get('type');
    if (tParam) corrEntityType.value = tParam;
    runCorrelation();
  }

  loadCampaigns();
});

