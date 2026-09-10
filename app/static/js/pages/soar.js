/**
 * SOAR Automation Client Controller
 */
document.addEventListener('DOMContentLoaded', () => {
  const playbooksGrid = document.getElementById('playbooksGrid');
  const tblExecutionsBody = document.getElementById('tblExecutionsBody');
  const tblApprovalsBody = document.getElementById('tblApprovalsBody');
  const countExecutions = document.getElementById('countExecutions');
  const countAllApprovals = document.getElementById('countAllApprovals');
  const pendingApprovalsBadge = document.getElementById('pendingApprovalsBadge');
  const pendingApprovalsGrid = document.getElementById('pendingApprovalsGrid');
  const approvalsSection = document.getElementById('approvalsSection');

  const runPlaybookModal = new bootstrap.Modal(document.getElementById('runPlaybookModal'));
  const executionDetailsModal = new bootstrap.Modal(document.getElementById('executionDetailsModal'));
  const runPlaybookForm = document.getElementById('runPlaybookForm');
  const modalPlaybookId = document.getElementById('modalPlaybookId');
  const modalTargetId = document.getElementById('modalTargetId');
  const modalTargetType = document.getElementById('modalTargetType');
  const runModalTitle = document.getElementById('runModalTitle');
  const btnConfirmRun = document.getElementById('btnConfirmRun');
  const confirmSpinIcon = document.getElementById('confirmSpinIcon');

  const runModalEl = document.getElementById('runPlaybookModal');
  if (runModalEl) {
    runModalEl.addEventListener('shown.bs.modal', () => {
      if (modalTargetId) {
        modalTargetId.focus();
      }
    });
  }

  const btnRefreshExecutions = document.getElementById('btnRefreshExecutions');

  // Load Playbooks
  function loadPlaybooks() {
    fetch('/soar/api/playbooks')
      .then(res => res.json())
      .then(data => {
        if (!playbooksGrid) return;
        if (!data.playbooks || data.playbooks.length === 0) {
          playbooksGrid.innerHTML = '<div class="text-muted text-center py-5">No playbooks found</div>';
          return;
        }
        playbooksGrid.innerHTML = data.playbooks.map(p => `
          <div class="col-md-6 col-lg-4">
            <div class="card playbook-card p-3 h-100 d-flex flex-column justify-content-between">
              <div>
                <div class="d-flex justify-content-between align-items-center mb-2">
                  <span class="badge bg-secondary small">${escapeHtml(p.category)}</span>
                  <span class="badge bg-dark border border-secondary text-info cell-mono small">${escapeHtml(p.target_type)}</span>
                </div>
                <h6 class="text-light fw-bold mb-2">${escapeHtml(p.name)}</h6>
                <p class="text-muted small mb-3">${escapeHtml(p.description)}</p>
              </div>
              <div>
                <button class="btn btn-outline-warning btn-sm w-100 fw-semibold btn-launch-playbook" data-id="${p.id}" data-name="${escapeHtml(p.name)}" data-target="${p.target_type}">
                  <i class="bi bi-play-fill me-1"></i>Configure &amp; Run
                </button>
              </div>
            </div>
          </div>
        `).join('');

        playbooksGrid.querySelectorAll('.btn-launch-playbook').forEach(btn => {
          btn.addEventListener('click', () => {
            modalPlaybookId.value = btn.dataset.id;
            modalTargetType.value = btn.dataset.target || 'alert';
            runModalTitle.textContent = `Run: ${btn.dataset.name}`;
            modalTargetId.value = '';
            runPlaybookModal.show();
          });
        });
      })
      .catch(err => console.error('Failed to load playbooks:', err));
  }

  // Load Approvals
  function loadApprovals() {
    fetch('/soar/api/approvals')
      .then(res => res.json())
      .then(data => {
        const approvals = data.approvals || [];
        if (countAllApprovals) countAllApprovals.textContent = approvals.length;

        // Pending banner
        const pending = approvals.filter(a => a.status === 'pending');
        if (pendingApprovalsBadge) pendingApprovalsBadge.textContent = pending.length;

        if (pending.length > 0 && approvalsSection && pendingApprovalsGrid) {
          approvalsSection.style.display = 'block';
          pendingApprovalsGrid.innerHTML = pending.map(a => `
            <div class="col-md-6">
              <div class="card approval-card p-3 h-100">
                <div class="d-flex justify-content-between align-items-center mb-2">
                  <strong class="text-warning">${escapeHtml(a.action_name)}</strong>
                  <span class="badge bg-warning text-dark cell-mono">PENDING APPROVAL</span>
                </div>
                <p class="text-light small mb-2">${escapeHtml(a.expected_impact)}</p>
                <div class="cell-mono small text-muted mb-3">Target: ${escapeHtml(a.target_entity_type)} / ${escapeHtml(a.target_entity_id)}</div>
                <div class="d-flex gap-2">
                  <button class="btn btn-success btn-sm btn-approve" data-id="${a.approval_id}">
                    <i class="bi bi-check-lg me-1"></i>Approve &amp; Apply
                  </button>
                  <button class="btn btn-outline-danger btn-sm btn-reject" data-id="${a.approval_id}">
                    <i class="bi bi-x-lg me-1"></i>Reject
                  </button>
                </div>
              </div>
            </div>
          `).join('');

          pendingApprovalsGrid.querySelectorAll('.btn-approve').forEach(b => {
            b.addEventListener('click', () => handleApprovalDecision(b.dataset.id, 'approve'));
          });
          pendingApprovalsGrid.querySelectorAll('.btn-reject').forEach(b => {
            b.addEventListener('click', () => handleApprovalDecision(b.dataset.id, 'reject'));
          });
        } else if (approvalsSection) {
          approvalsSection.style.display = 'none';
        }

        // Table
        if (tblApprovalsBody) {
          if (approvals.length === 0) {
            tblApprovalsBody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-4">No approval requests recorded.</td></tr>';
            return;
          }
          tblApprovalsBody.innerHTML = approvals.map(a => `
            <tr>
              <td class="cell-mono text-muted small">${escapeHtml(a.approval_id.substring(0, 8))}...</td>
              <td><strong class="text-light">${escapeHtml(a.action_name)}</strong></td>
              <td class="cell-mono small text-info">${escapeHtml(a.target_entity_type)}: ${escapeHtml(a.target_entity_id)}</td>
              <td><span class="badge ${a.status === 'approved' ? 'bg-success' : (a.status === 'rejected' ? 'bg-danger' : 'bg-warning text-dark')}">${escapeHtml(a.status)}</span></td>
              <td class="small text-muted">${escapeHtml(a.expected_impact)}</td>
              <td class="cell-mono small text-muted">${formatDateTime(a.requested_at)}</td>
              <td class="small text-light">${escapeHtml(a.decision_notes || '-')}</td>
            </tr>
          `).join('');
        }
      })
      .catch(err => console.error('Failed to load approvals:', err));
  }

  function handleApprovalDecision(approvalId, action) {
    const notes = prompt(`Notes for ${action} decision:`, `Action ${action}d by analyst`);
    if (notes === null) return;

    fetch(`/soar/api/approvals/${approvalId}/${action}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ notes: notes })
    })
      .then(res => res.json())
      .then(data => {
        if (data.status === 'success') {
          alert(`Successfully marked as ${action}d.`);
          loadApprovals();
          loadExecutions();
        } else {
          alert(`Failed: ${data.message}`);
        }
      })
      .catch(err => console.error('Approval decision failed:', err));
  }

  // Load Executions
  function loadExecutions() {
    fetch('/soar/api/executions')
      .then(res => res.json())
      .then(data => {
        const executions = data.executions || [];
        if (countExecutions) countExecutions.textContent = executions.length;
        if (!tblExecutionsBody) return;

        if (executions.length === 0) {
          tblExecutionsBody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-4">No playbook executions recorded.</td></tr>';
          return;
        }

        tblExecutionsBody.innerHTML = executions.map(ex => `
          <tr>
            <td class="cell-mono text-info small">${escapeHtml(ex.execution_id.substring(0, 8))}...</td>
            <td><strong class="text-light">${escapeHtml(ex.playbook_name)}</strong></td>
            <td class="cell-mono small text-light">${escapeHtml(ex.target_entity_type)}: ${escapeHtml(ex.target_entity_id)}</td>
            <td><span class="badge ${getStatusBadge(ex.status)}">${escapeHtml(ex.status)}</span></td>
            <td class="cell-mono small text-muted">${formatDateTime(ex.started_at)}</td>
            <td class="small text-muted text-truncate" style="max-width: 250px;">${escapeHtml(ex.summary || '-')}</td>
            <td>
              <button class="btn btn-outline-info btn-xs py-0 px-2 btn-view-exec" data-id="${ex.execution_id}">
                Audit Log
              </button>
            </td>
          </tr>
        `).join('');

        tblExecutionsBody.querySelectorAll('.btn-view-exec').forEach(btn => {
          btn.addEventListener('click', () => {
            viewExecutionDetails(btn.dataset.id);
          });
        });
      })
      .catch(err => console.error('Failed to load executions:', err));
  }

  function viewExecutionDetails(execId) {
    fetch(`/soar/api/executions/${execId}`)
      .then(res => res.json())
      .then(data => {
        if (data.status === 'success' && data.execution) {
          const ex = data.execution;
          document.getElementById('execModalTitle').textContent = `${ex.playbook_name} [${ex.execution_id.substring(0, 8)}]`;
          document.getElementById('execModalSummary').textContent = ex.summary || 'No summary generated.';

          const stepsEl = document.getElementById('execModalSteps');
          const steps = ex.execution_steps || [];
          if (steps.length === 0) {
            stepsEl.innerHTML = '<div class="text-muted">No step logs recorded.</div>';
          } else {
            stepsEl.innerHTML = steps.map(s => `
              <div class="execution-step-row ${s.status === 'completed' ? 'step-completed' : (s.status === 'failed' ? 'step-failed' : 'step-pending')}">
                <div class="d-flex justify-content-between align-items-center">
                  <strong class="text-light">${escapeHtml(s.step)}</strong>
                  <span class="badge ${getStatusBadge(s.status)} small">${escapeHtml(s.status)}</span>
                </div>
                <div class="text-muted small cell-mono">${formatDateTime(s.timestamp)}</div>
                ${s.details ? `<pre class="text-info small mb-0 mt-1" style="font-size:0.75rem;">${escapeHtml(JSON.stringify(s.details, null, 2))}</pre>` : ''}
              </div>
            `).join('');
          }

          document.getElementById('execModalJson').textContent = JSON.stringify(ex.results || {}, null, 2);
          executionDetailsModal.show();
        }
      })
      .catch(err => console.error('Failed to load execution details:', err));
  }

  // Execute Form
  runPlaybookForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const playbookId = modalPlaybookId.value;
    const targetId = modalTargetId.value.trim();
    const targetType = modalTargetType.value;

    if (!targetId) return;

    btnConfirmRun.disabled = true;
    confirmSpinIcon.className = 'spinner-border spinner-border-sm me-1';

    fetch(`/soar/api/playbooks/${playbookId}/execute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target_id: targetId,
        target_type: targetType,
      })
    })
      .then(res => res.json())
      .then(data => {
        btnConfirmRun.disabled = false;
        confirmSpinIcon.className = 'bi bi-play-fill me-1';
        runPlaybookModal.hide();

        if (data.status === 'success') {
          alert('Playbook execution completed successfully.');
          loadExecutions();
          loadApprovals();
          // Switch to executions tab
          const tab = document.getElementById('tab-executions');
          if (tab) bootstrap.Tab.getOrCreateInstance(tab).show();
        } else {
          alert(`Execution error: ${data.message}`);
        }
      })
      .catch(err => {
        btnConfirmRun.disabled = false;
        confirmSpinIcon.className = 'bi bi-play-fill me-1';
        console.error('Playbook run failed:', err);
        alert('Network or server error running playbook.');
      });
  });

  if (btnRefreshExecutions) {
    btnRefreshExecutions.addEventListener('click', () => {
      loadExecutions();
      loadApprovals();
    });
  }

  // Helpers
  function getStatusBadge(st) {
    const s = String(st || '').toLowerCase();
    if (s === 'completed') return 'bg-success';
    if (s === 'running') return 'bg-primary';
    if (s === 'pending_approval' || s === 'pending') return 'bg-warning text-dark';
    if (s === 'failed') return 'bg-danger';
    return 'bg-secondary';
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function formatDateTime(val) {
    if (!val) return '-';
    try {
      const d = new Date(val);
      if (isNaN(d.getTime())) return String(val);
      return d.toISOString().replace('T', ' ').substring(0, 19);
    } catch {
      return String(val);
    }
  }

  // Pre-seed from URL
  const urlParams = new URLSearchParams(window.location.search);
  const qParam = urlParams.get('q');
  if (qParam) {
    modalTargetId.value = qParam;
    const tParam = urlParams.get('type');
    if (tParam) modalTargetType.value = tParam;
    modalPlaybookId.value = 'suspicious_ip_investigation';
    runModalTitle.textContent = 'Execute Playbook';
    runPlaybookModal.show();
  }

  loadPlaybooks();
  loadApprovals();
  loadExecutions();
});

