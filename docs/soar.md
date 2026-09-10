# SOAR (Security Orchestration, Automation, and Response)

## Overview
The SOAR module handles orchestrated execution of predefined incident response workflows. It features human-in-the-loop approvals for state-changing operations and forbids direct shell execution for safety and compliance.

## Architecture
- **Playbook Execution**: Playbooks run Python logic deterministically on local data models. 
- **Approval Workflow**: High-impact state changes (like elevating an alert to an incident or isolating an asset) trigger a pending `SoarApproval` record instead of modifying state directly.
- **Audit Integration**: Execution runs, approvals, and rejections are heavily audited and dispatch multi-channel notifications.

## Playbook Catalog
10 safe, non-destructive playbooks are implemented:
1. **alert_investigation**: Correlates alert with asset metadata, IDS threat signatures, and SIEM logs.
2. **critical_alert_escalation**: Verifies high-risk indicators and stages an incident response escalation approval.
3. **incident_enrichment**: Gathers asset exposure, related alerts, and attack timelines for an active incident.
4. **ioc_enrichment**: Checks IOCs against SIEM logs and IDS detections.
5. **vulnerability_triage**: Evaluates affected assets for a target CVE, checks exploit signatures.
6. **asset_risk_investigation**: Runs a full security audit on an endpoint (alerts, CVEs).
7. **ids_alert_investigation**: Analyzes Suricata signatures and filters diagnostic noise (SID 2200074).
8. **phishing_investigation**: Correlates suspicious domain with threat intel feeds, DNS query logs, and gateway alerts.
9. **malware_investigation**: Queries threat intel for file hash matches and searches SIEM endpoint logs.
10. **suspicious_ip_investigation**: Cross-references suspicious IPs against network, IDS, and IOC feeds.

*Note: Shell executions are strictly prohibited.*

## Execution Lifecycle
1. **Trigger**: `/api/playbooks/<playbook_id>/execute` receives target and parameters.
2. **Run**: `trigger_playbook_execution` creates a `SoarPlaybookExecution` (status: "running").
3. **Steps Evaluation**: `execute_playbook_logic` evaluates the playbook code deterministically.
4. **Stage Changes**: If state-changing actions are required (e.g. `critical_alert_escalation`), it generates a `SoarApproval` record instead of executing them.
5. **Store**: Steps, summaries, and results are serialized to JSON. Status updates to "completed".
6. **Notify**: A notification is dispatched detailing success or failure.
7. **Audit**: The transaction is saved in `AuditLog`.

## Approval Workflow
- Approvals are retrieved via `/api/approvals`.
- `/api/approvals/<approval_id>/approve`: Accepts the pending action. `execute_approved_action` reads the `change_payload_json` and performs the state update (e.g., updates alert status to `resolved`, or creates an `Incident`).
- `/api/approvals/<approval_id>/reject`: Rejects the action with decision notes; no system state is altered.

## Models

### SoarPlaybookExecution
- Trackers: `execution_id`, `playbook_id`, `playbook_name`
- Target: `target_entity_type`, `target_entity_id`
- Progress: `status` ("running", "completed", "failed")
- Data: `input_params_json`, `execution_steps_json`, `results_json`, `summary`, `error_message`
- Metadata: `user_id`, `started_at`, `completed_at`

### SoarApproval
- Identifiers: `approval_id`, `execution_id`
- Action Data: `action_type`, `action_name`, `target_entity_type`, `target_entity_id`, `change_payload_json`, `expected_impact`
- Lifecycle: `status` ("pending", "approved", "rejected"), `decision_notes`, `requested_by_id`, `decided_by_id`

## Limitations / Notes
- No direct remote endpoint remediation (like executing bash on remote hosts). State changes only apply to local XDR database records.
