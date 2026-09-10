# Testing Guide

CyberDefense XDR uses `pytest` as its primary testing framework. The test suite comprises 22 modules located in the `tests/unit/` directory.

## Current Baseline
The test suite maintains a high coverage standard, with a baseline of **315+ passing tests**.

## Test Database Requirements
> [!WARNING]
> Tests require a live PostgreSQL database to succeed. SQLite is **not** supported for testing because the application relies on PostgreSQL-specific data types (like `JSONB`) and features.

Ensure your `DATABASE_URL` in `.env` is configured properly (e.g., pointing to a local test database) before running the suite.

## Running Tests

**Run the entire test suite:**
```bash
venv/bin/pytest -q
```

**Run a specific test file with verbose output:**
```bash
venv/bin/pytest tests/unit/test_ai_assistant.py -v
```

**Run tests matching a specific pattern:**
```bash
venv/bin/pytest -k "scanner or integration" -v
```

## Test Structure & Organization

The tests are organized into the following 22 files, targeting specific subsystems:

| Test File | Description |
|-----------|-------------|
| `test_ai_assistant.py` | Validates LLM security constraints, prompt scrubbing, and context injection rules. |
| `test_alerts.py` | Tests alert generation, deduplication, and lifecycle transitions. |
| `test_analytics.py` | Ensures aggregation and trend calculation math is accurate. |
| `test_assets.py` | Tests asset inventory CRUD operations and status reporting. |
| `test_audit_logs.py` | Validates immutability, format, and CSV export sanitization. |
| `test_correlation.py` | Verifies cross-module rule correlation engines. |
| `test_frontend_static_references.py`| Validates HTML static asset links and script paths. |
| `test_ids.py` | Tests Suricata event parsing and severity mapping. |
| `test_ids_log_rotation.py` | Verifies log file lifecycle management and disk limits. |
| `test_notifications.py` | Tests notification delivery, read state, and broadcast actions. |
| `test_packet_analysis.py` | Tests PCAP validation, TShark wrapping, and filter safety. |
| `test_rbac_hardening.py` | Rigorous enforcement tests for role boundaries and IDOR prevention. |
| `test_realtime_clock.py` | Confirms accurate timezone and temporal functionality handling. |
| `test_reports.py` | Tests PDF/HTML report generation templates and data binding. |
| `test_route_collisions.py` | Blueprint regression testing to prevent overlapping URL routes. |
| `test_scanner.py` | Validates target normalization, shell-injection filters, and multi-tool execution paths. |
| `test_security_hardening.py` | Validates HTTP headers, CSRF configurations, and global security policies. |
| `test_siem.py` | Tests log ingestion, indexing logic, and query consistency. |
| `test_soar.py` | Ensures playbook logic executes correctly based on trigger conditions. |
| `test_soc_dashboard.py` | Validates SOC metric aggregators. |
| `test_threat_hunting.py` | Tests hypothesis query saving and historical lookups. |
| `test_user_management.py` | Covers profile updates, role assignments, and authentication logic. |
