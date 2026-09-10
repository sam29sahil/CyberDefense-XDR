# Detection Engine

## Overview
The Detection Engine in CyberDefense XDR is responsible for managing detection rules and generating detection events. It provides a structured mechanism to define criteria (rules) and record instances where these criteria are met (events). It integrates with the SIEM and Alert Center to elevate critical findings.

## Architecture and Components

The module is structured into Models, Routes, and Services:
- **Models** (`app/detection/models.py`): Define the database schema for rules and events.
- **Routes** (`app/detection/routes.py`): Provide the REST APIs and web views for rule management and event history.
- **Services** (`app/detection/services.py`): Handle the core business logic, including CRUD operations and event persistence.

## Data Models

### DetectionRule
Stores the logic and metadata for a detection rule.
- `rule_id`: Unique string (e.g., `DET-123456`).
- `name`, `description`, `category`, `severity` (critical, high, medium, low).
- `mitre_id`, `mitre_name`: Mapping to MITRE ATT&CK.
- `status`: Lifecycle status (`active`, `testing`, `disabled`).
- `conditions`, `actions`, `tags`: Stored as JSON text.
- `triggers_30d`, `false_positive_rate`: Metrics.

### DetectionEvent
Represents an instance where a rule condition was met.
- `event_id`: Unique string (e.g., `EVT-123456`).
- `rule_id`: Foreign key to `DetectionRule`.
- `timestamp`, `source`, `host`, `severity`, `status`.
- `mitre_id`: Inherited or specific MITRE ATT&CK mapping.
- `raw_event`: The underlying telemetry that triggered the event, stored as text/JSON.

## API Endpoints

All endpoints are registered under the `/detection` blueprint.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/dashboard` | GET | Renders the detection dashboard. |
| `/rules` | GET | Renders the rule management UI. |
| `/rules/data` | GET | Returns all rules in JSON format. |
| `/rules/create` | GET, POST | Renders rule creation form or creates a new rule. |
| `/rules/<rule_id>` | GET | Renders details for a specific rule. |
| `/rules/<rule_id>/data` | GET | Returns JSON data for a specific rule. |
| `/rules/<rule_id>/update` | POST | Updates an existing rule. |
| `/rules/<rule_id>/toggle` | POST | Toggles rule status (active/disabled). |
| `/rules/<rule_id>/duplicate` | POST | Clones an existing rule. |
| `/rules/<rule_id>/delete` | POST | Deletes a rule. |
| `/history` | GET | Renders the detection events history UI. |
| `/history/data` | GET | Returns detection events in JSON format. |
| `/events` | POST | Creates a new detection event manually or programmatically. |

## Service Logic

### Rule Management
Rules can be created, updated, duplicated, toggled, and deleted via `services.py`. All operations are logged via the Audit Engine (`record_audit_event`). Rule IDs are auto-generated with the prefix `DET-`.

### Rule Matching Logic
The explicit matching logic of rules against real-time telemetry is distributed. Specifically, the SIEM module (`app/siem/services.py`) evaluates incoming logs (`trigger_detection_evaluation`) against active rules based on severity and Threat Intel IOC matches. If a match occurs, it calls `create_detection_event`.

### Event Persistence
The `create_detection_event` function creates a `DetectionEvent`, increments the rule's `triggers_30d` counter, and automatically attempts to generate a corresponding alert in the Alert Center (`create_alert_from_detection_event`).

## Limitations and Notes
- **Advanced Conditions**: Rule `conditions` and `actions` are currently stored as JSON, and the complex parsing and real-time execution engine over arbitrary fields is partially implemented (relies primarily on SIEM severity/IOC hooks).
- **Rule Engine Scale**: Complex aggregations or stateful correlation rules over time windows are handled downstream by the Correlation Engine.
