# Incident Response

## Overview
The Incident Response module manages the lifecycle of security incidents. It acts as the central workbench for security analysts to investigate, contain, and resolve elevated threats, correlating data from Detection Events and Alerts.

## Architecture and Components

- **Models** (`app/incidents/models.py`): Defines the `Incident` database schema.
- **Routes** (`app/incidents/routes.py`): Handles the web views, dashboards, and REST API for incident management.
- **Services** (`app/incidents/services.py`): Encapsulates business logic, including lifecycle state transitions and notifications.

## Data Models

### Incident
- `incident_id`: Unique identifier (e.g., `INC-123456`).
- `title`, `description`, `category`.
- `severity`, `priority` (critical, high, medium, low).
- `status`: Lifecycle phase (`new`, `investigating`, `contained`, `resolved`, `closed`).
- `assigned_to`, `created_by`: Foreign keys to `User`.
- `source`, `detection_event_id`: Traceability back to the origin.
- `affected_host`, `affected_asset`: Identifies the target of the incident.
- `mitre_id`, `mitre_name`: MITRE ATT&CK framework mapping.
- `investigation_notes`, `containment_notes`, `resolution_notes`: Analyst documentation.
- `detected_at`, `created_at`, `updated_at`, `resolved_at`: Timestamps.

## API Endpoints

All endpoints are registered under the `/incidents` blueprint.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/dashboard` | GET | Renders the incident dashboard with metrics. |
| `/` | GET | Renders the incident list view. |
| `/data` | GET | Returns all incidents in JSON format. |
| `/create` | GET, POST | Creates a new incident manually. |
| `/<incident_id>` | GET | Renders the incident details page. |
| `/<incident_id>/data` | GET | Returns JSON data for a specific incident. |
| `/<incident_id>/update` | POST | Updates incident properties. |
| `/<incident_id>/assign` | POST | Assigns the incident to a specific user. |
| `/<incident_id>/status` | POST | Changes the incident lifecycle status. |
| `/<incident_id>/resolve` | POST | Marks an incident as resolved with notes. |
| `/<incident_id>/close` | POST | Marks a resolved incident as closed. |
| `/<incident_id>/delete` | POST | Permanently deletes an incident. |
| `/from-detection/<event_id>` | POST | Escalates a detection event into an incident. |
| `/<incident_id>/evidence` | GET | Renders the evidence locker view. |
| `/<incident_id>/timeline` | GET | Renders the investigation timeline view. |
| `/playbooks` | GET | Renders the playbooks/workflows page. |

## Service Logic

### Lifecycle Management
Incidents progress through standard IR phases: `new` -> `investigating` -> `contained` -> `resolved` -> `closed`. Status changes are handled via `change_status`, `resolve_incident`, and `close_incident` in `services.py`. 

### Incident Escalation
The system allows seamless escalation from a `DetectionEvent` to an `Incident` using `create_incident_from_detection()`. This pre-populates the incident with host, severity, and MITRE data.

### Notifications
When an incident is created or assigned, the service layer dispatches notifications to the assigned user or users with appropriate permissions via the `app.notifications.services` module.

## Workflows and SOAR

- **Evidence Timeline**: The routes support `/evidence` and `/timeline` endpoints to render investigation views for analysts.
- **Containment Workflows & SOAR**: The platform provides a `/playbooks` route for response playbooks. *Note: Fully automated external SOAR integrations (e.g., executing scripts on external firewalls automatically) are partially mocked in the UI and are environment-dependent. They require specific configuration in the deployment environment.*

## Limitations
- Evidence locker currently relies on text notes; file attachment capabilities are limited or require external storage configuration.
