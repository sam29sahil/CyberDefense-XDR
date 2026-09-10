# SIEM & Log Explorer

## Overview
The SIEM (Security Information and Event Management) module is the core data lake for CyberDefense XDR. It handles the ingestion, indexing, correlation, and querying of raw security logs from various sources.

## Architecture and Components

- **Models** (`app/siem/models.py`): Defines `SiemEvent` (logs) and `SiemSavedSearch` (queries).
- **Routes** (`app/siem/routes.py`): Exposes the Log Explorer interface and REST APIs for searching and ingestion.
- **Services** (`app/siem/services.py`): Handles log ingestion, bulk processing, IOC correlation, and complex querying.

## Data Models

### SiemEvent
Represents a centralized log entry.
- `event_id`: Unique identifier (e.g., `LOG-123456`).
- `timestamp`: Event occurrence time.
- `severity`: `critical`, `high`, `medium`, `low`, `info`.
- `category`, `source`, `host`: Metadata for filtering.
- `message`, `raw_log`: Text content of the log.
- `fields_json`: Parsed key-value fields stored as JSON text.
- `tags_json`: Array of tags stored as JSON text.
- `ioc_match_id`: Foreign key reference to a matched Threat Intel IOC.
- `detection_event_id`: Reference to a DetectionEvent if the log triggered a rule.

### SiemSavedSearch
Stores saved Log Explorer queries.
- `search_id`: Unique identifier (e.g., `SRCH-42`).
- `name`, `description`, `query_text` (Lucene-like syntax or keywords).
- `owner`, `scope` (Team/Private).
- `pinned`, `alerting`: Flags for dashboard visibility and background alerting.
- `filters_json`: Stored filter states.

## API Endpoints

All endpoints are registered under the `/siem` blueprint.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` or `/dashboard` | GET | Renders the SIEM dashboard view. |
| `/log-explorer` | GET | Renders the Log Explorer interface. |
| `/api/dashboard` | GET | Returns aggregated SIEM stats, charts, and stream. |
| `/api/logs` | GET | Returns paginated, searchable, filtered logs. |
| `/api/logs/filter-options` | GET | Returns unique sources, hosts, categories, tags. |
| `/api/logs/<event_id>` | GET | Returns details and related logs for a specific event. |
| `/api/events` | POST | Ingests one or more logs into the SIEM pipeline. |
| `/api/saved-searches` | GET, POST | Lists or creates saved searches. |
| `/api/saved-searches/<id>/pin` | POST | Toggles the pinned status of a saved search. |
| `/api/saved-searches/<id>` | DELETE | Deletes a saved search. |

## Service Logic

### Event Ingestion and Correlation
The `ingest_event` and `ingest_events_bulk` functions process incoming logs. During ingestion:
1. **Threat Intel Correlation**: Extracts IPs, domains, and hashes from `fields` and `message` and checks them against known IOCs (`correlate_threat_intel`).
2. **Detection Evaluation**: If the log matches an IOC or has a high/critical severity, it triggers the Detection Engine (`trigger_detection_evaluation`) to generate a `DetectionEvent`.

### Search and Indexing
The Log Explorer uses `get_logs()` to provide powerful search capabilities:
- Supports filtering by severity, source, host, category, tag, and time range.
- Implements full-text search across `message`, `host`, `source`, `event_id`, and `raw_log` using SQLAlchemy `ilike`.

### Dashboard Statistics
`get_siem_dashboard_stats()` computes 24-hour KPIs, including Event Per Second (EPS), severity distributions, top sources, noisiest hosts, and a live log stream.

## Limitations and Notes
- **Scalability**: While the models use PostgreSQL text fields for JSON, extreme high-volume logging (10k+ EPS) may require migrating the underlying storage of `SiemEvent` to Elasticsearch or OpenSearch. The current implementation uses relational DB filtering.
