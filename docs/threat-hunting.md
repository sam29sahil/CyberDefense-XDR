# Threat Hunting

## Overview
The Threat Hunting module enables security analysts to perform proactive, federated searches across the entire XDR dataset. It provides a unified view of an entity's security profile, aggregates chronological timelines, and allows analysts to save and track their hunting queries.

## Architecture and Components

- **Models** (`app/threat_hunting/models.py`): Defines `ThreatHuntQuery` to store search history and bookmarks.
- **Routes** (`app/threat_hunting/routes.py`): Provides the API for multi-domain search, timelines, and entity profiles.
- **Services** (`app/threat_hunting/services.py`): Executes federated searches across multiple Postgres tables and aggregates results.

## Data Models

### ThreatHuntQuery
Stores analyst queries, history, and saved searches. It does *not* duplicate telemetry.
- `hunt_id`: Unique identifier (e.g., `HUNT-ABC12345`).
- `title`, `query_text`: The search string.
- `entity_type`: The detected type of the query (e.g., `ip`, `hash`).
- `filters_json`: Applied search filters (time range, severity, module).
- `result_count`: Number of matches found.
- `is_saved`: Boolean indicating if the query is bookmarked.
- `user_id`: The analyst who ran the query.

## API Endpoints

All endpoints are registered under the `/threat-hunting` blueprint.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/dashboard` | GET | Renders the Threat Hunting dashboard. |
| `/api/summary` | GET | Returns overview statistics of searchable telemetry. |
| `/api/search` | POST | Executes a multi-domain hunt search. |
| `/api/timeline` | GET | Returns a unified chronological threat timeline. |
| `/api/entity/<type>/<id>`| GET | Returns a 360-degree security profile for a given entity. |
| `/api/history` | GET | Returns analyst search history. |
| `/api/saved-searches` | GET, POST | Returns or saves bookmarked hunting searches. |

## Service Logic

### Entity Type Auto-Detection
The `detect_entity_type()` function uses heuristics and regex to automatically classify the search query. It can detect:
- IP Addresses
- Cryptographic Hashes (MD5, SHA-1, SHA-256)
- CVE identifiers
- URLs and Domains
- Specific XDR record IDs (e.g., `ALT-`, `INC-`, `AST-`, `IOC-`)

### Federated Multi-Domain Search
The core function `execute_hunt()` performs a federated search across multiple database tables depending on the query and active filters. It queries:
1. Assets (`Asset`)
2. Alerts (`Alert`)
3. Incidents (`Incident`)
4. IDS Events (`NetworkIDSEvent`)
5. SIEM Logs (`SiemEvent`)
6. Detections (`DetectionEvent`, `DetectionRule`)
7. Vulnerabilities (`VulnerabilityFinding`)
8. Threat Intel (`IOC`)
9. Packet Analysis (`PacketAnalysis`)

It returns results partitioned by module, a total match count, and a unified timeline.

### Unified Chronological Timeline
While fetching data from the various tables, `execute_hunt` constructs a standardized timeline object for each event (normalizing timestamps, severities, event types, and deep links). The timeline is sorted chronologically descending.

### Entity Profiles
`get_entity_profile()` utilizes the hunt engine over a 90-day window to generate a comprehensive 360-degree view of an entity. It computes:
- First seen and last seen timestamps.
- Severity distributions across all events.
- Direct links to resolved assets and known IOCs.

## Limitations
- **Full Table Scans**: Because the search leverages `ilike` and wildcard strings across multiple large tables, performance may degrade on very large databases without proper text indexing or external search engines (like Elasticsearch).
