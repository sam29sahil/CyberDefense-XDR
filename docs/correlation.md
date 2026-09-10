# Correlation Engine

## Overview
The Correlation Engine is a central intelligence layer in CyberDefense XDR. It discovers multidirectional relationships between assets, telemetry, detections, IOCs, and incidents. It computes deterministic risk scores and generates graph structures to help analysts visualize complex attacks.

## Architecture and Components

- **Routes** (`app/correlation/routes.py`): Exposes API endpoints for searching entities, generating graphs, and identifying campaigns.
- **Services** (`app/correlation/services.py`): Implements the core logic for risk scoring, entity correlation across modules, and campaign detection.

## Data Models
The Correlation Engine does not maintain its own primary database tables; instead, it dynamically queries and correlates data across all other modules (Assets, Alerts, Incidents, Vulnerabilities, IDS Events, SIEM Logs, Threat Intel).

## API Endpoints

All endpoints are registered under the `/correlation` blueprint.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Renders the Correlation dashboard. |
| `/api/entity/<type>/<id>` | GET | Returns full correlation data, risk scoring, and graph payload. |
| `/api/search` | POST | Searches for relationships matching an input query entity. |
| `/api/graph/<type>/<id>`| GET | Returns D3/vis-compatible nodes and links graph visualization payload. |
| `/api/campaigns` | GET | Returns active cross-asset and multi-vector attack campaigns. |

## Service Logic

### Entity Correlation Across Data Sources
The `correlate_entity(entity_type, entity_id)` function aggregates context around a given entity (e.g., an IP, asset, or CVE). 
It discovers relationships by querying:
- **Assets**: Matches IPs or hostnames.
- **Alerts**: Matches affected hosts.
- **Incidents**: Traces linked alerts and affected hosts.
- **Vulnerabilities**: Matches CVEs or vulnerable hosts.
- **IDS Events**: Matches source or destination IPs.
- **SIEM Logs**: Matches IPs or hostnames in raw logs or parsed fields.
- **Threat Intel**: Matches IOC values.

### Risk Scoring Algorithm
`calculate_risk_score()` computes a deterministic `0-100` score based on contributing factors:
- **Alerts**: Critical (+25 ea, max 50), High (+15 ea, max 30), Medium (+5 ea, max 15).
- **IDS Events**: High severity (+20), Standard (+10).
- **Vulnerabilities**: Critical CVEs (+15 ea, max 30), High CVEs (+10 ea, max 20).
- **Threat Intel**: Critical/High IOCs (+25), Standard IOCs (+15).
- **Incidents**: Active investigations (+20).
- **Asset Value**: Critical asset (+15), High asset (+10).
- **Synergy Multiplier**: Multi-vector attacks across 3+ layers (+15), 2+ layers (+10).

The resulting score categorizes the risk as CLEAN, LOW, MEDIUM, HIGH (>=60), or CRITICAL (>=80). It also returns human-readable justification strings.

### Diagnostic Noise Exclusion
To ensure accuracy, the engine specifically filters out known benign or diagnostic noise. For example, IDS events with Signature ID `2200074` (invalid checksums) are strictly ignored during risk calculation, graph building, and campaign detection.

### Graph Building
`build_correlation_graph()` generates a JSON payload representing a directed graph (nodes and links) compatible with visualization libraries (like D3 or vis.js). Entities are represented as nodes, and relationships (e.g., `hosts`, `detected_on`, `attacks`, `affects`) are represented as weighted links.

### Campaign Detection
`find_campaigns()` automatically identifies coordinated attacks:
1. **Multi-target Attacks**: Identifies external attacker IPs that are triggering IDS events against 2 or more distinct internal network hosts.
2. **Multi-vector Compromise**: Identifies specific assets that have both active critical/high vulnerabilities and active security alerts simultaneously.

## Limitations
- Heavy queries: The correlation logic performs multiple database lookups across large tables in real-time. Extreme dataset sizes may require caching or pre-computation.
