# Threat Intelligence

## Overview
The Threat Intelligence module acts as the centralized repository for Indicators of Compromise (IOCs), Threat Feeds, Threat Actors, and Campaigns. It provides enrichment data for other modules (like the Vulnerability Scanner and Network IDS) to correlate local observations with global threat intelligence.

## Architecture and Components

### Data Models
- **IOC (Indicator of Compromise)**: Tracks individual observables (IPs, domains, hashes) along with their threat level, confidence, source, and lifecycle status (active, expired, whitelisted).
- **ThreatFeed**: Manages external intelligence sources (Open Source, Commercial) and tracks their sync status and reliability.
- **ThreatActor**: Profiles known advanced persistent threats (APTs) or threat groups, including their origin, motivations, targeted sectors, and MITRE ATT&CK tactics.
- **ThreatCampaign**: Represents specific operations or campaigns associated with Threat Actors, linking multiple IOCs and TTPs to a single coordinated event.

### Route Architecture & Content Negotiation
The module employs a hybrid routing architecture that serves both Web UI and REST API clients from the same endpoint paths using content negotiation.
- `_wants_html()` checks the `Accept` headers and query parameters (e.g., `?format=json`). If the client prefers HTML, it renders a Jinja template; otherwise, it returns standard JSON responses. This allows endpoints like `/threat-intelligence/campaigns` to seamlessly serve both analysts using the browser and automated API integrations.

## Service Logic
- **Enrichment (`enrich_ioc`)**: Correlates IPs, domains, or URLs with existing Threat Intelligence records to provide contextual data during alert generation or vulnerability scanning.
- **Statistics (`get_dashboard_statistics`)**: Aggregates data across all models to power the Threat Intelligence dashboard visualizations (e.g., severity distributions, active vs. expired IOCs).
- **Lifecycle Management**: Provides capabilities to expire old IOCs, update feed sync statuses, and manage the attribution links between IOCs, Campaigns, and Actors.

## API Endpoints
- `GET /threat-intelligence/iocs` - Paginated IOCs with filtering (type, threat level, status).
- `POST /threat-intelligence/iocs` - Create a new manual IOC.
- `GET /threat-intelligence/campaigns` - Retrieves campaigns (supports HTML rendering).
- `GET /threat-intelligence/feeds` - Retrieves configured threat feeds.
- `GET /threat-intelligence/actors` - Retrieves threat actor profiles.
- `GET /threat-intelligence/dashboard/data` - Returns aggregated metrics for the dashboard.
