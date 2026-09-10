# Database Schema & Models

CyberDefense XDR utilizes PostgreSQL with SQLAlchemy ORM. The schema consists of 31 tables grouped into 17 functional modules.

## Database Initialization
The database schema is managed via **Alembic / Flask-Migrate**.
To initialize or upgrade your database, run:
```bash
flask --app run.py db upgrade
```

## Migration History
The project includes 23 migration files under `migrations/versions/`. Migrations handle creating tables, applying indexes, adding foreign constraints, and introducing RBAC fields over the lifecycle of the project. A baseline script `2567802aa611_initial_database_schema.py` establishes the core tables, with subsequent files adding integrations, incidents, SIEM events, vulnerability scanner tools, alert centers, etc.

---

## Core Models grouped by Module

### Auth & User Management
| Model Name | Table Purpose |
|------------|---------------|
| `User` | Core authentication model, tracking roles, active status, profiles, and password hashes. |

### Settings & Configuration
| Model Name | Table Purpose |
|------------|---------------|
| `SecuritySettings` | Global application security configurations. |
| `NotificationSettings` | Global or user-specific notification preferences. |
| `APIKey` | Management of generated API keys for programmatic access. |
| `Integration` | Stores configuration and status of third-party tool integrations. |
| `GeneralSettings` | Base application configuration attributes. |

### Detection Engine
| Model Name | Table Purpose |
|------------|---------------|
| `DetectionRule` | Custom logic/rules to trigger alerts based on log patterns. |
| `DetectionEvent` | A specific event triggered when a `DetectionRule` matched. |

### Incidents & Alerts
| Model Name | Table Purpose |
|------------|---------------|
| `Alert` | Centralized alerts generated from scanners, IDS, or SIEM engines. |
| `Incident` | Escalated cases tied to alerts, complete with severity, status, and assignee. |

### Threat Intelligence
| Model Name | Table Purpose |
|------------|---------------|
| `ThreatFeed` | Subscribed feeds distributing threat intel. |
| `IOC` | Indicators of Compromise (IPs, hashes, domains) sourced from feeds. |
| `ThreatCampaign` | Groupings of IOCs mapping to a specific real-world attack campaign. |
| `ThreatActor` | Known APT groups and adversaries. |

### SIEM
| Model Name | Table Purpose |
|------------|---------------|
| `SiemEvent` | Aggregated and normalized log data from diverse infrastructure points. |
| `SiemSavedSearch` | Persisted queries for frequent log lookups in the SIEM module. |

### Scanner
| Model Name | Table Purpose |
|------------|---------------|
| `ScanTarget` | Hosts/IPs registered for active scanning. |
| `Scan` | Record of a specific scan job execution (e.g., Nmap, Nikto). |
| `VulnerabilityFinding` | Documented vulnerability or exposure mapped to a scan. |
| `ServiceObservation` | Non-vulnerability metadata discovered during a scan (ports, services). |

### IDS (Intrusion Detection)
| Model Name | Table Purpose |
|------------|---------------|
| `IDSSensor` | Represents a deployed IDS sensor (e.g., a Suricata node). |
| `NetworkIDSEvent` | Captured security events and signatures parsed from the IDS logs. |

### Packet Analysis
| Model Name | Table Purpose |
|------------|---------------|
| `PacketAnalysis` | Uploaded PCAP files and their extracted analysis states. |

### Assets
| Model Name | Table Purpose |
|------------|---------------|
| `Asset` | Inventory of internal network devices, servers, and hardware. |

### Reports
| Model Name | Table Purpose |
|------------|---------------|
| `Report` | Generated periodic or ad-hoc security reports (PDF/HTML generation records). |

### Threat Hunting
| Model Name | Table Purpose |
|------------|---------------|
| `ThreatHuntQuery` | Saved hypotheses and queries used in proactive threat hunting. |

### AI Assistant
| Model Name | Table Purpose |
|------------|---------------|
| `AIConversation` | Tracks chat sessions with the Generative AI. |
| `AIMessage` | Individual prompt/response history within an AI conversation. |

### SOAR (Security Orchestration, Automation, and Response)
| Model Name | Table Purpose |
|------------|---------------|
| `SoarPlaybookExecution` | Record of an automated playbook run (status, steps executed). |
| `SoarApproval` | Human-in-the-loop approval gating for sensitive SOAR actions. |

### Audit Logs
| Model Name | Table Purpose |
|------------|---------------|
| `AuditLog` | Immutable record of system actions, user logins, and setting modifications. |

### Notifications
| Model Name | Table Purpose |
|------------|---------------|
| `Notification` | System notifications delivered to the application UI. |

## Backup Considerations
- As the system aggregates high-volume SIEM and IDS logs, PostgreSQL partition tables or external archiving (e.g., Elasticsearch, S3 cold storage) should be considered in large enterprise deployments.
- Regular use of `pg_dump` is recommended for core configuration, Auth, and Threat Intel databases.
