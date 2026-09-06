CyberDefense XDR — BRAIN.md

Purpose

This file is the persistent project context for ANY AI coding agent working on CyberDefense XDR.

Read this file before analyzing, modifying, generating, deleting, renaming, refactoring, or deploying anything.

The repository itself is the source of truth for implementation. This file defines project intent, architecture, constraints, workflow, and known status.

1. Project Identity

Project: CyberDefense XDR

Type: B.Tech cybersecurity / DevSecOps / XDR platform

Primary goal: Build a modular, functional cybersecurity platform demonstrating security monitoring, detection engineering, alert management, incident response, SIEM-style visibility, IDS/security events, security scanning/VAPT, threat intelligence, reporting, AI-assisted security analysis, user/security administration, and secure DevOps practices.

The final application must behave as an integrated security platform, not a collection of unrelated static dashboards.

Core workflow:

Security Event
      ↓
Detection Engine
      ↓
Alert Center
      ↓
Investigation / Triage
      ↓
Incident Response
      ↓
Containment / Resolution
      ↓
Reports / Analytics
      ↓
AI Assistance

2. Development Environment

Current environment:

OS: Kali Linux

Shell: Bash

Python: 3.13.x

Virtual environment: venv

Framework: Flask

Database: PostgreSQL

ORM: Flask-SQLAlchemy / SQLAlchemy

Migrations: Flask-Migrate / Alembic

Authentication: Flask-Login

Frontend: HTML + CSS + JavaScript

Editor: VS Code

AI agents may include Antigravity CLI, Claude Code, ChatGPT, Gemini, or other coding agents.

Project root:

~/Projects/CyberDefense-XDR

Run commands from the project root unless there is a specific reason not to.

3. Absolute AI Rules

Rule 1 — Analyze before editing

Never immediately generate code for a requested module.

First inspect:

repository structure

existing files

existing imports

existing models

existing routes

existing services

existing templates

existing JavaScript

existing CSS

existing migrations

database relationships

tests

configuration

Then explain what already exists.

Rule 2 — Do not recreate completed functionality

Some modules are already implemented.

Do NOT regenerate them simply because another file looks empty.

Before modifying a module:

Search the entire repository.

Find its routes.

Find its models.

Find its services.

Find its templates.

Find its JavaScript.

Find its database tables/migrations.

Determine whether it is complete, partial, placeholder-only, or broken.

Rule 3 — Existing files do NOT mean completed functionality

Classify modules as:

COMPLETE
PARTIAL
PLACEHOLDER
MISSING
BROKEN

A module is only COMPLETE when its required backend, model, service, routes, frontend, JavaScript, database integration, authentication/authorization, error handling, and basic testing work together.

Rule 4 — Never overwrite working code unnecessarily

Before changing a file:

git diff -- <file>

Inspect it first.

Prefer small targeted changes.

Do not replace a large existing file merely because a generated version looks cleaner.

Rule 5 — Preserve the current architecture

Do not introduce a new framework unless explicitly requested.

Current architecture is Flask + PostgreSQL.

Use modular structures such as:

models.py
services.py
routes.py
__init__.py
templates/
static/js/
static/css/

Rule 6 — No duplicate models

Before creating a model:

grep -Rni "class ModelName" app migrations
grep -Rni "__tablename__" app

Never create a second model for the same database entity.

Rule 7 — No duplicate routes

Before adding a route:

flask --app run.py routes
grep -Rni "@.*route" app

Do not create two endpoints with the same purpose.

Rule 8 — Database safety

Never blindly modify the database.

Before migration work:

flask --app run.py db current
flask --app run.py db heads

After generating a migration, inspect the migration file before upgrading.

Do not drop or alter existing tables unless explicitly authorized.

Rule 9 — No destructive commands without approval

Never automatically run:

DROP DATABASE
DROP TABLE
rm -rf
git reset --hard
git clean -fd
docker system prune
terraform destroy
cloud resource deletion

Ask first.

Rule 10 — Avoid unnecessary cloud spending

Develop locally whenever possible.

Do not create paid cloud infrastructure just for testing.

Avoid unnecessary:

VMs

managed databases

load balancers

NAT gateways

public IPs

Kubernetes clusters

storage

paid APIs

unless explicitly requested.

4. Application Structure

Major structure:

CyberDefense-XDR/
│
├── app/
│   ├── ai/
│   ├── alerts/
│   ├── api/
│   ├── assets/
│   ├── auth/
│   ├── dashboard/
│   ├── detection/
│   ├── ids/
│   ├── incidents/
│   ├── models/
│   ├── notifications/
│   ├── reports/
│   ├── scanner/
│   ├── services/
│   ├── settings/
│   ├── siem/
│   ├── threatintel/
│   ├── users/
│   ├── utils/
│   ├── static/
│   └── templates/
│
├── config/
├── migrations/
├── tests/
├── run.py
├── requirements.txt
├── .env.example
├── Dockerfile
└── README.md

Do not assume every directory above is implemented. Many were created as placeholders.

5. Flask Application Factory

Main file:

app/__init__.py

Core blueprints currently include:

main
auth
dashboard
settings
detection
incidents
alerts

Models are imported inside create_app() so SQLAlchemy registers them.

When adding a model:

from app.module.models import Model  # noqa: F401

When adding a blueprint:

from app.module import module

then:

app.register_blueprint(module)

Never register the same blueprint twice.

6. Database

Database:

PostgreSQL

Database user:

cyberadmin

Technology:

Flask-SQLAlchemy
Flask-Migrate
Alembic

Useful commands:

flask --app run.py db current
flask --app run.py db heads
flask --app run.py db history
flask --app run.py db check
flask --app run.py db migrate -m "message"
flask --app run.py db upgrade

Model workflow:

Create model
↓
Register model
↓
Verify metadata
↓
Generate migration
↓
Inspect migration
↓
Upgrade database
↓
Verify table
↓
Run db check

7. Authentication

Authentication uses Flask-Login.

Important:

app/extensions.py

contains:

db
migrate
login_manager

Do not remove or replace the existing Flask-Login configuration.

Do not introduce a second authentication system.

8. Completed Modules

Authentication

Status:

COMPLETE

Includes login, authentication routes/services/forms, and Flask-Login integration.

Do not rebuild unless a concrete bug is found.

Main Dashboard

Status:

COMPLETE

Primary route:

/dashboard/

Use Flask route generation:

{{ url_for('dashboard.index') }}

Do not replace it with old static-page links such as dashboard.html.

Detection Engine

Status:

COMPLETE

Primary route:

/detection/dashboard

Important: this route currently does NOT require a trailing slash.

Existing routes include:

/detection/dashboard
/detection/events
/detection/rules
/detection/rules/create
/detection/rules/<rule_id>/data
/detection/rules/<rule_id>/update
/detection/rules/<rule_id>/delete
/detection/rules/<rule_id>/duplicate
/detection/rules/<rule_id>/toggle
/detection/history
/detection/history/data
/detection/rules/data

Models:

DetectionRule
DetectionEvent

Detection frontend and JavaScript are already implemented.

Do NOT regenerate Detection Engine. Only modify it when necessary for integration or a verified bug.

Incident Response

Status:

COMPLETE

Primary route:

/incidents/dashboard

Existing routes include:

/incidents/
/incidents/dashboard
/incidents/data
/incidents/<incident_id>
/incidents/<incident_id>/data
/incidents/create
/incidents/<incident_id>/assign
/incidents/<incident_id>/status
/incidents/<incident_id>/close
/incidents/<incident_id>/delete
/incidents/<incident_id>/resolve
/incidents/<incident_id>/update
/incidents/from-detection/<event_id>

The Incident model is substantial.

Do NOT regenerate Incident Response.

Alert Center must integrate with the existing Incident Response implementation.

Settings

Status:

PARTIAL / FUNCTIONAL

Includes profile, password, general settings, security settings, notification settings, API keys, and integrations.

Important:

NotificationSettings != Alert Center

NotificationSettings controls notification preferences/channels.

Alert Center stores and manages security alerts.

9. Current Alert Center Status

Alert Center is currently being built.

Current structure:

app/alerts/
├── __init__.py
└── models.py

Blueprint:

alerts = Blueprint(
    "alerts",
    __name__,
    url_prefix="/alert-center",
)

Current model:

Alert

Database migration:

93487e79ddae_add_alert_center.py

Migration revision:

93487e79ddae

Previous revision:

3fa8a3ef70cb

Alert model concepts:

id
alert_id
title
description
severity
status
category
source
rule_id
detection_event_id
affected_host
affected_asset
mitre_id
mitre_name
assigned_to
incident_id
investigation_notes
resolution_notes
metadata_json
created_at
updated_at
acknowledged_at
resolved_at

Relationships:

Alert → DetectionEvent
Alert → User

Alert Center should support:

New
Acknowledged
Investigating
Resolved

Future states may include:

Escalated
False Positive
Suppressed

only if needed.

10. Alert Center Target Architecture

Expected:

app/
└── alerts/
    ├── __init__.py
    ├── models.py
    ├── services.py
    └── routes.py

app/templates/
└── alerts/
    ├── alert-center.html
    ├── alert-details.html
    └── alert-create.html

app/static/js/
├── data/
│   └── alerts-data.js
└── pages/
    ├── alert-center.js
    └── alert-details.js

Use the existing global CSS/design system where possible.

Do not create unnecessary duplicate CSS.

11. Target Alert Routes

Recommended:

GET  /alert-center/
GET  /alert-center/data
GET  /alert-center/<alert_id>
GET  /alert-center/<alert_id>/data

POST /alert-center/create
POST /alert-center/<alert_id>/acknowledge
POST /alert-center/<alert_id>/resolve
POST /alert-center/<alert_id>/assign
POST /alert-center/<alert_id>/status
POST /alert-center/<alert_id>/link-incident

Before implementing, check the repository for conflicting routes.

12. Alert Service Target

Business logic belongs in:

app/alerts/services.py

Potential methods:

create_alert()
get_alert()
get_alerts()
get_alert_by_id()
acknowledge_alert()
resolve_alert()
assign_alert()
change_alert_status()
link_alert_to_incident()
create_alert_from_detection_event()

Routes should stay thin.

Do not put all business logic directly in route functions.

13. Detection → Alert Integration

Target:

DetectionEvent
      ↓
Detection Engine
      ↓
Alert Service
      ↓
Alert
      ↓
Alert Center

When a detection event meets alert criteria:

create_alert_from_detection_event()

should create an Alert.

Do not duplicate DetectionEvent records.

Reference:

detection_event_id

14. Alert → Incident Integration

Target:

Alert
 ↓
Analyst investigation
 ↓
Create Incident
 ↓
Incident Response

An Alert may store:

incident_id

when an incident is created from it.

Reuse the existing Incident implementation rather than creating another Incident model/service.

15. Frontend Rules

The application is Flask-rendered.

Do NOT use old static links such as:

href="dashboard.html"
href="detection-history.html"
href="incident-dashboard.html"

Prefer:

{{ url_for('dashboard.index') }}

Static assets should use:

{{ url_for('static', filename='css/main.css') }}

and:

{{ url_for('static', filename='js/...') }}

Do not assume ../assets/ exists.

Actual Flask static directory:

app/static/

16. Navigation

Important routes:

Dashboard:
 /dashboard/

Detection:
 /detection/dashboard

Incident Response:
 /incidents/dashboard

Alert Center:
 /alert-center/

The sidebar uses:

/alert-center/

Do not change it to /alerts/ unless explicitly decided.

17. JavaScript Data Rule

Do not create JavaScript that expects an undefined global variable.

Every frontend data dependency must have one clear source:

server-rendered JSON
OR
API fetch
OR
data JS file

Prefer API-backed data for dynamic security dashboards.

18. API / JSON Rules

Use consistent JSON structures.

Success:

{
  "success": true,
  "data": {},
  "message": null
}

Lists:

{
  "success": true,
  "data": [],
  "total": 0
}

Errors:

{
  "success": false,
  "message": "Human-readable error"
}

Never expose passwords, secrets, API keys, tokens, environment variables, or database credentials.

19. Security Requirements

Every AI must actively check:

authentication
authorization
CSRF
SQL injection
XSS
command injection
path traversal
SSRF
unsafe file uploads
secret leakage
insecure deserialization
IDOR
mass assignment
privilege escalation
unsafe subprocess execution
sensitive-data logging

Do not introduce:

shell=True

unless justified and reviewed.

Never hard-code:

passwords
API keys
cloud credentials
tokens
database credentials

Use environment variables/configuration.

20. VAPT / Scanner Safety

Scanner/VAPT functionality is for controlled, authorized environments.

Default targets:

localhost
private lab
explicitly authorized target

Do not automatically scan public systems.

Do not add destructive exploitation functionality merely for demonstration.

21. AI Agent Workflow

Every AI agent must follow:

Phase A — Understand

Run:

pwd
find . -maxdepth 3 -type f | sort
git status

Inspect relevant files.

Phase B — Search

Before creating anything:

grep -Rni "keyword" app
grep -Rni "class " app
grep -Rni "@.*route" app
ls -lah migrations/versions/
flask --app run.py routes

Phase C — Classify

Report:

Existing:
Missing:
Partial:
Broken:
Duplicate:

Phase D — Plan

Give a small implementation plan.

Example:

1. Model
2. Migration
3. Service
4. Routes
5. Template
6. JavaScript
7. Integration
8. Tests

Do not implement unrelated modules.

Phase E — Implement

Prefer:

Model
↓
Migration
↓
Service
↓
Routes
↓
Frontend
↓
JavaScript
↓
Integration

Phase F — Verify

Run:

python -m compileall app
flask --app run.py routes
flask --app run.py db check

Then test relevant endpoints.

22. Git Checkpoints

Before a major module:

git status
git add .
git commit -m "checkpoint before <module>"

After successful implementation:

git status
git diff
git add .
git commit -m "implement <module>"

Never use:

git reset --hard

without explicit approval.

23. Testing Policy

Minimum verification for each module:

Python syntax

python -m compileall app

Flask startup

python run.py

Routes

flask --app run.py routes

Migration

flask --app run.py db check

Database model registration

python -c "from app import create_app; from app.extensions import db; app=create_app(); print(sorted(db.metadata.tables.keys()))"

HTTP

Use localhost with curl.

Browser

Check:

page loads
CSS loads
JavaScript loads
API calls work
buttons work
forms work
authentication works
no obvious console errors

24. Error Debugging Policy

When an error occurs:

Do NOT randomly rewrite files.

First identify:

exact error
file
line
call stack
root cause

Then inspect relevant code.

Fix the root cause rather than regenerating the application.

25. Required AI Output Format

When an AI works on this project, use:

## Analysis
What exists.

## Impact
What files/modules are affected.

## Plan
What will be changed.

## Changes
What was actually modified.

## Verification
Commands/tests executed.

## Result
What works and what remains.

## Next Step
Only the next logical task.

Never claim success without verification.

26. Never Trust AI Completion Claims

An AI saying:

done
complete
fully implemented
production ready

does NOT prove completion.

Verify:

routes
imports
database
frontend
API
JavaScript
browser
tests

before marking a module COMPLETE.

27. Module Roadmap

Current roadmap:

Authentication                 COMPLETE
Main Dashboard                 COMPLETE
Detection Engine               COMPLETE
Incident Response              COMPLETE

Alert Center                   IN PROGRESS
    ↓
SOC Dashboard                  PARTIAL / FUTURE
    ↓
SIEM                           FUTURE
    ↓
Assets                         PARTIAL / FUTURE
    ↓
IDS                            FUTURE
    ↓
Scanner / VAPT                 FUTURE
    ↓
Threat Intelligence            FUTURE
    ↓
Reports                        FUTURE
    ↓
AI Security Assistant          FUTURE
    ↓
User Management                PARTIAL / FUTURE
    ↓
Notifications                  PARTIAL
    ↓
Integrations                  PARTIAL
    ↓
Testing / Hardening             REQUIRED
    ↓
Deployment                     FINAL

Do not mark a module complete merely because its UI exists.

28. Target Final Security Platform

The final integrated workflow:

                  ┌──────────────────┐
                  │ Security Sources │
                  └────────┬─────────┘
                           ↓
                  ┌──────────────────┐
                  │ Detection Engine │
                  └────────┬─────────┘
                           ↓
                  ┌──────────────────┐
                  │   Alert Center   │
                  └────────┬─────────┘
                           ↓
                ┌──────────┴──────────┐
                ↓                     ↓
        Analyst Investigation    False Positive
                ↓
        ┌───────────────────┐
        │ Incident Response │
        └─────────┬─────────┘
                  ↓
             Containment
                  ↓
             Eradication
                  ↓
              Recovery
                  ↓
             Resolution
                  ↓
        ┌───────────────────┐
        │ Reports / Metrics │
        └───────────────────┘

                  ↕
             AI Assistant
                  ↕
       Threat Intelligence

29. Current Immediate Task

At the time this BRAIN.md was created:

Alert model: CREATED
Alert migration: GENERATED
Alert blueprint: CREATED
Alert blueprint registration: VERIFY
Alert service: NOT YET IMPLEMENTED
Alert routes: NOT YET IMPLEMENTED
Alert frontend: NOT YET IMPLEMENTED
Alert JavaScript: NOT YET IMPLEMENTED
Detection → Alert integration: NOT YET IMPLEMENTED
Alert → Incident integration: NOT YET IMPLEMENTED

Next logical implementation:

Alert Service
↓
Alert Routes
↓
Alert Center Frontend
↓
Alert JavaScript
↓
Detection → Alert
↓
Alert → Incident

Do not jump ahead.

30. Instructions for ANY AI Used on This Project

When starting a new AI session, tell the AI:

You are working on the existing CyberDefense XDR repository.

First read BRAIN.md completely.

Then inspect the actual repository.

Do not modify anything until you understand the current implementation.

Classify the requested module as COMPLETE, PARTIAL, PLACEHOLDER, MISSING, or BROKEN.

Do not regenerate completed modules.

Do not create duplicate models, routes, services, migrations, templates, or JavaScript.

Preserve the Flask + PostgreSQL architecture.

Use the existing project patterns.

Make the smallest safe changes necessary.

For database changes, inspect migrations before upgrading.

For frontend changes, use Flask url_for and the existing static structure.

For security functionality, consider authentication, authorization, CSRF, XSS, SQL injection, command injection, SSRF, IDOR, secrets, and privilege escalation.

Do not perform destructive commands or create unnecessary cloud resources.

After implementation, run verification commands and report exactly what happened.

Never claim a feature is complete without testing it.

31. Final Principle

Do not optimize for generating the most code.

Optimize for:

Correct architecture
+
Integration
+
Security
+
Maintainability
+
Testing
+
Small controlled changes

The project should become a working XDR platform one verified module at a time.