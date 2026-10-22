# ExDomainVault — Design Document

> External Domain Security & Exposure Monitoring Platform. Architecture, data model, APIs, security controls, scanning workflow and phased implementation plan.
>
> Version 1.0 · 22 October 2026 · Status: Initial implementation specification
>
> Converted from `ExDomainVault_Design_Document.docx`. This file is the primary product requirement; implementation clarifications live in `CLAUDE.md`.
# 1. Purpose

ExDomainVault is a web-based external attack-surface monitoring platform for maintaining an inventory of organisation-owned internet domains, discovering candidate subdomains, monitoring DNS and domain registration, checking exposed services, and generating actionable security advisories.

The platform must provide an auditable record of what was observed, when it was observed, why a finding was generated, and what remediation is recommended.

## 1.1 Objectives

1. Maintain a verified inventory of registered domains and related assets.
1. Perform DNS, RDAP, TLS certificate and HTTP configuration checks.
1. Discover candidate subdomains through passive sources.
1. Perform controlled TCP port and service checks using a Linux worker.
1. Detect changes between scans.
1. Generate findings through deterministic, version-controlled rules.
1. Prioritise findings according to severity, confidence, exposure and business criticality.
1. Track remediation and verify that findings are resolved.
1. Provide dashboards, historical trends and exportable reports.
10. Operate without a rented VPS by using the owner's existing home Linux machine.

## 1.2 Non-goals for the initial release

- Exploit execution or automated penetration testing.
- Brute-force authentication or credential testing.
- Destructive vulnerability testing.
- Automated changes to DNS, firewalls or production infrastructure.
- AI-generated severity decisions.
- Full commercial vulnerability scanner replacement.
- Scanning assets without verified scope and appropriate authorisation.

# 2. Technology stack

| Component | Technology |
|---|---|
| Source control | GitHub private repository |
| Frontend | React, Vite, TypeScript |
| UI | Tailwind CSS and a consistent component system |
| Hosting and API | Cloudflare Workers with static assets |
| Database | Neon PostgreSQL |
| Database access | Cloudflare Hyperdrive or the supported Neon serverless driver |
| ORM and migrations | Drizzle ORM |
| Job orchestration | Cloudflare Queues and Cron Triggers |
| Scanning engine | Python 3.12+ on home Linux |
| Port and service scanning | Nmap |
| DNS checks | dnspython |
| Domain registration | RDAP clients and registry APIs where available |
| TLS checks | Python SSL and certificate parsing libraries |
| Passive discovery | Certificate Transparency and approved passive sources |
| Worker lifecycle | systemd service |
| Connectivity | Outbound HTTPS; Cloudflare Tunnel for private administration where needed |
| Testing | Vitest, pytest and integration tests |
| CI/CD | GitHub Actions and Cloudflare deployment tooling |

Use supported package versions available at implementation time. Pin dependencies, commit lockfiles, and document any compatibility constraints.

Prefer Cloudflare's current React/Vite Workers integration rather than assuming that a traditional Pages-only configuration is necessary. The frontend may be served as static assets by the Worker application.

Official references:

- Cloudflare React and Vite: https://developers.cloudflare.com/workers/framework-guides/web-apps/react/
- Cloudflare Queues: https://developers.cloudflare.com/queues/
- Cloudflare Cron Triggers: https://developers.cloudflare.com/workers/configuration/cron-triggers/
- Cloudflare and Neon: https://developers.cloudflare.com/workers/databases/third-party-integrations/neon/
- Cloudflare Tunnel: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/
- Nmap: https://nmap.org/book/man.html
- RDAP: https://www.icann.org/rdap

# 3. High-level architecture

## 3.1 Web application

The React frontend provides:

- Executive dashboard.
- Domain inventory.
- Asset discovery and approval.
- Scan profiles and scan history.
- Findings and remediation workflow.
- Advisories.
- Configuration and user administration.
- Audit log and reports.

The frontend must never contain database credentials, worker credentials or privileged API secrets.

## 3.2 Cloudflare application layer

Cloudflare Workers handles:

- Authentication and authorisation.
- Domain and asset management.
- Domain verification.
- Scan job creation.
- Queue orchestration.
- API validation.
- Deterministic rules evaluation where appropriate.
- Findings and advisory management.
- Dashboard queries and reports.
- Scheduled job creation.

Workers must not attempt to execute Nmap or arbitrary operating-system commands.

## 3.3 Neon PostgreSQL

Neon is the system of record for application data, scan history and finding lifecycle.

Cloudflare Queues can deliver job notifications, but durable job state must remain in PostgreSQL. Queue delivery and database writes must be designed for retries and duplicate delivery.

## 3.4 Home Linux scanning worker

The worker runs continuously as a systemd service, subject to the availability of the home machine and internet connection.

Responsibilities:

1. Poll an authenticated job-claim API or consume jobs through an explicitly designed private connection.
1. Claim an eligible job.
1. Retrieve the approved target scope.
1. Revalidate the target and scan profile.
1. Execute the required checks.
1. Submit structured observations.
1. Report progress and failures.
1. Retry transient failures without duplicating results.

The worker must not expose an unauthenticated inbound HTTP endpoint.

## 3.5 Cloudflare Tunnel

Cloudflare Tunnel is optional for the worker's normal operation. The preferred default is for the home worker to initiate outbound HTTPS requests to Cloudflare and the authorised database endpoint.

If Tunnel is used for administration or private worker connectivity, restrict access with Cloudflare Access and service authentication. Do not expose an unrestricted scan-control endpoint.

## 3.6 Architecture flow

1. An administrator registers a domain.
1. The administrator verifies domain control.
1. The system creates an authorised asset scope.
1. Passive discovery identifies candidate subdomains.
1. Candidates are reviewed and approved according to policy.
1. Cloudflare schedules jobs.
1. The home worker claims a job.
1. The worker validates scope and executes approved checks.
1. Structured observations are saved.
10. The rules engine evaluates observations.
11. Findings and advisories are created or updated.
12. The dashboard displays the results and changes over time.

# 4. User roles

Implement role-based access control.

## Administrator

- Manage users and roles.
- Register and verify domains.
- Approve assets and scan scope.
- Configure scan policies and schedules.
- Manage integrations and operational settings.

## Security analyst

- Review assets and observations.
- Request scans within approved scope.
- Review, assign and update findings.
- Acknowledge and verify remediation.
- Generate reports.

## Asset owner

- View assigned assets and findings.
- Add remediation notes.
- Update remediation status.
- Request reassessment where permitted.

## Viewer

- Read authorised dashboards, findings and reports.
- Cannot initiate scans or change configuration.

All privileged operations must be authorised on the server, not merely hidden in the frontend.

# 5. Data model

Use UUID primary keys, foreign keys, UTC timestamps, appropriate indexes, database constraints and migrations.

## 5.1 `users`

- id
- email
- display_name
- role
- auth_provider_subject
- is_active
- created_at
- updated_at

Do not store plaintext passwords. Prefer an established authentication provider.

## 5.2 `domains`

- id
- fqdn — unique normalised registered domain
- registrar
- registered_at
- expires_at
- criticality — low, medium, high, critical
- business_owner
- verification_status
- verified_at
- monitoring_enabled
- created_by
- created_at
- updated_at

Distinguish verified information from missing or privacy-redacted registration information.

## 5.3 `domain_verifications`

- id
- domain_id
- method
- challenge_hash
- status
- created_at
- expires_at
- verified_at

Use short-lived challenges. Never retain reusable verification secrets in plaintext.

## 5.4 `assets`

- id
- domain_id
- hostname
- asset_type
- verification_status
- discovery_source
- first_seen_at
- last_seen_at
- monitoring_enabled
- criticality_override
- approved_by
- approved_at
- created_at
- updated_at

Store IP observations separately so an asset can change addresses without losing its identity or history.

## 5.5 `asset_ips`

- id
- asset_id
- ip_address — PostgreSQL inet
- first_seen_at
- last_seen_at
- is_current
- source

## 5.6 `scan_jobs`

- id
- job_type
- profile
- status
- priority
- requested_by
- reason
- scope_snapshot
- created_at
- scheduled_at
- started_at
- completed_at
- lease_expires_at
- attempts
- worker_id
- error_code
- error_summary

Statuses: queued, claimed, running, succeeded, failed, cancelled.

## 5.7 `scan_job_targets`

- id
- scan_job_id
- asset_id
- target_hostname
- target_ip
- status
- started_at
- completed_at
- error_code

Store a snapshot of approved targets so later scope changes cannot silently enlarge an existing job.

## 5.8 Observation tables

Create separate tables for:

- dns_observations
- registration_observations
- tls_observations
- http_observations
- port_observations
- discovery_observations

Every observation must include:

- A stable ID.
- Asset or target reference.
- Associated scan job.
- Observation timestamp.
- Source/checker version.
- Structured evidence.
- Result status.

Use JSONB for extensible evidence, but keep important queryable attributes in typed columns.

## 5.9 `findings`

- id
- asset_id
- rule_id
- rule_version
- title
- description
- severity
- confidence
- risk_score
- status
- evidence
- first_seen_at
- last_seen_at
- resolved_at
- assigned_to
- created_at
- updated_at

Prevent duplicate active findings for the same logical issue. Use a stable fingerprint derived from the asset, rule and relevant affected component.

## 5.10 `advisories`

- id
- finding_id
- title
- summary
- business_impact
- recommended_actions
- references
- created_at
- updated_at

Advisories must be based on findings and evidence, not unsupported speculation.

## 5.11 `audit_logs`

- id
- actor_user_id
- action
- resource_type
- resource_id
- request_id
- created_at
- metadata

Record domain verification, scope approvals, scan launches, policy changes, user administration and finding status changes.

## 5.12 Supporting tables

Implement worker_registry, scan_profiles, security_rules, notification_preferences and application_settings where required.

Do not store worker authentication secrets directly in general-purpose application settings.

# 6. Scan profiles

## Quick

- DNS records.
- Registration metadata.
- TLS certificate validity and expiry.
- Lightweight HTTP availability checks.

Default schedule: daily.

## Standard

- All Quick checks.
- HTTP security headers.
- Approved TCP port checks.
- Limited service identification.
- Change detection.

Default schedule: weekly.

## Deep

- Expanded approved TCP port coverage.
- More comprehensive service identification.
- Additional TLS and HTTP configuration checks.

Default schedule: monthly or manually requested.

Use conservative defaults. Profiles must define port ranges, timeouts, concurrency and rate limits. The user interface must not accept arbitrary shell commands or scanner flags.

# 7. Passive subdomain discovery

Implement a provider abstraction so discovery sources can be added or replaced.

Initial sources:

- Certificate Transparency data.
- Additional passive sources only when configured and approved.

For each candidate:

1. Normalise case and trailing dots.
1. Convert internationalised domain names to a consistent representation.
1. Validate exact DNS label boundaries beneath the approved root.
1. Record source and discovery timestamp.
1. Deduplicate candidates.
1. Resolve DNS where appropriate.
1. Store as pending until policy permits approval.

Passive discovery does not prove ownership, liveness or permission to actively scan. Never automatically expand the approved scan scope merely because a hostname appears in a certificate log.

# 8. Deterministic rules engine

Each rule must have:

- Stable rule ID and version.
- Category and title.
- Required observation types.
- Detection condition.
- Default severity and confidence.
- Evidence requirements.
- Remediation guidance.
- Resolution condition.
- Unit tests and sample fixtures.

Initial rules:

- DNS-001: Unexpected authoritative DNS change.
- DNS-002: Potential dangling CNAME requiring validation.
- DNS-003: Missing DMARC policy.
- DNS-004: Significant SPF configuration issue.
- TLS-001: Expired certificate.
- TLS-002: Certificate hostname mismatch.
- TLS-003: Certificate expiry within 14 days.
- TLS-004: Weak or unsupported TLS configuration.
- EXP-001: Newly exposed TCP port.
- EXP-002: Public administrative service violating an approved exposure policy.
- REG-001: Domain registration expiry within 30 days.
- REG-002: Unexpected registrar or nameserver change.
- ASSET-001: Newly discovered unapproved candidate asset.
- ASSET-002: Previously monitored asset missing from a successful discovery run.

An open port is an observation, not automatically a vulnerability. Severity depends on service, exposure policy, evidence, confidence and asset criticality.

## Severity and risk

Keep severity separate from risk score.

Use a transparent initial risk model:

risk_score = severity_weight × exposure_factor × criticality_factor

Define the factors in documented enums and clamp the score to a fixed range. Use explicit override rules for exceptional cases. Store the inputs used to calculate each score so that the result is explainable.

Initial severity categories: informational, low, medium, high, critical.

A rule must not claim that an exploit or compromise occurred unless there is sufficient evidence to support that statement.

# 9. Finding lifecycle

Implement the following lifecycle:

open → acknowledged → remediation_in_progress → resolved

Also support accepted_risk with a reason, approver and review date.

On subsequent scans:

- Update last_seen_at for recurring issues.
- Preserve the first detection timestamp.
- Reopen resolved issues if a successful observation confirms recurrence.
- Resolve only after a successful relevant check confirms the condition is absent.
- Do not resolve findings after failed or incomplete scans.
- Preserve evidence and status-change history.

# 10. API specification

Base path: /api/v1

## Domains

- GET /domains
- POST /domains
- GET /domains/:id
- PATCH /domains/:id
- POST /domains/:id/verify
- POST /domains/:id/discovery

## Assets

- GET /domains/:id/assets
- GET /assets/:id
- POST /assets/:id/approve
- POST /assets/:id/suspend
- GET /assets/:id/observations

## Scans

- POST /domains/:id/scans
- GET /scans
- GET /scans/:id
- POST /scans/:id/cancel

## Findings and advisories

- GET /findings
- GET /findings/:id
- PATCH /findings/:id
- GET /advisories
- GET /reports/summary

## Internal worker API

- POST /internal/worker/claim
- POST /internal/worker/heartbeat
- POST /internal/worker/results
- POST /internal/worker/failures

Worker endpoints require dedicated authentication, request validation, rate limiting and replay protection. Never accept arbitrary targets from worker or user requests without server-side scope validation.

Use a consistent JSON error format, request IDs, pagination, validation errors and appropriate HTTP status codes.

# 11. Worker implementation

Suggested modules:

- main.py
- config.py
- client.py
- queue.py
- scope.py
- dns_checks.py
- rdap_checks.py
- discovery.py
- tls_checks.py
- http_checks.py
- port_checks.py
- result_upload.py
- logging_config.py

Use a Python virtual environment and pinned dependencies.

The worker should:

1. Register or identify itself.
1. Claim a job over authenticated HTTPS.
1. Verify that the lease and scope are valid.
1. Revalidate each target and resolved destination.
1. Run the requested checks with bounded timeouts and concurrency.
1. Submit structured observations.
1. Heartbeat long-running work.
1. Report success or failure.
1. Retry transient failures with bounded exponential backoff.

Run under systemd with a dedicated unprivileged account. Use a restart policy, structured logs and health checks.

# 12. Security requirements

## Scope and network safety

- Require verified domains and explicit scan authorisation.
- Apply exact hostname boundary checks.
- Reject loopback, private, link-local, multicast, reserved and prohibited addresses.
- Validate IPv4 and IPv6.
- Prevent DNS rebinding and time-of-check/time-of-use errors.
- Revalidate every redirect, CNAME chain and resolved destination.
- Pin validated destinations for the relevant connection where technically supported.
- Require approval for shared hosting, CDN, cloud and third-party infrastructure.
- Do not follow arbitrary redirect destinations.
- Restrict scanner arguments to server-defined profiles.

## Worker isolation

- Do not run a public, unauthenticated worker API.
- Do not allow the worker to access the home LAN beyond explicitly required destinations.
- Restrict egress where feasible.
- Keep operating-system and scanning-tool packages patched.
- Use bounded resource consumption, output limits and execution timeouts.
- Never run user-supplied shell commands.
- Do not execute exploits or brute-force credentials.

## Credentials

- Store secrets in Cloudflare secrets, local environment files excluded from Git, or a suitable secret manager.
- Use separate credentials for application, worker and migrations.
- Use expiring or rotatable worker credentials.
- Do not log secrets.
- Do not expose database connection strings to the browser.
- Do not use a GitHub self-hosted runner on the home machine for untrusted workflows.

## Application security

- Enforce server-side role checks.
- Protect session-based requests against CSRF.
- Validate all input with schemas.
- Add rate limiting and scan quotas.
- Audit privileged actions.
- Apply retention policies.
- Back up and test restoration.
- Avoid leaking internal exceptions or credentials in API responses.

# 13. Observability and reliability

Implement:

- Structured JSON logs.
- Correlation/request IDs.
- Job retry counts and failure reasons.
- Worker last-seen and health status.
- Queue depth and oldest-job age.
- Scan duration and success rates.
- Database error monitoring.
- Notifications for persistent worker outages.
- Historical observation retention and cleanup.

Use atomic job claiming, expiring leases, idempotency keys and unique result identifiers. Queue messages may be delivered more than once.

# 14. Frontend design

Create a modern, professional security operations dashboard.

## Navigation

- Overview
- Domains
- Assets
- Scans
- Findings
- Advisories
- Reports
- Settings

## Overview

Display:

- Domains monitored.
- Verified assets.
- Pending assets.
- Open findings by severity.
- Findings created and resolved over time.
- Recently changed DNS records.
- Certificates approaching expiry.
- Latest scan status.
- Worker health.
- Top remediation priorities.

## Domain detail

Display registration metadata, DNS records, nameservers, certificate status, discovered assets, scan history and associated findings.

## Asset detail

Display hostname, current and historical IPs, discovery source, approval state, observed services, TLS information and findings.

## Finding detail

Display severity, confidence, evidence, first and last seen, affected asset, risk rationale, remediation instructions, references, assigned owner and status history.

## UI requirements

- Responsive desktop-first layout.
- Clear severity labels and accessible contrast.
- Search, sorting, pagination and filtering.
- Loading, empty, error and stale-data states.
- Confirmation for destructive or scope-changing actions.
- No fabricated scan results in production.

Demo fixtures may be used in a clearly labelled development-only mode.

# 15. Repository layout

Use a monorepo:

```text
ExDomainVault/
├── apps/
│   └── web/
├── packages/
│   ├── database/
│   │   ├── schema/
│   │   └── migrations/
│   ├── shared/
│   └── rules/
├── worker/
│   ├── app/
│   ├── tests/
│   ├── requirements.txt
│   └── Dockerfile
├── tests/
│   ├── api/
│   ├── rules/
│   └── integration/
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   ├── database-schema.md
│   ├── api-specification.md
│   ├── scan-safety.md
│   ├── advisory-rules.md
│   └── deployment.md
├── netlify.toml
├── .env.example
├── .gitignore
├── package.json
└── README.md
```

The exact structure may be refined to match the chosen Cloudflare framework, but frontend, API, shared code, database and worker responsibilities must remain separated.

# 16. Phased implementation

## Phase 1 — Foundation

- Scaffold repository.
- Configure TypeScript, React, Vite and Cloudflare Workers.
- Add authentication and role checks.
- Configure Neon and database migrations.
- Implement domain inventory and verification.
- Implement dashboard layout and audit logging.

Acceptance: an authorised user can register a domain, verify control and view persistent inventory.

## Phase 2 — Basic monitoring

- Implement DNS and RDAP checks.
- Implement TLS certificate and HTTP header checks.
- Persist observations.
- Add scan history and scheduled job creation.
- Implement baseline deterministic rules.

Acceptance: manual and scheduled checks create evidence-backed findings.

## Phase 3 — Linux worker

- Implement authenticated job claiming.
- Add worker leases, heartbeats and retries.
- Add scope validation.
- Implement controlled Nmap checks.
- Deploy and test the worker under systemd.

Acceptance: the worker executes only authorised targets and reports structured results reliably.

## Phase 4 — Discovery and lifecycle

- Integrate passive discovery.
- Add pending asset approval.
- Implement finding recurrence and resolution.
- Add advisories, assignment and remediation workflow.

Acceptance: discovered assets remain controlled, and findings reflect changes across successful scans.

## Phase 5 — Production hardening

- Complete RBAC and security tests.
- Add monitoring, retention and backup procedures.
- Test worker outage and recovery.
- Validate deployment and secret management.
- Document operational procedures.

Acceptance: production readiness criteria are met and all critical tests pass.

# 17. Definition of done

The initial production release is complete when:

1. Domain inventory and verification work end to end.
1. DNS, registration, TLS and HTTP observations persist in Neon.
1. Passive discovery produces deduplicated pending assets.
1. Approved TCP scans execute only within the authorised scope.
1. Findings are deterministic, explainable and evidence-backed.
1. Failed scans never cause false resolution.
1. Duplicate jobs and retries do not create duplicate active findings.
1. User permissions and worker authentication are enforced.
1. Secrets are not committed or exposed to the frontend.
10. Automated tests, deployment instructions and recovery procedures are available.

# 18. Implementation principles

- Build incrementally; do not attempt the entire platform in one unreviewed code-generation pass.
- Inspect official documentation when choosing current framework APIs.
- Prefer small, typed modules and explicit interfaces.
- Create database migrations rather than relying on automatic production schema mutation.
- Add tests with every feature.
- Never report a check as successful when its result is unknown or incomplete.
- Never invent scan results.
- Document assumptions and configuration required from the operator.
- Do not require paid integrations for the basic monitoring workflow.
- Keep deterministic rules as the authority for findings and severity.

End of specification.

