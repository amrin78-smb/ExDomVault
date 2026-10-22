# Claude Code Master Build Prompt — ExDomainVault

> Version 1.0 · 22 October 2026. Converted from `ExDomainVault_Claude_Code_Prompt.docx`.
> Usage: paste into Claude Code from the repo root, or run one of the per-milestone prompts in this folder.

You are the lead software architect, senior full-stack engineer, database engineer and application security engineer responsible for building ExDomainVault, an external domain security and exposure monitoring platform.

Your job is to implement the application in the current GitHub repository. Do not merely produce a plan or code snippets. Inspect the existing files, create and modify files, install appropriate dependencies when permitted, implement working functionality, run tests, fix errors, and document what has been completed.

# 1. Read the specification first

Before coding:

1. Read docs/design.md completely.
1. Read the existing README.md, package manifests, configuration files and source code.
1. Check the current Git branch and working tree. Do not overwrite or discard existing work.
1. Identify the current repository state and any existing implementation.
1. Check current official documentation for Cloudflare Workers, React/Vite, Neon, Drizzle ORM and relevant Python libraries when needed.
1. Write a concise implementation checklist and identify any genuine blockers.

The design specification is the primary product requirement. Where a detail is unspecified, choose a sensible, secure default, document the decision, and continue. Ask me only when a decision requires credentials, a paid service, an irreversible action, or information that cannot reasonably be inferred.

Do not stop after creating the checklist. Begin implementing the first milestone.

# 2. Product objective

Build ExDomainVault as a professional, production-oriented external domain monitoring platform.

The application must ultimately support:

- Domain inventory and domain control verification.
- Passive subdomain discovery.
- DNS, RDAP and registration lifecycle monitoring.
- TLS certificate and HTTP configuration checks.
- Controlled TCP port and service scanning by a home Linux worker.
- Historical observations and change detection.
- A deterministic rules engine.
- Evidence-backed findings and remediation advisories.
- Scan scheduling, status, retries and history.
- Role-based access control and audit logs.
- Dashboards and reports.

Do not implement exploit execution, credential brute forcing, destructive tests or unauthorised scanning.

# 3. Required technology stack

Use the following unless a verified technical incompatibility requires a documented change.

## Frontend

- React.
- Vite.
- TypeScript with strict checking.
- Tailwind CSS.
- Accessible, reusable UI components.
- A charting library only where it materially improves the dashboard.

## Cloudflare application

- Cloudflare Workers with the supported React/Vite integration and static assets.
- TypeScript API handlers.
- Cloudflare Queues for asynchronous processing where appropriate.
- Cron Triggers for scheduling.
- Wrangler for local development, configuration and deployment.

Do not assume a legacy Pages Functions structure is required. Use the currently supported Cloudflare application architecture.

## Database

- Neon PostgreSQL.
- Drizzle ORM and versioned SQL migrations.
- Cloudflare Hyperdrive or the supported Neon serverless driver, selected according to the actual runtime and connection requirements.
- PostgreSQL constraints and indexes for integrity and query performance.

## Scanning worker

- Python 3.12 or a currently supported compatible version.
- Nmap installed as an operating-system package.
- dnspython.
- Python standard-library SSL support and appropriate certificate parsing.
- RDAP HTTP client.
- HTTP client with strict timeouts and redirect controls.
- pytest for tests.
- systemd deployment instructions.

## Development

- GitHub repository.
- GitHub Actions for linting, tests and appropriate deployment workflows.
- npm or pnpm, using one package manager consistently.
- Python virtual environment and pinned dependencies.
- Environment-based configuration.

Avoid unnecessary microservices, Redis, Kubernetes and additional databases for the first release.

# 4. Repository architecture

Use the structure defined in docs/design.md, adapting it only where the chosen Cloudflare framework requires it.

Keep these responsibilities separated:

- Frontend presentation.
- API and application services.
- Authentication and authorisation.
- Database schema and migrations.
- Scan orchestration.
- Deterministic security rules.
- Python scanning worker.
- Shared API contracts and validation.
- Automated tests.
- Operational documentation.

Do not place all business logic in a single React component or a single Worker file.

Create typed interfaces and reusable modules. Keep the code readable and easy to extend.

# 5. Mandatory implementation sequence

Implement the application in small, verifiable milestones.

## Milestone 1 — Repository foundation

Implement:

1. Project scaffolding.
1. React/Vite/TypeScript frontend.
1. Cloudflare Worker application and API routing.
1. Local development commands.
1. Environment configuration and .env.example.
1. Git ignore rules.
1. Linting, formatting and type checking.
1. Automated test setup.
1. CI workflow.
10. Initial documentation.

Create a professional ExDomainVault interface with:

- A persistent navigation layout.
- Overview dashboard.
- Domains.
- Assets.
- Scans.
- Findings.
- Advisories.
- Reports.
- Settings.

Use clearly labelled development fixtures if the database is not yet configured. Demo data must never be presented as real scan results.

Deliver a working local application and successful production build before proceeding.

## Milestone 2 — Database and authentication

Implement:

- Drizzle schema.
- Versioned SQL migrations.
- Neon database connection.
- Domain and asset entities.
- User and role entities.
- Scan job entities.
- Observation entities.
- Findings and advisories.
- Audit log.
- Appropriate indexes and constraints.

Authentication requirements:

- Do not create an insecure custom password system.
- Prefer a supported identity provider or a properly configured Cloudflare Access integration.
- Keep a replaceable authentication interface so the identity implementation can evolve.
- Implement local development authentication separately from production authentication.
- Production must fail closed if authentication is not configured.
- Never trust identity headers supplied directly by arbitrary clients.
- Enforce permissions on the server.

Do not invent provider credentials or silently enable a public, unauthenticated production deployment.

If production authentication requires my Cloudflare account configuration, implement the integration interface and document the exact steps I must complete.

## Milestone 3 — Domain inventory

Implement working APIs and UI for:

- Listing domains.
- Adding a domain.
- Viewing domain details.
- Editing business owner and criticality.
- Enabling and disabling monitoring.
- Normalising domain names.
- Preventing duplicate registrations.
- Domain verification workflow.
- Audit events.

Support CSV import only after validation and confirmation of the import preview.

Implement DNS TXT verification first. Use expiring challenges and store only what is needed to validate them securely.

Domain verification must not automatically grant permission to scan third-party hosting or unrelated IP addresses.

Write unit tests for hostname normalisation, domain boundaries and verification expiry.

## Milestone 4 — Scan job lifecycle

Implement the durable scan job model.

Required functionality:

- Create jobs through authorised API endpoints.
- Validate scan profile and approved scope.
- Store an immutable snapshot of targets and policy.
- Claim jobs atomically.
- Prevent two workers from claiming the same active job.
- Use expiring leases.
- Support heartbeats.
- Support bounded retries.
- Record progress and errors.
- Support cancellation where safe.
- Process duplicate deliveries idempotently.

Use PostgreSQL as the durable source of job state.

If Cloudflare Queues is enabled, treat queue delivery as a notification or dispatch mechanism. Do not assume that a message is delivered exactly once.

Do not make the user wait for the scan to finish inside the API request.

## Milestone 5 — Python worker

Create the worker package under worker/.

Implement modules for:

- Configuration.
- API client.
- Worker identity.
- Job polling or claiming.
- Scope validation.
- DNS checks.
- RDAP checks.
- TLS checks.
- HTTP checks.
- TCP port checks.
- Result normalisation.
- Result submission.
- Logging and health reporting.

The worker must use authenticated outbound HTTPS requests to the application's API.

Prefer a pull-based model: the home worker claims jobs from the application rather than exposing a public control server.

Cloudflare Tunnel is optional for administration or a specifically designed private access path. Do not make normal worker operation dependent on opening inbound ports at home.

Do not configure the home machine as a GitHub self-hosted runner for untrusted pull-request workflows.

Include:

- requirements.txt with pinned dependencies.
- pyproject.toml where useful.
- .env.example.
- A hardened Dockerfile if it is useful for testing or deployment.
- A systemd unit example.
- Linux installation instructions.
- Health-check instructions.
- Worker upgrade and restart instructions.

The worker must run under a dedicated, unprivileged service account where possible.

## Milestone 6 — Scanning and target safety

This milestone has a hard security gate.

Before any network scanning is enabled, implement and test the scope validator.

Requirements:

1. Accept only approved scan profiles.
1. Accept targets derived from approved database records.
1. Enforce exact DNS label boundaries.
1. Validate IPv4 and IPv6 destinations.
1. Reject loopback, private, link-local, multicast, reserved and prohibited addresses.
1. Validate every resolved destination immediately before connecting.
1. Prevent DNS rebinding and time-of-check/time-of-use errors.
1. Validate every redirect destination.
1. Reject out-of-scope CNAME targets unless separately approved.
10. Pin validated destination addresses for the relevant connection where technically supported.
11. Apply timeouts, concurrency caps, request limits and rate limits.
12. Prevent user-supplied shell commands or arbitrary scanner flags.
13. Bound scanner output and process resource consumption.
14. Record scope validation decisions in logs.

Pay special attention to IPv4-mapped IPv6, alternative address encodings, public-to-private DNS changes, mixed DNS answers and redirects.

Write comprehensive unit tests for these cases.

The initial scanner must perform non-destructive checks only. Do not implement exploit attempts, credential attacks or destructive testing.

If the safety validator is incomplete, keep active scanning disabled.

## Milestone 7 — Deterministic rules engine

Create a rules package with versioned rules and automated tests.

Implement initial rules for:

- DNS record changes.
- Potential dangling CNAMEs.
- Missing DMARC.
- Significant SPF configuration issues.
- Expired TLS certificates.
- TLS hostname mismatches.
- Certificates approaching expiry.
- Weak TLS configurations.
- Newly observed TCP ports.
- Public administrative ports that violate an explicit exposure policy.
- Domain registration expiry.
- Unexpected registrar or nameserver changes.
- New unapproved candidate assets.
- Previously monitored assets missing from successful discovery runs.

Every rule must define:

- ID and version.
- Category.
- Required evidence.
- Detection logic.
- Severity.
- Confidence.
- Remediation advice.
- Resolution logic.
- Unit tests.

Rules must not confuse observations with confirmed vulnerabilities.

For example, an open port alone is not automatically a vulnerability. A missing DMARC record is a configuration issue, not proof of domain compromise.

Do not use an LLM to decide severity in this release.

## Milestone 8 — Finding lifecycle

Implement:

- Open.
- Acknowledged.
- Remediation in progress.
- Resolved.
- Accepted risk.

Track first seen, last seen, resolution time, recurrence, assignee and status history.

A failed or incomplete scan must never automatically resolve a finding.

When an issue reappears after resolution, reopen it or create a linked recurrence according to the design specification.

Prevent duplicate active findings using stable fingerprints and database constraints where appropriate.

## Milestone 9 — Passive subdomain discovery

Implement a provider abstraction for passive discovery.

Start with Certificate Transparency data and add other sources only where their usage is appropriate.

For each candidate:

- Normalise the hostname.
- Validate exact root-domain boundaries.
- Record source and timestamp.
- Deduplicate results.
- Resolve DNS when appropriate.
- Save the candidate in a pending state.
- Require policy-based approval before active scanning.

Do not treat a certificate entry as proof that a hostname is currently live or that the organisation is authorised to scan its hosting infrastructure.

Add tests for malformed hostnames, wildcard names, duplicate results, IDNs and boundary bypasses.

## Milestone 10 — Frontend integration

Connect the UI to real APIs.

Implement:

- Dashboard metrics from actual stored data.
- Domain list, filters and detail view.
- Asset inventory and approval workflow.
- Scan creation and progress.
- Scan history.
- Findings list and detail view.
- Evidence display.
- Remediation workflow.
- Advisory list.
- Report summary.
- Settings and worker health.

Include loading, empty, error, permission-denied and stale-data states.

Avoid excessive animation and decorative charts that do not help security operations.

Use consistent severity labels and clear risk explanations.

## Milestone 11 — Production hardening

Complete:

- Authentication and authorisation tests.
- Input validation tests.
- Worker authentication tests.
- Scope-validation tests.
- Database migration verification.
- Job lease and retry tests.
- Finding idempotency tests.
- Rate limiting.
- Audit logging.
- Secret-handling checks.
- Dependency vulnerability scanning.
- Structured logging.
- Database backup and restoration documentation.
- Deployment and rollback instructions.

Run all tests and fix issues rather than simply reporting them.

# 6. API and data contracts

Use the API paths and entities specified in docs/design.md.

Use typed request and response schemas. Validate all external input at runtime.

Return consistent errors with:

- A stable error code.
- A safe human-readable message.
- A request ID.
- Optional field validation details.

Do not return stack traces, internal network details or secrets to clients.

Use pagination for lists and enforce server-side limits.

The frontend must not access the database directly.

# 7. Configuration and secrets

Create .env.example with placeholder values only.

Document all required configuration, including:

- Database connection or Hyperdrive binding.
- Authentication provider configuration.
- Worker API authentication.
- Cloudflare account and deployment configuration.
- Discovery provider settings, if required.
- Scan limits.
- Job polling intervals.
- Log levels.

Never create real credentials or pretend that an external integration is configured.

Do not commit .dev.vars, .env, private keys, Tunnel credentials or database URLs.

Use separate credentials for application traffic, workers and database migrations.

# 8. Development workflow

Provide consistent root commands where practical:

- npm run dev
- npm run build
- npm run lint
- npm run typecheck
- npm run test
- npm run db:generate
- npm run db:migrate
- npm run worker:install
- npm run worker:test

These commands must reflect the actual scripts and tooling implemented. Do not leave misleading placeholder commands.

For Python, document virtual environment activation and installation.

Use local mocks or fixtures for external APIs in automated tests. Tests must not scan real third-party assets.

Do not deploy to production, modify Cloudflare account settings, create paid resources, run migrations against a production database, or push commits without explicit authorisation.

You may inspect the Git working tree and create local source files. Ask before destructive operations or irreversible external actions.

# 9. Testing standards

Every feature must include appropriate tests.

Minimum required categories:

- Unit tests for domain normalisation and verification.
- Unit tests for scan scope and IP validation.
- Unit tests for DNS and observation normalisation.
- Rule engine tests using deterministic fixtures.
- Finding lifecycle and recurrence tests.
- API authorisation and validation tests.
- Database migration tests.
- Worker retry and idempotency tests.
- Frontend component tests for key workflows.
- Build and type-check verification.

Use synthetic test targets and mocked external services.

Do not use a live third-party system as a test target.

If a test cannot run because credentials or services are missing, report it explicitly. Do not claim that it passed.

# 10. Documentation requirements

Create or update:

- README.md
- docs/design.md
- docs/architecture.md
- docs/database-schema.md
- docs/api-specification.md
- docs/scan-safety.md
- docs/advisory-rules.md
- docs/deployment.md
- docs/home-worker-setup.md
- docs/troubleshooting.md

Documentation must reflect the actual implementation rather than aspirational features.

Include architecture diagrams, environment setup, migration steps, local development, worker installation, production deployment and troubleshooting.

# 11. Working method and reporting

Work incrementally.

At the beginning:

1. Inspect the repository.
1. Read the design specification.
1. Report the existing state briefly.
1. Identify the first milestone and any genuine blockers.

Then start coding.

After each milestone:

1. Summarise files created or changed.
1. Run linting, type checking, relevant tests and builds.
1. Fix failures.
1. Update documentation.
1. List any remaining limitations.
1. State the next milestone.

Do not rewrite the whole application repeatedly. Preserve working code and use small, reviewable changes.

Do not stop to ask me about ordinary implementation choices that can be made safely and documented.

If a requirement cannot be implemented safely, explain the specific issue and propose a bounded alternative.

# 12. First task: start building now

For this first session:

1. Inspect the repository and read docs/design.md.
1. Create the initial project scaffold.
1. Implement Milestone 1.
1. Build the ExDomainVault dashboard layout and navigation.
1. Add the first typed API endpoint and health check.
1. Add the initial test suite and CI workflow.
1. Run the actual build, lint, type checks and tests.
1. Fix failures.
1. Update the README with exact local development instructions.
10. Summarise what works and list the exact next actions.

Do not attempt to implement every milestone in one pass. Prioritise a clean, tested foundation.

The result of the first session must be real code in the repository, not just a plan.

Product name: ExDomainVault

Product description: External Domain Security & Exposure Monitoring

Primary design principle: Evidence-backed, authorised and explainable security monitoring.

Begin by inspecting the repository now.

