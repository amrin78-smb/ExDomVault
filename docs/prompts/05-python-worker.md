# Milestone 5 — Python worker

Read `CLAUDE.md`, `docs/progress.md`, and `docs/prompts/00-master-build-prompt.md` (especially §6–§11). Check `git status` and confirm the previous milestone is marked done in `docs/progress.md`; if it is not, report what is missing and finish it first.

Spec: `docs/design.md` §3.4, §11, §12 (Worker isolation). Milestone definition: master prompt §5, "Milestone 5".

## Scope

- Package under `worker/app/` with the modules from design §11 (config, client, queue, scope, dns_checks, rdap_checks, discovery, tls_checks, http_checks, port_checks, result_upload, logging_config, main).
- Pull model: authenticated outbound HTTPS to the internal worker API (HMAC signing matching Milestone 4), claim → heartbeat → submit → report, bounded exponential backoff, graceful shutdown on SIGTERM. No inbound listener.
- Implement DNS and RDAP checks and result normalisation now. TLS/HTTP/port checks may be implemented, but **all network-connecting checks must route through `scope.py` and remain disabled by config until Milestone 6 passes**.
- Structured JSON logging (no secrets), local health file/command.
- Pinned `requirements.txt` (+ hashes if practical), `pyproject.toml`, `.env.example`, hardened non-root Dockerfile, `deploy/exdomainvault-worker.service` (dedicated user, `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, restart policy, minimal capabilities — `CAP_NET_RAW` only if Nmap SYN scan is chosen; prefer TCP connect scan without it).
- pytest with mocked API and DNS/RDAP responses — no live targets.
- Write `docs/home-worker-setup.md` (install, venv, systemd, health check, upgrade/restart, credential rotation).

## Finish

1. Run lint, typecheck, test, build (and `worker:test` if the worker changed). Fix failures; report anything that genuinely cannot run and why.
2. Update the relevant docs in `docs/` to match what was actually built.
3. Update `docs/progress.md`: status table, decisions, operator actions, limitations, session log.
4. Summarise files changed, check results, remaining limitations, and the next milestone. Commit and push to `main`.
