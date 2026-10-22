# Milestone 6 — Scanning and target safety (HARD SECURITY GATE)

Read `CLAUDE.md`, `docs/progress.md`, and `docs/prompts/00-master-build-prompt.md` (especially §6–§11). Check `git status` and confirm the previous milestone is marked done in `docs/progress.md`; if it is not, report what is missing and finish it first.

Spec: `docs/design.md` §6, §12 (Scope and network safety). Milestone definition: master prompt §5, "Milestone 6".

## Scope
Implement and exhaustively test the scope validator **before** enabling any connecting check. Cover every item in master prompt §5 Milestone 6 (1–14).
- Address policy: use `ipaddress` and reject loopback, RFC1918, CGNAT 100.64/10, link-local, multicast, reserved, unspecified, documentation, benchmarking, 6to4/Teredo/NAT64 embedding private v4, IPv4-mapped/compatible IPv6, ULA, site-local, plus a configurable deny-list (including the home LAN and its public IP if configured).
- Hostname policy: exact label-boundary match against the job's snapshot; CNAME chains revalidated hop by hop; out-of-scope CNAME targets rejected unless separately approved.
- Resolve → validate → **connect to the validated IP** (pin; set SNI/Host separately) for TLS, HTTP and Nmap. Mixed answers: drop disallowed addresses and log; reject if none remain. Redirects: never auto-follow; validate each hop, cap hop count.
- Nmap: fixed argument templates per profile built as argv lists, explicit IP targets only, `--max-rate`/timeouts/host-timeout, output size limits, subprocess timeout and resource limits. TCP connect scan unless a privileged mode is explicitly documented.
- Tests for: decimal/octal/hex/short-form IPv4 encodings, IPv4-mapped IPv6, zone IDs, public→private rebinding between resolution and connect, mixed DNS answers, redirect to private IP / out-of-scope host, CNAME escapes, label-boundary bypasses, oversized output, timeouts.
- Only after all tests pass: flip the config flag that enables active checks, and record the gate decision in `docs/progress.md`.
- Write `docs/scan-safety.md` and `docs/threat-model.md`.

## Finish
1. Run lint, typecheck, test, build (and `worker:test` if the worker changed). Fix failures; report anything that genuinely cannot run and why.
2. Update the relevant docs in `docs/` to match what was actually built.
3. Update `docs/progress.md`: status table, decisions, operator actions, limitations, session log.
4. Summarise files changed, check results, remaining limitations, and the next milestone. Commit and push to `main`.
