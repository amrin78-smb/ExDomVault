# Scan safety

Principle: ExDomainVault only contacts what it is authorised to contact, with server-defined behaviour,
and every decision is explainable. This document describes the controls **as implemented** at
Milestone 6. Nothing here performs exploitation, credential testing or destructive checks.

Related: [`threat-model.md`](threat-model.md), [`worker-protocol.md`](worker-protocol.md),
[`home-worker-setup.md`](home-worker-setup.md).

## Current state

- Active (target-connecting) checks are implemented behind the Milestone 6 scope validator
  (`worker/app/policy.py`) and pinned network primitives (`worker/app/net.py`).
- Active scanning is **off** unless both independent kill switches are turned on (see
  [Kill switches](#kill-switches)). `apps/web/wrangler.jsonc` ships `ACTIVE_SCANNING_ENABLED: "false"`;
  the worker defaults `EXDV_ACTIVE_SCANNING_ENABLED` to `false`, and the shipped `worker.env`
  (`worker/deploy/install.sh`, `worker/.env.example`) sets `EXDV_PROFILES=passive,discovery` (both
  passive).
- Passive checks (`dns`, `rdap`, `discovery`) query public resolvers, registries and one fixed
  Certificate Transparency provider only, and never contact the domain's own hosts (see
  [Passive discovery](#passive-discovery-milestone-9)).
- Scheduled active scans exist but are off by default; an administrator must enable them and they
  only run while the server switch is on (see [Scheduled active scans](#scheduled-active-scans)).

## Tiered policy (owner decision)

Every check belongs to exactly one tier (`policy.tier_of`, `PASSIVE_TIER_CHECKS` / `WEB_TIER_CHECKS` /
`NETWORK_TIER_CHECKS`; mirrored server-side by `PASSIVE_CHECKS` / `WEB_CHECKS` / `NETWORK_CHECKS` in
`packages/shared/src/api/scans.ts`). An unknown check is refused (`check_not_allowed`).

| Tier    | Checks                                                     | May contact                                                                                                                                                                                                           |
| ------- | ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| passive | `dns`, `rdap`, `discovery`, `network`                      | Configured DNS resolvers, IANA RDAP bootstrap and the registry's RDAP server, `https://crt.sh/` and `https://api.certspotter.com/` (discovery only), the five RIR RDAP servers (`network` only). Never a target host. |
| web     | `tls_certificate`, `http_availability`, `http_headers`     | Any **public** address an in-scope hostname resolves to (browser-like: one handshake / one GET per hop).                                                                                                              |
| network | `tcp_ports`, `service_identification`, `tls_configuration` | Only public addresses **inside the job's admin-approved networks**.                                                                                                                                                   |

Outside any job, the worker also downloads the DB-IP "IP to Country Lite" file from the fixed URL
`https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.csv.gz` (at most monthly; redirects never
followed; see `docs/worker-protocol.md`, "IP geolocation"). The resulting country (`geo` on A/AAAA
`dns` observations) is display-only and never feeds scope, tier or approval decisions.

Domain verification never authorises the network tier on its own: a verified domain hosted on a CDN or
cloud provider gets web checks only, unless an administrator approves the specific network
(`/api/v1/approved-networks`, permission `scan_policies:manage`, admin only).

## Requirement mapping (Milestone 6)

The 14 requirements from `docs/prompts/00-master-build-prompt.md` §5 Milestone 6. Python paths are under
`worker/`, TypeScript under `apps/web/worker/` unless stated.

| #   | Requirement                                                              | Implementation                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Tests                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| --- | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Accept only approved scan profiles                                       | Server: `services/scans.ts` `getProfile` (known, enabled, `scanProfileConfigSchema`-valid; invalid stored profiles are dropped by `listProfiles`). Schema forbids non-passive checks on non-active profiles and ports without `tcp_ports`. Worker: `app/queue.py` `parse_job` (range-checks every config field), `Worker._refusal` (profile must be in `EXDV_PROFILES`, checks in `KNOWN_CHECKS`, connecting checks only on active profiles), `ScopePolicy.assert_check_allowed` (check must be listed in the job's profile).                                     | `routes/scans.test.ts` ("enforces permissions and validates the profile"); `tests/test_queue.py` (`test_unknown_check_is_refused`, `test_non_active_profile_with_connecting_checks_is_refused`, `test_malformed_tcp_ports_make_the_job_invalid`); `tests/test_policy.py` (`test_check_must_be_in_profile`, `test_tier_of_unknown_check`)                                                                                                                                                                                                                                                                  |
| 2   | Targets derived from approved database records                           | `services/scans.ts` `resolveTargets` (approved assets only; apex approved via verification and audited `asset.approved`; never re-approves a rejected/suspended apex; capped at `maxTargets`); immutable `scope_snapshot`. Worker: `scope.validate_job_targets` and `ScopePolicy.from_job` (every target in the domain **and** listed in the snapshot, else `scope_rejected`). Server: `job-lifecycle.ts` `submitResultsDetailed` rejects target ids outside the job.                                                                                             | `routes/scans.test.ts` ("approves the apex … snapshots approved targets only", "never implicitly re-approves a rejected apex", "rejects results for targets outside the job snapshot"); `tests/test_policy.py` `test_from_job_validates_targets_against_domain_and_snapshot`; `tests/test_queue.py` `test_target_outside_domain_is_refused`                                                                                                                                                                                                                                                               |
| 3   | Exact DNS label boundaries                                               | Worker: `scope.normalise_hostname`, `scope.name_within_domain`, `ScopePolicy.assert_hostname` (`name == domain or name.endswith("." + domain)` after strict A-label normalisation). Server: `isWithinDomain` (`packages/shared/src/hostname/normalise.ts`), used by `resolveTargets` and observation ingestion.                                                                                                                                                                                                                                                   | `tests/test_policy.py` (`test_hostname_within_domain`, `test_hostname_label_boundary_bypasses`); `tests/test_scope.py` `test_name_within_domain_label_boundaries`; `packages/shared/src/hostname/normalise.test.ts` (`isWithinDomain`)                                                                                                                                                                                                                                                                                                                                                                    |
| 4   | Validate IPv4 and IPv6 destinations                                      | Worker: `policy.parse_address` — canonical dotted quad only (rejects octal, hex, integer, short forms), IPv6 without zone ids, brackets or whitespace; `parse_network` with host bits zero. Server: `packages/shared/src/net/ip.ts` `parseIp` / `parseCidr` (same strictness, BigInt).                                                                                                                                                                                                                                                                            | `tests/test_policy.py` (`test_parse_address_rejects_non_canonical`, `test_parse_address_accepts_canonical`, `test_parse_network_strict`); `packages/shared/src/net/ip.test.ts` (`parseIp`, CIDR helpers)                                                                                                                                                                                                                                                                                                                                                                                                  |
| 5   | Reject loopback, private, link-local, multicast, reserved and prohibited | `policy.address_prohibited_reason` (explicit tables, IPv6 outside `2000::/3` refused, stdlib properties as a fail-closed backstop), operator deny list `EXDV_DENY_NETWORKS` plus self-protection networks (`deny_listed`). Server: `prohibitedReason` / `isProhibitedAddress` in `ip.ts` for approved networks and observations, using the single table `packages/shared/src/net/prohibited-ranges.ts`. See [Prohibited addresses](#prohibited-addresses).                                                                                                        | `tests/test_policy.py` (`test_prohibited_ranges_both_edges`, `test_ipv6_transition_and_embedded_forms`, `test_public_unicast_is_allowed`, `test_scoped_ipv6_object_is_refused`, `test_deny_list_always_refused`, `test_no_flag_permits_loopback`); `ip.test.ts` (`isProhibitedAddress`); `packages/shared/src/net/prohibited-ranges.test.ts` (TS/Python parity); `tests/test_self_protection.py`                                                                                                                                                                                                          |
| 6   | Validate every resolved destination immediately before connecting        | `ScopePolicy.resolve` validates each A/AAAA answer; `ScopePolicy.assert_destination` re-validates the exact address inside `net.connect_tcp` (the only place a target socket is opened) before the socket exists; `port_checks.check_tcp_ports` re-asserts every address immediately before starting Nmap.                                                                                                                                                                                                                                                        | `tests/test_net.py` (`test_connect_tcp_refuses_before_creating_a_socket`, `test_connect_tcp_network_tier_needs_approved_network`); `tests/test_port_checks.py` `test_any_refused_address_aborts_before_nmap_runs`; `tests/test_policy.py` `test_assert_destination_*`                                                                                                                                                                                                                                                                                                                                     |
| 7   | Prevent DNS rebinding and TOCTOU                                         | The validated address object is what gets connected to (pinning, below); no component re-resolves the name between check and use. `resolve` refuses a CNAME chain that changed between the hop-by-hop walk and the address query (`cname_chain_invalid`). Nmap is given literal addresses with `-n`.                                                                                                                                                                                                                                                              | `tests/test_policy.py` (`test_rebinding_resolve_then_assert_destination`, `test_resolve_chain_changed_between_queries_refused`); `tests/test_net.py` (`test_rebinding_connection_uses_pinned_validated_address`, `test_connect_tcp_does_no_name_resolution`)                                                                                                                                                                                                                                                                                                                                              |
| 8   | Validate every redirect destination                                      | `net.http_get`: redirects are never followed automatically; each `Location` is parsed strictly (`_parse_url`), its host checked with `assert_hostname`, required to be the first host or an approved target hostname and to use the default or original port, then resolved and validated through `resolve` and pinned like the first hop; one deadline covers all hops. See [Redirects](#http-redirects).                                                                                                                                                        | `tests/test_net.py` (`test_redirect_hop_is_resolved_and_pinned_separately`, `test_redirect_to_ip_literal_is_refused_without_connecting`, `test_redirect_to_in_scope_name_resolving_private`, `test_redirect_out_of_scope_host`, `test_redirect_scheme_not_allowed`, `test_redirect_loop_is_cut`, `test_redirect_cap`, `test_redirect_to_unapproved_in_domain_host_is_not_resolved`, `test_redirect_to_other_ports_is_refused`, `test_http_get_respects_the_caller_deadline`, `test_http_get_stops_between_hops`); `tests/test_http_checks.py` `test_refused_redirect_is_partial_and_stops_at_the_refusal` |
| 9   | Reject out-of-scope CNAME targets unless separately approved             | `ScopePolicy.resolve` walks the chain hop by hop; any hop outside the job's domain is refused (`cname_out_of_scope`), as are loops, more than 8 hops and multiple CNAMEs at one name (`cname_chain_invalid`). **There is no "separately approved" mechanism: out-of-scope CNAME targets are always refused.**                                                                                                                                                                                                                                                     | `tests/test_policy.py` (`test_resolve_follows_in_scope_cname_chain`, `test_resolve_cname_leaving_domain`, `test_resolve_cname_out_and_back_in_is_refused`, `test_resolve_cname_loop`, `test_resolve_cname_chain_cap`, `test_resolve_multiple_cnames_refused`); `tests/test_net.py` `test_http_get_cname_escape`                                                                                                                                                                                                                                                                                           |
| 10  | Pin validated destination addresses                                      | `net.connect_tcp` connects to the literal validated address; `tls_handshake` and `_exchange` pass the hostname only as SNI / `Host`; the non-verifying certificate-capture handshake reuses the same pinned address. Nmap receives validated literal IPs (`-n`, no hostnames).                                                                                                                                                                                                                                                                                    | `tests/test_net.py` (`test_connect_tcp_connects_to_exact_literal_address`, `test_https_default_port_and_pinning`, `test_tls_handshake_pins_ipv6`); `tests/test_port_checks.py` `test_scan_runs_on_validated_network_tier_addresses`                                                                                                                                                                                                                                                                                                                                                                       |
| 11  | Timeouts, concurrency caps, request and rate limits                      | See [Resource limits](#resource-limits). `checks.CheckContext` (per-target deadline), `checks.RateLimiter` (per job), `ThreadPoolExecutor(max_workers=concurrency)`, `net` caps, Nmap `--max-rate` / `--max-parallelism` / `--host-timeout`; server: one queued/active job per domain and profile, `maxTargets`, 120 signed requests/min per worker key; scan quotas at creation (`services/quotas.ts`: 60 requested scans per user per hour, 24 requested active scans and 6 discovery runs per domain per day, exact PostgreSQL counts, `429` + `Retry-After`). | `tests/test_net.py` (`test_connect_tcp_caps_timeout`, `test_slow_drip_headers_hit_the_hop_deadline`, `test_no_response_times_out`); `tests/test_port_checks.py` (`test_host_timeout_is_capped_by_the_remaining_budget`, `test_too_little_budget_left_is_a_target_timeout`); `routes/scans.test.ts` ("refuses a second queued or active job…", "rate-limits each credential"); `routes/quotas.test.ts`                                                                                                                                                                                                     |
| 12  | No user-supplied shell commands or scanner flags                         | Profiles are data (`scanProfileConfigSchema`, strict); there is no field for arguments. `port_checks.build_nmap_argv` is a fixed template filled only with validated integers and canonical IPs; `run_nmap` uses `shell=False`, argument list, `env={"PATH": "/usr/bin:/bin"}`. `EXDV_NMAP_PATH` must be absolute without whitespace.                                                                                                                                                                                                                             | `tests/test_port_checks.py` (`test_standard_profile_argv_is_exact`, `test_deep_profile_argv_is_exact_ipv6`, `test_argv_without_service_identification_and_never_dangerous_flags`, `test_invalid_profile_ports_are_refused`); `tests/test_config.py` `test_nmap_path_must_be_absolute_without_whitespace`                                                                                                                                                                                                                                                                                                  |
| 13  | Bound scanner output and process resources                               | `run_nmap`: stdout ≤ 2 MB (process group killed on overflow), stderr counted and discarded (≤ 64 KB accounted), wall-clock timeout, rlimits applied by a fixed exec stub (`limited_argv`, no `preexec_fn`); XML screened for DTDs/entities before parsing. HTTP: headers ≤ 32 KB / 100 headers, body ≤ 64 KB read and discarded. systemd `MemoryMax=512M`, `TasksMax=64`, `CPUQuota=50%`.                                                                                                                                                                         | `tests/test_port_checks.py` (`test_run_returns_stdout_with_minimal_env_and_rlimits`, `test_oversized_output_kills_the_process`, `test_timeout_kills_the_process_group`, `test_stop_request_kills_the_process`, `test_dtds_and_entities_are_refused`); `tests/test_net.py` (`test_oversized_headers_are_bounded`, `test_header_count_is_bounded`, `test_body_is_bounded`)                                                                                                                                                                                                                                  |
| 14  | Record scope validation decisions in logs                                | `ScopePolicy._log` emits a structured `scope_decision` event (`jobId`, `subject`, `tier`, `allowed`, `reason`) for every check, host, CNAME hop, address and destination decision. Also `approved_network_ignored`, `approved_networks_shrunk`, `self_protection_refreshed`, `check_refused`, `check_failed`, `nmap_started`, `nmap_failed`. Server: audit `scan.refused`, `scan.cancel_requested` (authorisation withdrawn), `network.approved`, `network.revoked`, `scan.requested`.                                                                            | `tests/test_policy.py` `test_every_decision_is_logged_as_structured_json`, `test_resolve_mixed_answers_keeps_only_public`; `routes/networks.test.ts` ("approves … and audits the approval", "revokes an approval, audits it…")                                                                                                                                                                                                                                                                                                                                                                            |

## Prohibited addresses

Worker table (`policy._IPV4_PROHIBITED`, `policy._IPV6_PROHIBITED`); first match gives the reason.

| Range                                               | Reason          | Range                                       | Reason            |
| --------------------------------------------------- | --------------- | ------------------------------------------- | ----------------- |
| `0.0.0.0/8`                                         | `unspecified`   | `::/128`                                    | `unspecified`     |
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`     | `private`       | `::1/128`                                   | `loopback`        |
| `100.64.0.0/10`                                     | `cgnat`         | `::ffff:0:0/96`, `::ffff:0:0:0/96`          | `ipv4_mapped`     |
| `127.0.0.0/8`                                       | `loopback`      | `::/96`                                     | `ipv4_compatible` |
| `169.254.0.0/16`                                    | `link_local`    | `64:ff9b::/96`, `64:ff9b:1::/48`            | `nat64`           |
| `192.0.0.0/24`                                      | `reserved`      | `100::/64`                                  | `discard`         |
| `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | `documentation` | `2001::/32`                                 | `teredo`          |
| `192.88.99.0/24`                                    | `6to4`          | `2001:2::/48`                               | `benchmarking`    |
| `198.18.0.0/15`                                     | `benchmarking`  | `2001:10::/28`, `2001:20::/28`, `2001::/23` | `reserved`        |
| `224.0.0.0/4`                                       | `multicast`     | `2001:db8::/32`, `3fff::/20`                | `documentation`   |
| `255.255.255.255/32`                                | `broadcast`     | `2002::/16`                                 | `6to4`            |
| `240.0.0.0/4`                                       | `reserved`      | `fc00::/7`                                  | `ula`             |
|                                                     |                 | `fe80::/10`                                 | `link_local`      |
|                                                     |                 | `fec0::/10`                                 | `site_local`      |
|                                                     |                 | `ff00::/8`                                  | `multicast`       |

Additionally:

- Any IPv6 address outside `2000::/3`, or with a scope id, is `reserved`.
- Every IPv6 transition form that embeds IPv4 (mapped, compatible, NAT64, 6to4, Teredo) is refused even
  when the embedded IPv4 address is public: the worker never reaches IPv4 through IPv6 forms.
- Backstop: if Python's `ipaddress` considers the address loopback, private, link-local, multicast,
  reserved, unspecified or not global, it is refused (`reserved`). The tables do not depend on those
  properties, which differ between Python releases.
- `EXDV_DENY_NETWORKS` (≤ 100 canonical CIDRs, validated at start-up; a malformed entry stops the worker,
  and `ScopePolicy.from_job` fails closed on one) adds operator-specific ranges — **the home's own public
  IP belongs here** — refused at every tier with reason `deny_listed`. While active scanning is enabled,
  [self-protection](#home-network-self-protection) adds this host's interface and egress networks to the
  same list.
- There is no flag, environment variable or argument that permits a prohibited address. Tests that need
  a loopback server monkeypatch `address_prohibited_reason` for one address (`test_no_flag_permits_loopback`,
  `test_loopback_allowance_is_test_only`).

Server table: `PROHIBITED_RANGES` in `packages/shared/src/net/prohibited-ranges.ts` (re-exported by
`ip.ts`), the single TypeScript list used by the API and the SPA. It holds exactly the same networks as
the worker's tables: `prohibited-ranges.test.ts` parses `worker/app/policy.py` and fails if the two lists
differ. On the server a range is refused if it overlaps a prohibited range in either direction, and IPv6
outside `2000::/3` is refused as well. The systemd egress filter mirrors the same list (see
[below](#defence-in-depth-systemd-egress-filter)).

## Resolution, CNAMEs and pinning

`ScopePolicy.resolve(hostname, resolver, tier, lifetime)` (web and network tiers only):

1. `assert_hostname`: strict A-label normalisation; the name must be the job's domain or beneath it on
   a label boundary (`out_of_scope_host`), otherwise nothing is queried.
2. CNAME walk: query `CNAME` at the current name; every target must be a valid name inside the job's
   domain (`cname_out_of_scope`), with no loop, at most `MAX_CNAME_HOPS = 8`, and one CNAME per name
   (`cname_chain_invalid`). Each hop is logged.
3. Query `A` and `AAAA` at the final name. If the resolver's canonical name differs from the walked
   chain's end (the chain changed between queries), refuse (`cname_chain_invalid`).
4. Each answer is parsed strictly; wrong-family answers, prohibited, deny-listed and (network tier)
   unapproved addresses are dropped with a logged reason. Mixed answers keep only the allowed addresses.
   If none remain: `no_allowed_address`.

DNS errors (`NXDOMAIN`, timeout) propagate unchanged; NODATA is "no records". The resolver is
`dns_checks.DnspythonResolver` with its cache disabled, using `EXDV_DNS_RESOLVERS` (default Cloudflare
and Quad9 over IPv4/IPv6).

**Pinning.** `net.connect_tcp` calls `assert_destination` (re-validates the address, the tier, approved
networks, the deny list and the active-scanning flag) **before** creating a socket, then connects to
the literal address — no name resolution happens. TLS uses `server_hostname=<hostname>` for SNI and
certificate checking; HTTP sends `Host: <hostname>`. Because the connection never re-resolves, a
rebinding answer after validation cannot redirect it.

Address selection: `tls_certificate` checks at most the first allowed IPv4 and first allowed IPv6
address (`tls_checks.select_addresses`); HTTP uses the first allowed address per hop; port checks use
up to `MAX_ADDRESSES = 4` per target.

## HTTP redirects

`net.http_get` (http/https only, GET, `Connection: close`, written by hand on the pinned socket):

- Redirect statuses 301/302/303/307/308 with `Location` are followed manually, at most
  `MAX_REDIRECTS = 5` (callers may lower it). A URL seen before ends the chain (`too_many_redirects`).
- Each next URL is resolved against the current one, the fragment dropped, then parsed strictly:
  printable ASCII, ≤ 2048 chars, scheme `http`/`https` only (`scheme_not_allowed`), host must be a
  name — IP literals, brackets and userinfo are refused (`invalid_url`); explicit port 1–65535 without
  leading zero.
- The host must be inside the job's domain (`redirect_out_of_scope`) **and** be the first URL's host or
  one of the job's approved target hostnames (`ScopePolicy.target_hostnames`: the claimed targets plus
  the in-domain hostnames in the snapshot's `targets`) (`redirect_not_approved_target`). Other names
  under the domain — e.g. pending CT discoveries — are neither resolved nor contacted.
- The port must be the scheme's default (80 for `http`, 443 for `https`) or the first URL's explicit
  port (`port_not_allowed`), so a web-tier redirect cannot become a probe of an arbitrary port.
- Refusals are recorded without connecting. An allowed host is resolved and validated by `resolve` and
  pinned exactly like the first hop.
- One deadline covers every hop of a URL: `min(start + 2 × timeout, deadline)`, where the caller passes
  the target's remaining budget. The job's stop signal (user cancel, authorisation withdrawn, lease
  lost, shutdown) is checked before every hop and recorded as a `stopped` hop.
- Every hop, including refused ones, is recorded in the `http` observation's `evidence.hops`
  (`url`, `ip`, `status`, `decision`, `error`). A refused redirect makes the observation `partial`.
- `https://` is tried first; `http://` only if the HTTPS attempt reached an address but got no HTTP
  response (`http_checks.check_http`).

## Nmap (network tier)

Built only by `port_checks.build_nmap_argv`; run by `run_nmap`:

```text
[nmap, -sT, -Pn, -n, --unprivileged, --max-retries, 1, --host-timeout, <T>s,
 --max-rate, <R>, --max-parallelism, <P>, -p, <ports>, (-sV --version-light), (-6),
 -oX, -, <ip>...]
```

- `<R>` = clamp(round(`ratePerSecond` × 10), 1, 100); `<P>` = clamp(`concurrency` × 4, 1, 16);
  `<T>` = max(5, min(`targetSeconds`, remaining target budget)). Seeded profiles: standard `R=10`,
  `P=8`; deep `R=5`, `P=4`.
- `<ports>`: the profile's `tcpPorts`, validated integers 1–65535, at most 1024, sorted and unique.
- `-sV --version-light` only when the profile lists `service_identification`. `-6` for IPv6; IPv4 and
  IPv6 are separate runs. No `--script`, `-O`, `-sS`, `-A` or any other option exists in the template.
- `<ip>`: canonical text of validated addresses (cannot start with `-`), each re-asserted with
  `assert_destination(tier="network")` immediately before the run; one refusal aborts the check before
  any process starts.
- Process: `shell=False`, stdin `/dev/null`, `env={"PATH": "/usr/bin:/bin"}` (no `HOME`, `NMAPDIR`),
  `close_fds`, its own process group (`process_group=0`); the group is killed (`SIGKILL`) on timeout,
  output overflow or job stop (cancellation reaches a running Nmap); wall clock `<T> + 30 s`.
- rlimits `RLIMIT_AS` 512 MB, `RLIMIT_CPU` = timeout + 1 s, `RLIMIT_NOFILE` 1024, no core dumps
  (clamped to existing hard limits). They are **not** set with `preexec_fn` (unsafe in this
  multi-threaded worker). `limited_argv` wraps the argv in a fixed stub,
  `<python> -I -S -c <constant code> <nmap argv…>`, into which only the integer limits computed in the
  parent are interpolated; the stub calls `setrlimit` and then `os.execv`s the Nmap argv unchanged, so
  the limits apply from Nmap's first instruction and no shell is involved.
- **NSE under `-sV`.** Version detection also runs Nmap's `version`-category NSE scripts; no other
  category can run because the template has no `--script`, `-sC` or `-A`. With the installed Nmap 7.94
  that is 46 scripts (`nmap --script-help version`). None is in the `intrusive`, `exploit`, `brute`,
  `dos`, `malware` or `external` categories; they are protocol-specific version/banner probes (e.g.
  `http-server-header`, `fingerprint-strings`, `rpc-grind`). The only one also tagged `vuln`
  (`wdb-version`) has a UDP-only port rule and cannot run under this TCP connect scan.
- Output: XML on stdout ≤ 2 MB. Before parsing, any `<!ENTITY` or a DOCTYPE other than Nmap's bare
  `<!DOCTYPE nmaprun>` is refused. Only `(validated IP, profile port)` pairs become `port`
  observations; anything else Nmap reports is ignored. A run with no results fails the check
  (`nmap_no_results`), so an empty scan is never reported as "all closed".

## Resource limits

| Limit             | Value / source                                                                                                                                                                          |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Targets per job   | `maxTargets` (seeded 50; schema ≤ 1000), enforced at creation and by the worker                                                                                                         |
| Concurrency       | `concurrency` threads per job (seeded 1–4; schema ≤ 16); one job at a time per worker                                                                                                   |
| Rate              | `RateLimiter(ratePerSecond)` per job before every network step (DNS query set, TLS handshake, HTTP URL attempt, Nmap run; redirect hops within one attempt are not separately spaced)   |
| Per-target budget | `timeouts.targetSeconds` (`TargetTimeout` → target `failed`, `target_timeout`)                                                                                                          |
| Socket timeouts   | `connectMs` / `readMs`, clipped to the remaining budget; `net` caps any timeout at 60 s                                                                                                 |
| HTTP deadline     | one deadline per URL across all hops: min(2 × timeout, the target's remaining budget); slow-drip servers and slow redirect chains cannot hold the worker                                |
| HTTP response     | headers ≤ 32 KB, ≤ 100 headers, values ≤ 2048 chars; body ≤ 64 KB read and discarded                                                                                                    |
| Redirects         | ≤ 5                                                                                                                                                                                     |
| Evidence          | ≤ 16 KB per observation; header values ≤ 512 printable ASCII; no cookies or bodies stored                                                                                               |
| Nmap              | see above                                                                                                                                                                               |
| Server            | one queued/claimed/running job per domain and profile (partial unique index); ≤ 3 attempts with backoff; worker API 120 req/min per key, body ≤ 1 MB, ≤ 500 observations per submission |
| systemd           | `MemoryMax=512M`, `TasksMax=64`, `CPUQuota=50%`, `LimitNOFILE=4096`                                                                                                                     |

## Server-side controls

**Job creation** (`services/scans.ts` `createScan`, permission `scans:request` — admin and analyst):
active profiles need `ACTIVE_SCANNING_ENABLED=true` and a currently authorised domain
(`domainAuthorisedForActive`: `verified` and review date not passed). The snapshot stores the domain
state, profile version and config, targets and — for active profiles only — the currently active
approved networks. Cron-created jobs are passive (monitoring, discovery) unless an administrator
enabled [scheduled active scans](#scheduled-active-scans), which go through the same checks.

**Claim-time re-authorisation** (`services/job-lifecycle.ts` `claimJob` / `claimRefusal`): before an
active job is handed out, the server re-checks the flag (`active_scanning_disabled`) and the domain's
current authorisation (`domain_not_authorised`); a refused job is cancelled, its targets skipped, and
`scan.refused` audited. Targets whose asset is no longer `approved` (rejected, suspended or deleted
while the job waited) are marked `skipped` with `asset_not_approved` and not handed out; if none remain
the job is refused with `no_approved_targets`. The snapshot's approved networks are **intersected**
with the networks still active (`networks.ts` `intersectNetworks`): revocation or expiry shrinks scope;
nothing is added.

**In-flight cancellation** (`heartbeat`, `submitResultsDetailed`, `stopActiveJobsForDomains`):

- Every heartbeat and result submission for a held job re-runs the same authorisation check. If it
  fails (kill switch off, domain revoked, lapsed or deleted, monitoring off for a scheduled job), the
  job is flagged `cancel_requested_at` (audited `scan.cancel_requested`, system actor, with the
  reason), the heartbeat answers `cancelRequested: true` with `approvedNetworks: []`, and any result
  submission carrying `tls`/`http`/`port` evidence is refused with `409` (passive and status-only
  submissions are still accepted so the job can wind down).
- Revoking a domain (`revokeDomain`) or its administrator authorisation lapsing
  (`expireStaleChallenges`, run on reads/writes and by the Cron Trigger) stops the domain's active jobs
  in the same transaction: queued ones are cancelled (`scan.cancelled`), claimed/running ones flagged
  (`scan.cancel_requested`). Passive jobs are unaffected.
- Each heartbeat also returns the job's **current** approved networks (snapshot ∩ active now). The
  worker shrinks its policy to the intersection before starting any further check
  (`queue.PolicyHolder`, `ScopePolicy.with_approved_networks_shrunk`); a heartbeat can never widen
  scope. Network revocation therefore takes effect within one heartbeat interval (60 s) for checks that
  have not started yet.
- On the worker, a stop request interrupts work in progress: HTTP checks stop between hops, the second
  (non-verifying) TLS handshake is skipped, and a running Nmap process group is killed.

**Approved networks** (`services/networks.ts`): canonical CIDR, entirely public (no overlap with a
prohibited range, IPv6 within `2000::/3`), no broader than /16 (IPv4) or /32 (IPv6), no overlap with
another active approval, reason ≥ 10 chars, review date ≤ 24 months; approval and revocation audited
(`network.approved`, `network.revoked`). Approvals are serialised with a transaction-scoped advisory
lock (`pg_advisory_xact_lock`), so two concurrent overlapping approvals cannot both pass the overlap
check. The worker additionally ignores (logs) malformed entries or entries broader than /8 / /20.

**Ingestion re-validation** (`services/observations.ts` `validate`, in the results transaction): every
observation must reference a target of the job, have `observedAt` within −7 days / +5 minutes, and:
`dns` hostnames inside the domain; `registration` for the apex only; `tls`/`http`/`port` only for an
active profile listing a producing check (for `tls`, the check named in its `check` field); their
`ipAddress` must be strictly-formatted public unicast (`isProhibitedAddress`); the `tls` hostname and
the `http` URL host (strict parser, no IP literals or userinfo, LDH labels without empty labels) must
**equal the observation's target hostname**; `port` in the profile's `tcpPorts` and inside the job's
networks as intersected **at ingestion time**; `tls` with `check: "tls_configuration"` likewise inside
those networks. Hostnames must be syntactically valid (`isValidHostname`; `isWithinDomain` rejects
names with empty labels). Evidence is capped at 16 KB in UTF-8 bytes. Any invalid observation rejects
the whole submission (400).

## Scheduled active scans

`services/scan-schedule.ts` (API: [`/settings/scan-schedule`](api-specification.md#scan-schedule-scheduled-active-scans)).

- **Off by default.** Only an administrator (`scan_policies:manage`) can enable it; every change is
  audited (`settings.scan_schedule_updated`, before/after). A missing or invalid stored setting is
  treated as disabled.
- **Both switches.** The cron schedules nothing unless the setting is enabled **and** the server's
  `ACTIVE_SCANNING_ENABLED` is `true` (the cron entry point parses it with `loadConfig`; an invalid
  configuration fails closed). The worker's own switch and `EXDV_PROFILES` still decide whether a
  queued job is ever run.
- **Same scope rules as a user-requested active scan.** Only monitored domains currently authorised
  for active scanning (DNS-verified or administrator-authorised with the review date not passed) are
  considered, re-checked under a row lock in the creating transaction. Targets are the approved assets
  only (CT-log discoveries stay `pending` and are never targeted); the apex is approved implicitly
  through domain verification as for a manual scan, recorded with the administrator who enabled the
  schedule as accountable approver (no such user → no implicit approval). Network-tier checks reach
  only the approved networks captured in the snapshot, intersected with those still active.
- **Claim-time and in-flight re-checks apply unchanged**, plus `monitoring_disabled` for scheduled
  jobs: a domain that is revoked, lapses or has monitoring switched off while its job waits is refused
  at claim; running jobs are stopped at the next heartbeat.
- **Bounded.** Fixed server-defined profiles only (`quick` or `standard`, never `deep`), interval 1–30
  days, staggered across the interval by domain-id hash, at most 30 jobs per cron run, queued behind
  user-requested and passive jobs (priority 220), one active job per domain and profile.
- **Audited.** One `scan.scheduled` row per run with counts and job ids; implicit apex approvals are
  audited `asset.approved` individually.

## Kill switches

Two independent switches; both must be on for any target connection.

| Switch                                  | Where                           | Effect when off                                                                                                                                                                                                                                                                                                                               |
| --------------------------------------- | ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ACTIVE_SCANNING_ENABLED` (server)      | `apps/web/wrangler.jsonc` var   | Active jobs refused at creation (409) and cancelled at claim (`active_scanning_disabled`); **running** active jobs are told to stop at their next heartbeat and their active evidence is refused (409). Only `"true"`/`"false"` accepted; anything else fails configuration closed (`config.ts` `parseFlag`). Changing it needs a deploy.     |
| `EXDV_ACTIVE_SCANNING_ENABLED` (worker) | `/etc/exdomainvault/worker.env` | Job with an active profile or connecting check refused before any check (`Worker._refusal`); and `assert_check_allowed` / `assert_destination` refuse every connection (`active_scanning_disabled`). Only `true`/`false`; read at start-up, so changes need a restart (which also ends the current job; its lease expires and it is retried). |

`EXDV_PROFILES` is a further operator control: the worker claims only the listed profiles (default
`passive,discovery`). A user can also cancel a running job (picked up at the next heartbeat).

## Passive discovery (Milestone 9)

`worker/app/discovery.py` (protocol details in
[`worker-protocol.md`](worker-protocol.md#passive-discovery-milestone-9)). Discovery finds candidate
hostnames; it is evidence, not authorisation.

- **Passive only.** The `discovery` check is in the passive tier (`PASSIVE_TIER_CHECKS`,
  `scope.PASSIVE_CHECKS`). It makes one HTTPS request to a **fixed** provider URL
  (`https://crt.sh/?q=%25.<domain>&output=json`, the domain being the validated registrable job
  domain) and resolves candidates through the configured public resolvers. It never opens a connection
  to a candidate or target, never builds a scope policy, and never runs a web/network check: a
  profile that combines `discovery` with `active: true` or any connecting check is refused before
  anything runs (`invalid_profile`), whatever `EXDV_ACTIVE_SCANNING_ENABLED` says. Tests replace every
  connecting primitive (`net.connect_tcp`, `tls_handshake`, `http_get`), the policy factory and
  self-protection with functions that fail the test (`tests/test_discovery.py`).
- **Provider request hygiene.** HTTPS with certificate verification; redirects are never followed (a
  redirect is a permanent provider error); proxy variables from the environment are ignored
  (`trust_env=False`); identifying `User-Agent: ExDomainVault-worker/<version> (passive discovery)`;
  profile connect/read timeouts clipped to the target budget; the body is streamed and capped at
  32 MB (beyond it the run is `partial`); one JSON element is capped at 1 MB; at most 50 000 distinct
  raw names are tracked; at most one provider request every 3 s per worker process.
- **Never expands scope.** Candidates are reported as `discovery` observations; the server stores them
  as `pending` assets. Nothing the worker discovers is added to the running job, to its scope snapshot
  or to any later job; only an explicit approval in the application can make a discovered name a scan
  target.
- **Filters.** Certificates expired for more than 365 days are ignored. Names are lowercased, one
  trailing dot stripped, a leading `*.` stripped and flagged (`wildcard`), any other `*` dropped; IDNs
  are converted to A-labels that must round-trip (`idna` package, IDNA 2008 + UTS #46); emails, IP
  literals, empty labels, non-LDH labels (including `_`), labels over 63 and names over 253 characters
  are dropped; the exact label-boundary check (`name == domain or name.endswith("." + domain)`) rejects
  `example.com.evil.com`, `evilexample.com` and similar. The server re-validates every hostname.
- **Limits.** At most 2000 candidates per run (more → `partial`), at most 300 resolved (A, AAAA,
  CNAME), DNS rate-limited by the profile's `ratePerSecond` and `concurrency`, everything within
  `targetSeconds`.
- **Failures never look like absence.** Transient provider failures are reported as retryable job
  failures; permanent ones and truncated runs produce one `error`/`partial` observation for the domain
  so the run is known to be incomplete.

## Wider discovery (Milestone 15)

`worker/app/discovery.py` (Cert Spotter) and `worker/app/network_checks.py` (`network` check); protocol
in [`worker-protocol.md`](worker-protocol.md#wider-discovery-milestone-15).

- **Passive only.** `network` is in the passive tier (`PASSIVE_TIER_CHECKS`, `scope.PASSIVE_CHECKS`,
  `PASSIVE_CHECKS` in `packages/shared`). It contacts only the IANA bootstrap host
  (`data.iana.org`), the five RIR RDAP hosts (`rdap.apnic.net`, `rdap.arin.net`, `rdap.db.ripe.net`,
  `rdap.lacnic.net`, `rdap.afrinic.net`; any other host, including in a redirect, is refused) and the
  configured DNS resolvers (PTR, then A/AAAA/CNAME of names found). It never connects to the
  addresses it looks up or to any target. Cert Spotter is one more fixed CT URL
  (`https://api.certspotter.com/v1/issuances?...`). Tests replace every connecting primitive with
  functions that fail the test (`tests/test_network_checks.py`, `tests/test_certspotter.py`).
- **Rate limits.** RDAP: at least 1 s between requests to one registry (process-wide), at most 100
  `/ip` queries per run, one bounded 429 retry. PTR: the job's `ratePerSecond` (5/s for the discovery
  profile), at most 2048 per run, only IPv4 networks of ≤ 1024 addresses registered to the
  organisation. Cert Spotter: ≥ 2 s between requests, ≤ 10 pages. Everything within `targetSeconds`.
- **Ownership is not authorisation.** A network whose RDAP record names a configured organisation is
  shown as "registered to your organisation"; it is **never** added to the approved networks. The
  Attack Surface page offers administrators a link that pre-fills the existing approved-networks form
  (CIDR and label only); the administrator must still write a reason and submit, and the normal limits
  (public space, at most a /16 or /32, review date, audit) apply. PTR names become `pending` assets.
- **Scope of reverse DNS.** Only names within the job's own domain (exact label boundary) are
  reported; names of other domains are counted, not stored.
- **Untrusted registry data.** RDAP text is display data: clipped, never used for scope; the server
  re-validates addresses (public, inside the reported range) and re-computes the organisation match.

## Lookalike domains (Milestone 15)

`worker/app/lookalike_checks.py` (protocol in
[`worker-protocol.md`](worker-protocol.md#lookalike-domains-milestone-15)). A lookalike is somebody
else's name, so it is **never a target**:

- **Passive only, DNS only.** The `lookalike` check is in the passive tier (`scope.PASSIVE_CHECKS`,
  `PASSIVE_CHECKS` in `packages/shared`). It sends NS/SOA/A/AAAA/MX queries for the candidate names
  to the worker's configured public resolvers and nothing else: no HTTP, no TLS, no port probe, no
  RDAP/WHOIS, never a connection to a candidate's addresses or name servers (beyond the recursion the
  resolver does). A profile that combines `lookalike` with `active: true` or any connecting check is
  refused before anything runs (`invalid_profile`). Tests replace `socket.create_connection`,
  `socket.socket.connect`, `ssl.SSLContext.wrap_socket` and the httpx transport with functions that
  fail the test (`tests/test_lookalike_checks.py`).
- **The server decides the names.** Candidates are generated on the server and frozen in the job's
  scope snapshot; the worker resolves exactly that list (≤ 1500, validated: lowercase LDH, known
  technique, never within the job's domain) and the server accepts observations only for listed
  candidates, never for a name within any monitored domain.
- **Opt-in per domain.** Only domains with `brand_monitoring` on (default off; administrator,
  audited) get weekly brand jobs or manual checks.
- **Limits.** Profile `brand`: 10 queries/s, 8 threads, 1800 s per run; NXDOMAIN costs one query per
  candidate, registered candidates at most five.
- **Failures never look like absence.** SERVFAIL/timeout on a candidate is reported as an `error`/
  `timeout` observation (never "not registered"); a run that hits its time budget fails the target, so
  LOOK-001 findings resolve only after a complete run that no longer finds the name.

## Home-network self-protection

`worker/app/self_protection.py`, active only while `EXDV_ACTIVE_SCANNING_ENABLED=true`. The home host's
own addresses are not always in the prohibited ranges: the router's NAT egress IPv4 is public by
definition (hair-pinning can reach the router's admin interface), and a global IPv6 /64 is the home LAN
with every device globally addressable. At start-up and then hourly (`REFRESH_SECONDS = 3600`; whether a
refresh is due is checked in the poll loop and before each active job), the worker computes:

1. every address on a local interface — IPv4 from `/proc/self/net/fib_trie` (`/32 host LOCAL` entries;
   fallback `SIOCGIFADDR` per interface), IPv6 from `/proc/self/net/if_inet6` (global addresses as
   their /64, others as /128);
2. the public egress address(es): one `whoami.cloudflare` TXT query in the CHAOS class to `1.1.1.1` and
   `2606:4700:4700::1111` (a resolver query, never a target contact); IPv6 egress as its /64.

These are added to every active job's deny list (`deny_listed`) alongside `EXDV_DENY_NETWORKS`. An
egress address detected earlier stays denied if a later detection fails (denying more only shrinks
scope). **Fail closed:** if no IPv4 egress address was detected in the latest refresh and
`EXDV_DENY_NETWORKS` is empty, web and network checks are refused with `egress_ip_unknown` until a later
detection succeeds (passive checks still run). Because detection only counts IPv4, an IPv6-only host
must list its prefix in `EXDV_DENY_NETWORKS`. Detected values are logged as `self_protection_refreshed`
(they are the operator's own addresses, not secrets). Tests: `tests/test_self_protection.py`.

## Defence in depth: systemd egress filter

`worker/deploy/exdomainvault-worker.service` sets:

```ini
IPAddressAllow=127.0.0.53/32
IPAddressDeny=localhost link-local multicast
IPAddressDeny=0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12
IPAddressDeny=192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 192.168.0.0/16 198.18.0.0/15
IPAddressDeny=198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4 255.255.255.255/32
IPAddressDeny=::/128 ::1/128 ::ffff:0:0/96 ::ffff:0:0:0/96 ::/96 64:ff9b::/96 64:ff9b:1::/48
IPAddressDeny=100::/64 2001::/23 2001::/32 2001:2::/48 2001:10::/28 2001:20::/28 2001:db8::/32
IPAddressDeny=3fff::/20 2002::/16 fc00::/7 fe80::/10 fec0::/10 ff00::/8
IPAddressDeny=::/3 4000::/2 8000::/1
```

The deny list mirrors the prohibited table (worker and server) plus everything outside `2000::/3`;
`IPAddressAllow=` wins over `IPAddressDeny=`, so only the systemd-resolved stub stays reachable.
systemd implements these as eBPF programs attached to the **unit's cgroup**; they filter IP packets of
every process in that cgroup. Child processes inherit their parent's cgroup (a new process group does
not change the cgroup), so **Nmap launched by the worker is subject to the same filter** (and to the
unit's `MemoryMax`, `TasksMax`, `CPUQuota`, seccomp filter and empty capability set). Caveats:

- It relies on cgroup v2 with BPF support in the kernel; it was not separately verified on the host
  with a test connection. Verify with e.g. `systemd-run -p IPAddressDeny=… curl …` if in doubt.
- It does **not** cover the home's public IP or global IPv6 prefix (those are dynamic); the
  application-level self-protection and `EXDV_DENY_NETWORKS` do. It is a backstop, not a replacement
  for the scope validator.
- It applies to all of the worker's traffic, including RDAP and resolver queries; a LAN resolver needs
  an `IPAddressAllow=` entry.

## Red-team reviews (Milestone 6 gate)

Two adversarial reviews were run against the Milestone 6 code before active scanning may be enabled.
Every attack is kept as a regression test that asserts the **safe** behaviour (a failing test is an
open vulnerability); no test contacts a live third-party system.

**Worker** — `worker/tests/test_redteam.py`, 497 attack tests (address encodings, rebinding, redirects,
CNAME tricks, Nmap argv/output abuse, job tampering). Verdict **PASS** once the three Medium findings
were fixed. All findings:

| ID   | Severity | Finding                                                                                       | Fix                                                                                                           |
| ---- | -------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| RT-1 | Medium   | A redirect could go to any explicit port on an in-domain name (web tier became a port probe). | Redirects only to the scheme's default port or the first URL's explicit port (`port_not_allowed`).            |
| RT-2 | Medium   | Redirect hosts were checked against the domain only, not the job's approved targets.          | Redirects only to the first host or an approved target hostname (`redirect_not_approved_target`).             |
| RT-3 | Low      | The HTTP time limit was per hop, so a redirect chain could hold a thread for minutes.         | One deadline across all hops, capped by the target's budget; stop checked between hops.                       |
| RT-4 | Low      | The worker accepted a job domain that is a TLD, public suffix or single label.                | `scope.assert_registrable_domain` (single label, `.arpa`, built-in public-suffix list) → `scope_rejected`.    |
| RT-5 | Medium   | The home's public IPv4 and routable IPv6 LAN were reachable unless manually deny-listed.      | [Self-protection](#home-network-self-protection), fail closed on unknown egress (`egress_ip_unknown`).        |
| RT-6 | Low      | `IPAddressDeny=` covered fewer ranges than the application table.                             | The unit now mirrors the full table plus everything outside `2000::/3`.                                       |
| RT-7 | Info     | Does `-sV` run NSE scripts?                                                                   | Yes, `version` category only; reviewed — see [Nmap](#nmap-network-tier).                                      |
| RT-8 | Info     | rlimits were set with `preexec_fn` in a multi-threaded process.                               | Fixed exec stub (`limited_argv`) and `process_group=0`.                                                       |
| RT-9 | Info     | RDAP redirects were not checked against the address policy.                                   | Redirect targets pre-validated (HTTPS, public addresses via the worker's resolver); see `worker-protocol.md`. |

**Server** — 500 attack tests in `packages/shared/src/net/redteam.test.ts` (IP/CIDR parsing,
encodings, boundaries, label boundaries, parity with the worker tables) and
`apps/web/worker/routes/redteam.test.ts` (approved-networks API, RBAC/CSRF, snapshot and claim,
observation ingestion, job ownership/replay/fencing). Findings, all fixed:

| ID  | Severity | Finding                                                                                                | Fix                                                                                                                           |
| --- | -------- | ------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------- |
| F1  | High     | Claimed/running active jobs kept going after the kill switch was turned off or the domain was revoked. | [In-flight cancellation](#server-side-controls): heartbeat/results re-check, revoke/lapse flags jobs, 409 on active evidence. |
| F2  | Medium   | Claim did not re-check asset approval.                                                                 | Unapproved targets skipped (`asset_not_approved`); none left → `no_approved_targets`.                                         |
| F3  | Medium   | TLS hostname / HTTP URL host only had to be inside the domain.                                         | Must equal the observation's target hostname.                                                                                 |
| F4  | Medium   | The server table lacked `2001::/23` and `3fff::/20`.                                                   | Single shared table `prohibited-ranges.ts` with a TS/Python parity test.                                                      |
| F5  | Low      | Malformed hostnames (empty labels) were accepted in observations.                                      | `isValidHostname`; `isWithinDomain` rejects empty labels; strict URL host parsing.                                            |
| F6  | Low      | Network approval overlap check was racy (read-then-insert).                                            | Transaction-scoped advisory lock.                                                                                             |
| F7  | Low      | TLS evidence could not be distinguished as `tls_configuration` (network tier).                         | `tls.check` field; `tls_configuration` requires an approved network; stored in `evidence.check`.                              |

## Subdomain-takeover evidence and e-mail records (Milestone 15)

Rule DNS-008 ("Subdomain takeover risk confirmed by provider response") and the e-mail rules
EMAIL-001…005 add **no new kind of traffic**:

- **Nothing is ever claimed.** No bucket, app, site or custom domain is created, registered or
  bound at any provider, and no POST or account action is made. A finding states that the public
  fingerprint matches; it never "proves" a takeover by performing one.
- **No extra requests for takeover evidence.** The worker matches provider "unclaimed resource"
  signatures (`worker/app/takeover_fingerprints.json`, mirrored from
  `packages/rules/src/takeover-fingerprints.ts`, curated from
  [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)) against the body that the
  existing `http_availability` GET already reads (`net.MAX_BODY_BYTES` = 64 KB). The body stays in
  memory (`HttpHop.body`, excluded from `repr`); only `evidence.takeoverSignature = { provider,
signature }` is uploaded. Only the requested host's own final response is matched (not a response
  reached through an in-domain redirect to another host).
- **Scope is unchanged.** The scope validator still refuses web checks whose CNAME chain leaves the
  domain (`cname_out_of_scope`, requirement 9), so the worker never sends a request to the provider
  behind a dangling CNAME. Consequently DNS-008 fires in practice from **passive DNS evidence**
  (CNAME chain ending in NXDOMAIN at a provider whose names can be re-registered — Azure, Elastic
  Beanstalk); the HTTP-signature path applies today only to approved hosts served by a provider
  without a CNAME (GitHub Pages apex A records), and is ready for a future, separately approved
  out-of-domain CNAME policy. Domain verification still does not authorise contacting
  third-party hosting.
- **DNS evidence.** For an aliased name, the A/AAAA observation's `rcode` is the chain's terminal
  status and `evidence.canonicalName` its end — now also recorded for NXDOMAIN answers
  (`dns_checks._nxdomain_canonical`).
- **E-mail records are passive DNS only.** At the apex the `dns` check adds TXT lookups through the
  configured public resolvers: `<selector>._domainkey.<apex>` for 17 common DKIM selectors (always),
  and `_mta-sts.<apex>`, `_smtp._tls.<apex>`, `default._bimi.<apex>` only when the same run's apex MX
  lists a real exchanger. **The MTA-STS policy file (`https://mta-sts.<apex>/.well-known/mta-sts.txt`)
  is never fetched**; only the DNS record is checked. All lookups pass through `ctx.before_network_call()`
  (profile rate limit, target deadline, stop signal) like every other DNS query.
- Tests use fake resolvers and in-memory `HttpResult`s only (`tests/test_dns_checks.py`,
  `tests/test_http_checks.py`, `test_signature_detection_makes_no_extra_requests`).

## What is not done / residual risks

- **`tls_configuration` is not run.** It is accepted in the deep profile but only logged
  (`check_not_implemented`); `net` has no version-pinned handshake primitive. The negotiated version is
  recorded in `tls.protocolVersion`. The target's status does not reflect the skipped check.
- **Out-of-scope CNAME targets are always refused.** Requirement 9's "unless separately approved" has
  no mechanism, so hostnames that CNAME to a CDN or SaaS name outside the domain get no web or network
  checks (`cname_out_of_scope`). This also means the HTTP half of subdomain-takeover confirmation
  (DNS-008) cannot run for dangling CNAMEs; DNS-008 relies on NXDOMAIN evidence for them.
- **DKIM coverage is a guess list.** Selectors cannot be enumerated; dated or per-tenant selectors
  (Mimecast `mimecast20190104`, Amazon SES tokens) are never found, which is why EMAIL-004 is
  informational with low confidence.
- **CNAME scope is domain-level, not target-level.** A CNAME chain may pass through any name under the
  job's domain, including names that are not approved assets; the connection still goes to the
  validated address of the approved target's hostname. (Redirects, by contrast, are limited to approved
  target hostnames.)
- **The resolver is trusted for public address choice.** Web checks go to whatever public address the
  domain's DNS returns; a domain owner (or a spoofed, non-DNSSEC-validated answer) can point a
  hostname at a third party's public address, which then receives one TLS handshake and HTTP GETs.
  Prohibited, deny-listed and self-protection ranges are still enforced. Network checks are limited to
  approved networks.
- **Self-protection trusts its detection.** The egress address comes from one resolver's view
  (Cloudflare `whoami`); a host with several egress paths, or an address change between hourly
  refreshes, can leave a home address undetected for up to an hour. Listing static addresses in
  `EXDV_DENY_NETWORKS` closes that gap. IPv6-only hosts must configure it.
- **Shared IPs are scanned once per target.** Targets resolving to the same address each trigger
  their own TLS/HTTP/Nmap work within one job; there is no per-address de-duplication or cross-job
  rate budget.
- **Asset rejection after claim is not applied to a running job.** Asset approval is re-checked at
  claim time only; a target whose asset is rejected while the job runs is still checked. Domain
  authorisation, the kill switch and network approvals are re-checked at every heartbeat.
- **Checks already started finish their current step.** A stop or network shrink is applied between
  steps (before each check, between HTTP hops, before the second TLS handshake) and kills a running
  Nmap; a single in-progress TCP/TLS exchange is not aborted mid-way.
- **The worker switch needs a restart.** `EXDV_ACTIVE_SCANNING_ENABLED` is read at start-up.
- **RDAP redirect checks are a pre-check.** The registry redirect target is resolved and validated, but
  httpx resolves it again when connecting (no pinning); the systemd filter backs this up.
- **The worker's public-suffix list is compact** (about 150 entries). The server enforces the full PSL
  when a domain is added; the worker list is only a backstop against a bad snapshot.
- **Worker scope decisions stay local.** `scope_decision` events go to the home host's journal; only
  target `errorCode`s and observation evidence (hop decisions) reach the application.
- The worker's minimum approved prefix (/8, /20) is looser than the server's (/16, /32); the server is
  authoritative.
