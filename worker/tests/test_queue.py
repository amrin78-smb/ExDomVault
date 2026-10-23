"""End-to-end tests of the worker loop against a mocked internal worker API (no network)."""

import base64
import copy
import hashlib
import ipaddress
import json
import re
import threading

import dns.resolver
import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import net, port_checks
from app.client import Signer, WorkerApiClient
from app.config import load_config
from app.dns_checks import DnsAnswer
from app.health import HealthReporter
from app.queue import Worker
from app.rdap_checks import BOOTSTRAP_URL, RdapClient
from app.scope import ScopeError
from app.self_protection import SelfProtection

from .conftest import KEY_ID
from .test_port_checks import host, nmap_xml, port
from .test_rdap_checks import AVAILABLE, BOOTSTRAP
from .test_tls_checks import (
    FakePolicy,
    assert_http_schema,
    assert_port_schema,
    assert_tls_schema,
    make_cert,
    tls_result,
)

JOB_ID = "6f1f8f7e-1d1b-4d55-8a0e-0d3f6a1b2c3d"
APEX_ID = "11111111-1111-4111-8111-111111111111"
WWW_ID = "22222222-2222-4222-8222-222222222222"
GONE_ID = "33333333-3333-4333-8333-333333333333"
#: Synthetic "public egress address" reported by the fake self-protection detector.
EGRESS_V4 = ipaddress.IPv4Address("198.51.100.77")
ISO_Z = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$")

PASSIVE_CONFIG = {
    "active": False,
    "checks": ["dns", "rdap"],
    "tcpPorts": [],
    "timeouts": {"connectMs": 3000, "readMs": 5000, "targetSeconds": 60},
    "concurrency": 4,
    "ratePerSecond": 50,
    "maxTargets": 50,
}


def make_job(config=None, targets=None, profile="passive", domain="example.com"):
    targets = targets or [
        {"id": APEX_ID, "hostname": "example.com", "ip": None},
        {"id": WWW_ID, "hostname": "www.example.com", "ip": None},
        {"id": GONE_ID, "hostname": "gone.example.com", "ip": None},
    ]
    return {
        "id": JOB_ID,
        "attempt": 2,
        "profile": profile,
        "leaseExpiresAt": "2026-10-22T10:05:00.000Z",
        "leaseSeconds": 300,
        "heartbeatSeconds": 60,
        "snapshot": {
            "version": 1,
            "createdAt": "2026-10-22T10:00:00.000Z",
            "requestedBy": None,
            "trigger": "manual",
            "domain": {
                "id": "44444444-4444-4444-8444-444444444444",
                "fqdn": domain,
                "verificationStatus": "unverified",
                "verificationMethod": None,
                "verificationExpiresAt": None,
            },
            "profile": {
                "key": profile,
                "version": 1,
                "config": copy.deepcopy(config or PASSIVE_CONFIG),
            },
            "targets": [{"assetId": None, "hostname": t["hostname"]} for t in targets],
        },
        "targets": targets,
    }


class FakeApi:
    """Mimics the internal worker API: verifies signatures and nonces, records calls."""

    def __init__(self, key: Ed25519PrivateKey, job=None):
        self.public_key = key.public_key()
        self.job = job
        self.calls: list[tuple[str, dict]] = []
        self.nonces: set[str] = set()
        self.heartbeat_responses: list = []
        self.results_responses: list = []
        self.lock = threading.Lock()

    def endpoint_calls(self, name):
        return [body for endpoint, body in self.calls if endpoint == name]

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        message = "\n".join(
            [
                "EDV1",
                "POST",
                path,
                request.headers["X-EDV-Timestamp"],
                request.headers["X-EDV-Nonce"],
                hashlib.sha256(request.content).hexdigest(),
            ]
        )
        self.public_key.verify(
            base64.b64decode(request.headers["X-EDV-Signature"]), message.encode()
        )
        assert request.headers["X-EDV-Key-Id"] == KEY_ID
        with self.lock:
            nonce = request.headers["X-EDV-Nonce"]
            assert nonce not in self.nonces, "nonce reused"
            self.nonces.add(nonce)
            endpoint = path.rsplit("/", 1)[-1]
            body = json.loads(request.content)
            self.calls.append((endpoint, body))
            if endpoint == "claim":
                job, self.job = self.job, None
                return httpx.Response(200, json={"job": job})
            if endpoint == "heartbeat":
                if self.heartbeat_responses:
                    r = self.heartbeat_responses.pop(0)
                    if isinstance(r, httpx.Response):
                        return r
                    return httpx.Response(200, json=r)
                return httpx.Response(
                    200,
                    json={"leaseExpiresAt": "2026-10-22T10:10:00.000Z", "cancelRequested": False},
                )
            if endpoint == "results":
                if self.results_responses:
                    return self.results_responses.pop(0)
                return httpx.Response(200, json={"accepted": True, "status": "running"})
            if endpoint == "failures":
                return httpx.Response(200, json={"status": "failed", "retryAt": None})
        return httpx.Response(404)


class FakeResolver:
    def __init__(self, on_query=None):
        self.queries = []
        self.on_query = on_query
        self.lock = threading.Lock()

    def query(self, name, rdtype, lifetime):
        with self.lock:
            self.queries.append((name, rdtype))
        if self.on_query:
            self.on_query(name, rdtype)
        if name == "gone.example.com":
            raise dns.resolver.NXDOMAIN
        if rdtype == "A":
            return DnsAnswer(300, ["192.0.2.10"], name)
        if rdtype == "MX" and name == "example.com":
            return DnsAnswer(3600, ["10 mx.example.com."], name)
        if rdtype == "TXT" and name == "_dmarc.example.com":
            return DnsAnswer(3600, ['"v=DMARC1; p=reject"'], name)
        return DnsAnswer(None, [], name)


@pytest.fixture
def setup(valid_env, tmp_path):
    def build(
        job, *, resolver=None, heartbeat_interval=None, rdap_routes=None, env=None,
        policy_factory=None, self_protection=None,
    ):  # fmt: skip
        key = Ed25519PrivateKey.generate()
        api = FakeApi(key, job)
        client = WorkerApiClient(
            "https://exdomainvault.example.com",
            Signer(key, KEY_ID),
            transport=httpx.MockTransport(api),
            sleep=lambda _s: None,
        )
        rdap_seen: list[str] = []
        routes = rdap_routes or {
            BOOTSTRAP_URL: httpx.Response(200, json=BOOTSTRAP),
            "https://rdap.registry.test/com/v1/domain/example.com": httpx.Response(
                200, json=AVAILABLE
            ),
        }

        def rdap_handler(request):
            rdap_seen.append(str(request.url))
            return routes.get(str(request.url), httpx.Response(404))

        resolver = resolver or FakeResolver()
        extra = {} if policy_factory is None else {"policy_factory": policy_factory}
        config = load_config({**valid_env, **(env or {})})
        # Never detect the real host's addresses or query a real resolver in tests.
        protection = self_protection or SelfProtection(
            configured_deny=config.deny_networks,
            local_reader=lambda: [],
            egress_detector=lambda: [EGRESS_V4],
        )
        worker = Worker(
            config,
            client,
            resolver_factory=lambda _timeout: resolver,
            rdap_client=RdapClient(transport=httpx.MockTransport(rdap_handler)),
            health=HealthReporter(str(tmp_path / "health.json"), "home-worker-01"),
            heartbeat_interval=heartbeat_interval,
            sleep=lambda _s: None,
            self_protection=protection,
            **extra,
        )
        return worker, api, resolver, rdap_seen

    return build


def assert_observation_shape(o):
    common = {"kind", "targetId", "observedAt", "checkerVersion", "resultStatus", "evidence"}
    if o["kind"] == "dns":
        assert set(o) == common | {"hostname", "recordType", "ttl", "values"}
        assert re.fullmatch(r"[a-z0-9_.-]+", o["hostname"])
        assert not o["hostname"].endswith(".")
        assert o["values"] == sorted(o["values"])
    else:
        assert o["kind"] == "registration"
        assert set(o) == common | {
            "registrar", "registeredAt", "expiresAt", "nameservers", "dataStatus",
        }  # fmt: skip
    assert ISO_Z.match(o["observedAt"])
    assert re.fullmatch(r"[0-9A-Za-z.+-]{1,40}", o["checkerVersion"])
    assert o["resultStatus"] in {"success", "partial", "error", "timeout", "skipped"}
    assert len(json.dumps(o["evidence"])) <= 16384


def test_passive_job_end_to_end(setup):
    worker, api, resolver, rdap_seen = setup(make_job())
    assert worker.run_once() == "job"

    endpoints = [e for e, _ in api.calls]
    assert endpoints[0] == "claim"
    assert endpoints[1] == "heartbeat"
    assert endpoints[-1] == "results"
    assert "failures" not in endpoints
    assert api.endpoint_calls("claim")[0] == {"profiles": ["passive", "discovery"]}
    hb = api.endpoint_calls("heartbeat")[0]
    assert hb == {
        "jobId": JOB_ID,
        "attempt": 2,
        "progress": {"completedTargets": 0, "totalTargets": 3},
    }

    results = api.endpoint_calls("results")
    assert results[-1]["complete"] is True
    assert all(r["jobId"] == JOB_ID and r["attempt"] == 2 for r in results)
    assert all(re.fullmatch(r"[A-Za-z0-9_-]{8,128}", r["resultId"]) for r in results)
    targets = {t["targetId"]: t for r in results for t in r["targets"]}
    assert targets == {
        APEX_ID: {"targetId": APEX_ID, "status": "succeeded"},
        WWW_ID: {"targetId": WWW_ID, "status": "succeeded"},
        GONE_ID: {"targetId": GONE_ID, "status": "succeeded"},
    }
    observations = [o for r in results for o in r["observations"]]
    for o in observations:
        assert_observation_shape(o)

    apex_dns = {
        (o["hostname"], o["recordType"])
        for o in observations
        if o["targetId"] == APEX_ID and o["kind"] == "dns"
    }
    assert ("_dmarc.example.com", "TXT") in apex_dns
    assert len(apex_dns) == 11
    www = [o for o in observations if o["targetId"] == WWW_ID]
    assert {o["recordType"] for o in www} == {"A", "AAAA", "CNAME"}
    a = next(o for o in www if o["recordType"] == "A")
    assert a["values"] == ["192.0.2.10"]
    assert a["ttl"] == 300
    gone = [o for o in observations if o["targetId"] == GONE_ID]
    assert all(o["evidence"] == {"rcode": "NXDOMAIN"} and o["values"] == [] for o in gone)

    registrations = [o for o in observations if o["kind"] == "registration"]
    assert len(registrations) == 1
    assert registrations[0]["targetId"] == APEX_ID
    assert registrations[0]["nameservers"] == ["a.iana-servers.net", "b.iana-servers.net"]
    # RDAP contacted only IANA bootstrap and the registry, never a target host.
    assert rdap_seen == [BOOTSTRAP_URL, "https://rdap.registry.test/com/v1/domain/example.com"]
    # DNS queries only for names within the job's domain.
    assert all(n == "example.com" or n.endswith(".example.com") for n, _ in resolver.queries)

    health = json.loads((worker._health._path).read_text())
    assert health["lastJobId"] == JOB_ID
    assert health["status"] == "ok"


def test_idle_when_no_job(setup):
    worker, api, _, _ = setup(None)
    assert worker.run_once() == "idle"
    assert [e for e, _ in api.calls] == ["claim"]


def test_rdap_only_profile_skips_subdomains(setup):
    config = {**PASSIVE_CONFIG, "checks": ["rdap"]}
    worker, api, resolver, _ = setup(make_job(config))
    worker.run_once()
    assert resolver.queries == []
    targets = {
        t["targetId"]: t["status"] for r in api.endpoint_calls("results") for t in r["targets"]
    }
    assert targets == {APEX_ID: "succeeded", WWW_ID: "skipped", GONE_ID: "skipped"}


@pytest.mark.parametrize(
    "config",
    [
        {**PASSIVE_CONFIG, "active": True, "checks": ["dns", "rdap", "tls_certificate"]},
        {**PASSIVE_CONFIG, "active": True},
        {**PASSIVE_CONFIG, "checks": ["dns", "tcp_ports"]},
    ],
)
def test_active_profile_is_refused_without_running_checks(setup, config):
    worker, api, resolver, rdap_seen = setup(make_job(config, profile="passive"))
    worker.run_once()
    assert [e for e, _ in api.calls] == ["claim", "failures"]
    failure = api.endpoint_calls("failures")[0]
    assert failure["errorCode"] == "active_scanning_disabled"
    assert failure["retryable"] is False
    assert failure["jobId"] == JOB_ID and failure["attempt"] == 2
    assert resolver.queries == []
    assert rdap_seen == []


def test_target_outside_domain_is_refused(setup):
    targets = [
        {"id": APEX_ID, "hostname": "example.com", "ip": None},
        {"id": WWW_ID, "hostname": "www.evil-example.com", "ip": None},
    ]
    worker, api, resolver, _ = setup(make_job(targets=targets))
    worker.run_once()
    failure = api.endpoint_calls("failures")[0]
    assert failure["errorCode"] == "scope_rejected"
    assert failure["retryable"] is False
    assert resolver.queries == []


def test_malformed_job_is_refused(setup):
    job = make_job()
    del job["snapshot"]["profile"]["config"]["timeouts"]
    worker, api, _, _ = setup(job)
    worker.run_once()
    failure = api.endpoint_calls("failures")[0]
    assert failure["errorCode"] == "invalid_job"
    assert failure["retryable"] is False


def test_cancellation_on_first_heartbeat(setup):
    worker, api, resolver, _ = setup(make_job())
    api.heartbeat_responses.append(
        {"leaseExpiresAt": "2026-10-22T10:10:00.000Z", "cancelRequested": True}
    )
    worker.run_once()
    assert [e for e, _ in api.calls] == ["claim", "heartbeat", "failures"]
    failure = api.endpoint_calls("failures")[0]
    assert failure["errorCode"] == "cancelled"
    assert failure["retryable"] is False
    assert resolver.queries == []


def test_cancellation_via_periodic_heartbeat_mid_job(setup):
    started = threading.Event()
    release = threading.Event()

    def on_query(name, rdtype):
        started.set()
        release.wait(5)

    resolver = FakeResolver(on_query=on_query)
    worker, api, _, _ = setup(make_job(), resolver=resolver, heartbeat_interval=0.05)
    api.heartbeat_responses.extend(
        [
            {"leaseExpiresAt": "2026-10-22T10:10:00.000Z", "cancelRequested": False},
            {"leaseExpiresAt": "2026-10-22T10:10:00.000Z", "cancelRequested": True},
        ]
    )

    def release_after_cancel():
        started.wait(5)
        while len(api.endpoint_calls("heartbeat")) < 2:
            threading.Event().wait(0.01)
        release.set()

    helper = threading.Thread(target=release_after_cancel)
    helper.start()
    worker.run_once()
    helper.join(5)
    endpoints = [e for e, _ in api.calls]
    assert endpoints[-1] == "failures"
    assert api.endpoint_calls("failures")[0]["errorCode"] == "cancelled"
    assert not any(r["complete"] for r in api.endpoint_calls("results"))


def test_lease_lost_stops_without_reporting(setup):
    worker, api, resolver, _ = setup(make_job())
    api.heartbeat_responses.append(httpx.Response(409, json={"error": {"code": "conflict"}}))
    worker.run_once()
    assert [e for e, _ in api.calls] == ["claim", "heartbeat"]
    assert resolver.queries == []


def test_lease_lost_on_results_stops_without_failure_report(setup):
    worker, api, _, _ = setup(make_job())
    api.results_responses.append(httpx.Response(409, json={"error": {"code": "conflict"}}))
    worker.run_once()
    endpoints = [e for e, _ in api.calls]
    assert endpoints.count("results") == 1
    assert "failures" not in endpoints


def test_results_retry_reuses_result_id(setup):
    worker, api, _, _ = setup(make_job())
    api.results_responses.append(httpx.Response(503))
    worker.run_once()
    results = api.endpoint_calls("results")
    assert len(results) == 2
    assert results[0] == results[1]
    assert results[0]["complete"] is True


def test_shutdown_reports_worker_shutdown(setup):
    worker, api, _, _ = setup(make_job())

    def on_query(name, rdtype):
        worker.shutdown.set()  # simulates SIGTERM arriving mid-job

    worker._resolver_factory = lambda _t: FakeResolver(on_query=on_query)
    assert worker.run_once() == "job"
    endpoints = [e for e, _ in api.calls]
    assert endpoints[-1] == "failures"
    failure = api.endpoint_calls("failures")[0]
    assert failure["errorCode"] == "worker_shutdown"
    assert failure["retryable"] is True
    assert not any(r["complete"] for r in api.endpoint_calls("results"))
    # After shutdown no further claims.
    assert worker.run_once() == "idle"
    assert [e for e, _ in api.calls].count("claim") == 1


def test_run_forever_exits_cleanly_on_shutdown(setup):
    worker, api, _, _ = setup(None)
    worker.shutdown.set()
    assert worker.run_forever() == 0
    assert api.calls == []


def test_unexpected_error_reports_retryable_worker_error(setup):
    worker, api, _, _ = setup(make_job())

    def broken(*_a, **_k):
        raise RuntimeError("bug with /home/secret path")

    worker._run_targets = broken
    worker.run_once()
    failure = api.endpoint_calls("failures")[0]
    assert failure["errorCode"] == "worker_error"
    assert failure["retryable"] is True
    assert "secret" not in failure["errorSummary"]
    assert "Traceback" not in failure["errorSummary"]


def test_target_timeout_marks_target_failed(setup):
    clock = {"now": 0.0}

    def on_query(name, rdtype):
        clock["now"] += 30.0

    worker, api, _, _ = setup(make_job(), resolver=FakeResolver(on_query=on_query))
    worker._monotonic = lambda: clock["now"]
    worker.run_once()
    targets = {t["targetId"]: t for r in api.endpoint_calls("results") for t in r["targets"]}
    assert targets[APEX_ID]["status"] == "failed"
    assert targets[APEX_ID]["errorCode"] == "target_timeout"
    assert api.endpoint_calls("results")[-1]["complete"] is True


def test_all_queries_failing_marks_target_failed(setup):
    class DeadResolver:
        def query(self, name, rdtype, lifetime):
            raise dns.resolver.NoNameservers

    config = {**PASSIVE_CONFIG, "checks": ["dns"]}
    worker, api, _, _ = setup(make_job(config), resolver=DeadResolver())
    worker.run_once()
    targets = {t["targetId"]: t for r in api.endpoint_calls("results") for t in r["targets"]}
    assert all(
        t["status"] == "failed" and t["errorCode"] == "checks_failed" for t in targets.values()
    )


def test_auth_error_on_claim(setup):
    worker, _api, _, _ = setup(None)
    worker._api._http._transport = httpx.MockTransport(lambda r: httpx.Response(401))
    assert worker.run_once() == "auth_error"
    assert worker._health.last_error == "auth_failed"


# -- Milestone 6: active checks (all network primitives faked) ---------------------------------

QUICK_CONFIG = {
    **PASSIVE_CONFIG,
    "active": True,
    "checks": ["dns", "rdap", "tls_certificate", "http_availability"],
}
STANDARD_CONFIG = {
    **PASSIVE_CONFIG,
    "active": True,
    "checks": [
        "dns", "rdap", "tls_certificate", "http_availability", "http_headers", "tcp_ports",
        "service_identification",
    ],
    "tcpPorts": [22, 80, 443],
    "concurrency": 2,
}  # fmt: skip
WEB_ADDRESSES = {"example.com": ["203.0.113.10"], "www.example.com": ["203.0.113.20"]}


@pytest.fixture
def active(setup, valid_env, tmp_path, monkeypatch):
    """Worker with active scanning enabled, a fake policy and fake net/Nmap primitives."""
    nmap = tmp_path / "nmap"
    nmap.write_text("#!/bin/sh\nexit 1\n")  # never executed: run_nmap is faked
    nmap.chmod(0o755)
    calls = {"tls": [], "http": [], "nmap": [], "factory": []}
    der = make_cert(sans=("example.com", "*.example.com"))

    def fake_tls(policy, hostname, address, port, *, timeout, tier="web", **_kw):
        calls["tls"].append((hostname, str(address), port))
        return tls_result(der, address=str(address))

    def fake_http(policy, url, resolver, *, timeout, tier="web", **_kw):
        # Mirrors net.http_get: resolution goes through the policy; a refusal becomes a hop.
        calls["http"].append(url)
        try:
            resolved = policy.resolve(url.split("/")[2], resolver, tier=tier, lifetime=timeout)
        except ScopeError as exc:
            return net.HttpResult(hops=(net.HttpHop(url, None, None, decision=exc.code),))
        headers = {"strict-transport-security": "max-age=600", "set-cookie": "sid=SECRET"}
        return net.HttpResult(hops=(net.HttpHop(url, resolved.addresses[0], 200, headers),))

    def fake_nmap(argv, *, timeout, should_stop=lambda: False, **_kw):
        calls["nmap"].append(argv)
        return nmap_xml(
            host(argv[-1], port(22, "open", service='<service name="ssh" method="probed"/>')
                 + port(80, "closed") + port(443, "filtered"))
        )  # fmt: skip

    monkeypatch.setattr(net, "tls_handshake", fake_tls)
    monkeypatch.setattr(net, "http_get", fake_http)
    monkeypatch.setattr(port_checks, "run_nmap", fake_nmap)

    def build(job, *, policy=None, env=None, factory_error=None, self_protection=None):
        policy = policy or FakePolicy({"web": WEB_ADDRESSES})

        def factory(**kwargs):
            calls["factory"].append(kwargs)
            if factory_error:
                raise ScopeError(factory_error, "refused")
            return policy

        worker, api, _resolver, _ = setup(
            job,
            env={
                "EXDV_ACTIVE_SCANNING_ENABLED": "true",
                "EXDV_PROFILES": "passive,quick,standard,deep",
                "EXDV_NMAP_PATH": str(nmap),
                **(env or {}),
            },
            policy_factory=factory,
            self_protection=self_protection,
        )
        worker.run_once()
        results = api.endpoint_calls("results")
        targets = {t["targetId"]: t for r in results for t in r["targets"]}
        observations = [o for r in results for o in r["observations"]]
        return api, targets, observations, policy

    return build, calls


def test_quick_job_runs_web_checks(active):
    build, calls = active
    api, targets, observations, policy = build(make_job(QUICK_CONFIG, profile="quick"))
    assert "failures" not in [e for e, _ in api.calls]
    assert api.endpoint_calls("results")[-1]["complete"] is True
    assert targets[APEX_ID] == {"targetId": APEX_ID, "status": "succeeded"}
    assert targets[WWW_ID] == {"targetId": WWW_ID, "status": "succeeded"}
    # gone.example.com: DNS evidence (NXDOMAIN) but every connecting check refused.
    assert targets[GONE_ID] == {
        "targetId": GONE_ID, "status": "succeeded", "errorCode": "no_allowed_address",
    }  # fmt: skip

    (factory_kwargs,) = calls["factory"]
    assert factory_kwargs["job_id"] == JOB_ID
    assert factory_kwargs["deny_networks"] == (f"{EGRESS_V4}/32",)
    assert factory_kwargs["active_scanning_enabled"] is True
    assert factory_kwargs["target_hostnames"] == [
        "example.com", "www.example.com", "gone.example.com",
    ]  # fmt: skip
    assert factory_kwargs["snapshot"]["domain"]["fqdn"] == "example.com"

    tls = [o for o in observations if o["kind"] == "tls"]
    http = [o for o in observations if o["kind"] == "http"]
    for o in tls:
        assert_tls_schema(o)
    for o in http:
        assert_http_schema(o)
        assert set(o["evidence"]) == {"hops"}  # http_headers not in the quick profile
    assert {(o["hostname"], o["ipAddress"], o["hostnameMatches"]) for o in tls} == {
        ("example.com", "203.0.113.10", True),
        ("www.example.com", "203.0.113.20", True),
    }
    # Both schemes are requested per target, as a visitor would; gone.example.com is refused before
    # connecting, so its plain-HTTP request is not made either.
    assert sorted(calls["http"]) == [
        "http://example.com/", "http://www.example.com/",
        "https://example.com/", "https://gone.example.com/", "https://www.example.com/",
    ]  # fmt: skip
    assert calls["nmap"] == []
    assert "SECRET" not in json.dumps(observations)
    assert not any(o["kind"] == "port" for o in observations)
    checked = [c[1] for c in policy.calls if c[0] == "assert_check_allowed"]
    assert set(checked) == {"dns", "rdap", "tls_certificate", "http_availability"}


def test_standard_job_runs_web_and_network_checks(active):
    build, calls = active
    policy = FakePolicy(
        {
            "web": WEB_ADDRESSES,
            "network": {
                "www.example.com": ["198.51.100.7"],
                "example.com": "network_not_approved",
            },
        }
    )
    _api, targets, observations, _ = build(
        make_job(STANDARD_CONFIG, profile="standard"), policy=policy
    )
    assert targets[WWW_ID] == {"targetId": WWW_ID, "status": "succeeded"}
    assert targets[APEX_ID] == {
        "targetId": APEX_ID, "status": "succeeded", "errorCode": "network_not_approved",
    }  # fmt: skip
    (argv,) = calls["nmap"]
    assert argv[:5] == [argv[0], "-sT", "-Pn", "-n", "--unprivileged"]
    assert argv[argv.index("-p") + 1] == "22,80,443"
    assert "-sV" in argv and argv[-1] == "198.51.100.7"
    ports = [o for o in observations if o["kind"] == "port"]
    for o in ports:
        assert_port_schema(o)
    assert [(o["targetId"], o["port"], o["state"], o["service"]) for o in ports] == [
        (WWW_ID, 22, "open", "ssh"), (WWW_ID, 80, "closed", None), (WWW_ID, 443, "filtered", None),
    ]  # fmt: skip
    http = [o for o in observations if o["kind"] == "http"]
    assert all("securityHeaders" in o["evidence"] for o in http)
    assert all(o["hstsEnabled"] is True for o in http if o["url"].startswith("https://"))
    assert ("assert_destination", "198.51.100.7", "network") in policy.calls


def test_only_refused_checks_fail_the_target_with_the_refusal_code(active):
    build, calls = active
    config = {**QUICK_CONFIG, "checks": ["tls_certificate"]}
    targets_in = [{"id": WWW_ID, "hostname": "www.example.com", "ip": None}]
    policy = FakePolicy({"web": {"www.example.com": "cname_out_of_scope"}})
    _api, targets, observations, _ = build(
        make_job(config, targets=targets_in, profile="quick"), policy=policy
    )
    assert targets == {
        WWW_ID: {"targetId": WWW_ID, "status": "failed", "errorCode": "cname_out_of_scope"}
    }
    assert observations == []
    assert calls["tls"] == []


def test_check_refused_by_policy_is_recorded(active):
    build, calls = active
    policy = FakePolicy({"web": WEB_ADDRESSES}, denied_checks=("tls_certificate",))
    _api, targets, observations, _ = build(make_job(QUICK_CONFIG, profile="quick"), policy=policy)
    assert calls["tls"] == []
    assert targets[WWW_ID]["errorCode"] == "check_not_allowed"
    assert targets[WWW_ID]["status"] == "succeeded"  # DNS + HTTP evidence still collected
    assert not any(o["kind"] == "tls" for o in observations)


def test_missing_nmap_fails_network_checks_only(active):
    build, calls = active
    policy = FakePolicy({"web": WEB_ADDRESSES, "network": {"www.example.com": ["198.51.100.7"]}})
    _api, targets, observations, _ = build(
        make_job(STANDARD_CONFIG, profile="standard"),
        policy=policy,
        env={"EXDV_NMAP_PATH": "/nonexistent/nmap"},
    )
    assert calls["nmap"] == []
    assert targets[WWW_ID] == {
        "targetId": WWW_ID, "status": "succeeded", "errorCode": "nmap_unavailable",
    }  # fmt: skip
    assert any(o["kind"] == "tls" for o in observations)


def test_policy_build_refusal_fails_the_job(active):
    build, calls = active
    api, targets, _, _ = build(
        make_job(QUICK_CONFIG, profile="quick"), factory_error="scope_rejected"
    )
    failure = api.endpoint_calls("failures")[0]
    assert failure["errorCode"] == "scope_rejected"
    assert failure["retryable"] is False
    assert targets == {}
    assert calls["tls"] == [] and calls["http"] == []


def test_tls_configuration_is_accepted_but_not_run(active):
    build, calls = active
    config = {**QUICK_CONFIG, "checks": ["dns", "tls_configuration"]}
    api, targets, observations, _ = build(make_job(config, profile="deep"))
    assert "failures" not in [e for e, _ in api.calls]
    assert all(t["status"] == "succeeded" and "errorCode" not in t for t in targets.values())
    assert {o["kind"] for o in observations} == {"dns"}
    assert calls["tls"] == [] and calls["nmap"] == []


def test_non_active_profile_with_connecting_checks_is_refused(active):
    build, calls = active
    config = {**PASSIVE_CONFIG, "checks": ["dns", "tls_certificate"]}
    api, _, _, _ = build(make_job(config))
    failure = api.endpoint_calls("failures")[0]
    assert failure["errorCode"] == "invalid_profile"
    assert calls["factory"] == []


def test_unknown_check_is_refused(active):
    build, calls = active
    config = {**QUICK_CONFIG, "checks": ["dns", "nmap_script"]}
    api, _, _, _ = build(make_job(config, profile="quick"))
    assert api.endpoint_calls("failures")[0]["errorCode"] == "unsupported_check"
    assert calls["factory"] == []


@pytest.mark.parametrize("ports", [[0], [True], ["22"], list(range(1, 1100))])
def test_malformed_tcp_ports_make_the_job_invalid(active, ports):
    build, _ = active
    api, _, _, _ = build(make_job({**STANDARD_CONFIG, "tcpPorts": ports}, profile="standard"))
    assert api.endpoint_calls("failures")[0]["errorCode"] == "invalid_job"


def test_active_profile_refused_when_worker_disables_active_scanning(active):
    build, calls = active
    api, _, _, _ = build(
        make_job(QUICK_CONFIG, profile="quick"), env={"EXDV_ACTIVE_SCANNING_ENABLED": "false"}
    )
    assert [e for e, _ in api.calls] == ["claim", "failures"]
    failure = api.endpoint_calls("failures")[0]
    assert failure["errorCode"] == "active_scanning_disabled"
    assert failure["retryable"] is False
    assert calls["factory"] == [] and calls["tls"] == []


# -- home-network self-protection and heartbeat scope shrink ------------------------------------


def test_unknown_egress_address_fails_connecting_checks_closed(active):
    build, calls = active
    protection = SelfProtection(local_reader=lambda: [], egress_detector=lambda: [])
    api, targets, observations, _ = build(
        make_job(STANDARD_CONFIG, profile="standard"), self_protection=protection
    )
    assert calls["tls"] == [] and calls["http"] == [] and calls["nmap"] == []
    assert {o["kind"] for o in observations} <= {"dns", "registration"}
    assert targets[WWW_ID]["errorCode"] == "egress_ip_unknown"
    assert api.endpoint_calls("results")[-1]["complete"] is True


def test_unknown_egress_address_is_tolerated_with_an_explicit_deny_list(active):
    build, calls = active
    protection = SelfProtection(
        configured_deny=("198.51.100.0/24",), local_reader=lambda: [], egress_detector=lambda: []
    )
    build(make_job(QUICK_CONFIG, profile="quick"), self_protection=protection,
          env={"EXDV_DENY_NETWORKS": "198.51.100.0/24"})  # fmt: skip
    assert calls["tls"] and calls["http"]
    (kwargs,) = calls["factory"]
    assert kwargs["deny_networks"] == ("198.51.100.0/24",)


def test_local_and_egress_networks_join_the_deny_list(active):
    build, calls = active
    protection = SelfProtection(
        configured_deny=("192.0.2.0/24",),
        local_reader=lambda: [
            ipaddress.ip_network("10.0.3.1/32"), ipaddress.ip_network("2001:470:1:2::/64"),
        ],
        egress_detector=lambda: [EGRESS_V4, ipaddress.ip_address("2001:470:1:2::99")],
    )  # fmt: skip
    build(make_job(QUICK_CONFIG, profile="quick"), self_protection=protection)
    (kwargs,) = calls["factory"]
    assert kwargs["deny_networks"] == (
        "192.0.2.0/24", "10.0.3.1/32", "2001:470:1:2::/64", f"{EGRESS_V4}/32",
    )  # fmt: skip


def test_self_protection_is_not_consulted_while_active_scanning_is_disabled(setup):
    def boom():
        raise AssertionError("must not detect addresses when active scanning is off")

    protection = SelfProtection(local_reader=boom, egress_detector=boom)
    worker, api, _, _ = setup(make_job(), self_protection=protection)
    worker.shutdown.set()
    worker.run_forever()
    worker.shutdown.clear()
    worker.run_once()
    assert "failures" not in [e for e, _ in api.calls]


def test_heartbeat_approved_networks_shrink_the_running_policy(setup, monkeypatch, tmp_path):
    from app.policy import ScopePolicy

    nmap = tmp_path / "nmap"
    nmap.write_text("#!/bin/sh\nexit 1\n")
    nmap.chmod(0o755)
    runs = []
    monkeypatch.setattr(port_checks, "run_nmap", lambda argv, **_kw: runs.append(argv) or b"")
    config = {**STANDARD_CONFIG, "checks": ["dns", "tcp_ports"], "tcpPorts": [22]}
    job = make_job(config, profile="standard")
    job["snapshot"]["approvedNetworks"] = ["93.184.216.0/24"]
    built = []

    def factory(**kwargs):
        built.append(ScopePolicy.from_job(**kwargs))
        return built[-1]

    class Resolver(FakeResolver):
        def query(self, name, rdtype, lifetime):
            if rdtype == "A" and name == "www.example.com":
                return DnsAnswer(60, ["93.184.216.34"], name)
            return super().query(name, rdtype, lifetime)

    worker, api, _, _ = setup(
        job, resolver=Resolver(), policy_factory=factory,
        env={"EXDV_ACTIVE_SCANNING_ENABLED": "true", "EXDV_PROFILES": "standard",
             "EXDV_NMAP_PATH": str(nmap)},
    )  # fmt: skip
    # The first heartbeat (sent before any check) no longer lists the job's network; networks the
    # job never had must not be added.
    api.heartbeat_responses.append(
        {"leaseExpiresAt": "2026-10-22T10:10:00.000Z", "cancelRequested": False,
         "approvedNetworks": ["94.0.0.0/8", "198.51.100.0/24"]}
    )  # fmt: skip
    worker.run_once()
    assert built[0].approved_networks == (ipaddress.ip_network("93.184.216.0/24"),)
    assert runs == [], "network check ran on a revoked network"
    targets = {t["targetId"]: t for r in api.endpoint_calls("results") for t in r["targets"]}
    assert targets[WWW_ID]["errorCode"] == "no_allowed_address"


def test_heartbeat_without_approved_networks_keeps_the_policy(setup):
    from app.policy import ScopePolicy
    from app.queue import PolicyHolder

    policy = ScopePolicy(
        job_id="j", domain="example.com",
        approved_networks=(ipaddress.ip_network("93.184.216.0/24"),),
    )  # fmt: skip
    holder = PolicyHolder(policy)
    holder.shrink_approved_networks(["93.184.216.128/25", "10.0.0.0/8", "bad", None])
    assert holder.current.approved_networks == (ipaddress.ip_network("93.184.216.128/25"),)
    holder.shrink_approved_networks("93.184.216.0/24")  # not a list: nothing approved
    assert holder.current.approved_networks == ()
