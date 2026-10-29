"""Lookalike-domain check (Milestone 15): mocked resolvers only, nothing leaves the process."""

import re
import socket
import ssl
import threading
from pathlib import Path

import dns.exception
import dns.resolver
import httpx
import pytest

from app.checks import CheckContext, CheckFailed, CheckStopped, RateLimiter, TargetTimeout
from app.dns_checks import DnsAnswer
from app.lookalike_checks import (
    LOOKALIKE_TECHNIQUES,
    MAX_CANDIDATES,
    Candidate,
    check_candidate,
    parse_candidates,
    run_lookalikes,
)

from .test_queue import APEX_ID, make_job, setup  # noqa: F401  (fixture)

TARGET = APEX_ID
REPO = Path(__file__).resolve().parents[2]

BRAND_CONFIG = {
    "active": False,
    "checks": ["lookalike"],
    "tcpPorts": [],
    "timeouts": {"connectMs": 5000, "readMs": 10000, "targetSeconds": 1800},
    "concurrency": 8,
    "ratePerSecond": 10,
    "maxTargets": 1,
}


class Clock:
    def __init__(self):
        self.now = 1000.0
        self.lock = threading.Lock()

    def monotonic(self):
        with self.lock:
            return self.now

    def sleep(self, seconds):
        with self.lock:
            self.now += seconds


class ZoneResolver:
    """Synthetic DNS: ``zones`` = name → {rdtype: [values]}; names absent → NXDOMAIN;
    ``failures`` = (name, rdtype) → exception class."""

    def __init__(self, zones=None, failures=None, clock=None, cost=0.0):
        self.zones = zones or {}
        self.failures = failures or {}
        self.queries = []
        self.lock = threading.Lock()
        self.clock = clock
        self.cost = cost

    def query(self, name, rdtype, lifetime):
        assert lifetime > 0
        with self.lock:
            self.queries.append((name, rdtype))
        if self.clock is not None:
            self.clock.sleep(self.cost)
        failure = self.failures.get((name, rdtype))
        if failure is not None:
            raise failure()
        if name not in self.zones:
            raise dns.resolver.NXDOMAIN
        return DnsAnswer(300, list(self.zones[name].get(rdtype, [])), name)


def ctx(clock=None, seconds=1800.0, rate=1000.0, should_stop=lambda: False):
    clock = clock or Clock()
    return CheckContext(
        deadline=clock.monotonic() + seconds,
        connect_seconds=5,
        read_seconds=10,
        rate_limiter=RateLimiter(rate, monotonic=clock.monotonic, sleep=clock.sleep),
        should_stop=should_stop,
        monotonic=clock.monotonic,
    )


REGISTERED = {
    "exmple.com": {
        "NS": ["NS1.Parking.Example.NET.", "ns2.parking.example.net."],
        "A": ["192.0.2.7"],
        "MX": ["10 MX.Example.ORG."],
    },
    "exampel.com": {"NS": ["ns.example.net."]},
    "example.co": {"NS": [], "SOA": ["ns. host. 1 2 3 4 5"]},  # zone apex without NS answer
    "exampe.com": {"NS": []},  # exists, not a zone apex (e.g. a TLD wildcard): not registered
    "exam.ple.com": {"A": ["198.51.100.1"]},
}


# --- check_candidate ----------------------------------------------------------------------------


def test_registered_candidate_with_records():
    resolver = ZoneResolver(REGISTERED)
    o = check_candidate(resolver, TARGET, Candidate("exmple.com", "omission"), ctx())
    assert o["kind"] == "lookalike"
    assert o["resultStatus"] == "success"
    assert o["registered"] is True
    assert o["candidate"] == "exmple.com" and o["technique"] == "omission"
    assert o["records"] == {
        "NS": ["ns1.parking.example.net.", "ns2.parking.example.net."],
        "A": ["192.0.2.7"],
        "MX": ["10 mx.example.org."],
    }
    assert o["evidence"] == {"queries": 4}
    assert resolver.queries == [
        ("exmple.com", "NS"),
        ("exmple.com", "A"),
        ("exmple.com", "AAAA"),
        ("exmple.com", "MX"),
    ]


def test_nxdomain_is_not_registered_after_one_query():
    resolver = ZoneResolver(REGISTERED)
    assert check_candidate(resolver, TARGET, Candidate("unused.com", "omission"), ctx()) is None
    assert resolver.queries == [("unused.com", "NS")]


def test_soa_fallback_and_non_apex_names():
    resolver = ZoneResolver(REGISTERED)
    o = check_candidate(resolver, TARGET, Candidate("example.co", "tld_swap"), ctx())
    assert o["registered"] is True and o["evidence"]["soa"] is True
    assert o["records"] == {"NS": []}
    assert check_candidate(resolver, TARGET, Candidate("exampe.com", "omission"), ctx()) is None


@pytest.mark.parametrize(
    ("exc", "status"),
    [
        (dns.resolver.NoNameservers, "error"),  # SERVFAIL from every resolver
        (dns.exception.Timeout, "timeout"),
    ],
)
def test_resolver_failure_is_never_unregistered(exc, status):
    resolver = ZoneResolver(REGISTERED, failures={("exmple.com", "NS"): exc})
    o = check_candidate(resolver, TARGET, Candidate("exmple.com", "omission"), ctx())
    assert o["resultStatus"] == status
    assert o["registered"] is False
    assert o["records"] == {}
    assert o["evidence"] == {"query": "NS", "error": exc.__name__}


def test_record_lookup_failure_makes_partial():
    resolver = ZoneResolver(REGISTERED, failures={("exmple.com", "MX"): dns.resolver.NoNameservers})
    o = check_candidate(resolver, TARGET, Candidate("exmple.com", "omission"), ctx())
    assert o["resultStatus"] == "partial"
    assert o["registered"] is True
    assert "MX" not in o["records"]
    assert o["evidence"]["errors"] == {"MX": "NoNameservers"}


def test_subdomain_dot_uses_address_records_not_ns():
    resolver = ZoneResolver(REGISTERED)
    o = check_candidate(resolver, TARGET, Candidate("exam.ple.com", "subdomain_dot"), ctx())
    assert o["registered"] is True and o["records"] == {"A": ["198.51.100.1"]}
    assert ("exam.ple.com", "NS") not in resolver.queries
    resolver.queries.clear()
    assert (
        check_candidate(resolver, TARGET, Candidate("ex.ample.com", "subdomain_dot"), ctx()) is None
    )
    assert resolver.queries == [("ex.ample.com", "A")]  # NXDOMAIN stops early


def test_records_are_capped():
    zones = {"exmple.com": {"NS": ["ns.example.net."], "A": [f"192.0.2.{i}" for i in range(40)]}}
    o = check_candidate(ZoneResolver(zones), TARGET, Candidate("exmple.com", "omission"), ctx())
    assert len(o["records"]["A"]) == 20


# --- run_lookalikes -----------------------------------------------------------------------------

CANDIDATES = [
    Candidate("exmple.com", "omission"),
    Candidate("exampel.com", "transposition"),
    Candidate("unused.com", "omission"),
    Candidate("example.co", "tld_swap"),
    Candidate("exam.ple.com", "subdomain_dot"),
    Candidate("broken.com", "omission"),
]


def test_run_emits_only_registered_and_failed_candidates():
    resolver = ZoneResolver(REGISTERED, failures={("broken.com", "NS"): dns.resolver.NoNameservers})
    out = []
    outcome = run_lookalikes(resolver, TARGET, CANDIDATES, ctx(), out.append, concurrency=8)
    assert outcome.checked == 6 and outcome.registered == 4 and outcome.failed == 1
    by_name = {o["candidate"]: o for o in out}
    assert set(by_name) == {"exmple.com", "exampel.com", "example.co", "exam.ple.com", "broken.com"}
    assert by_name["broken.com"]["resultStatus"] == "error"


def test_run_with_nothing_registered_is_complete_and_empty():
    out = []
    outcome = run_lookalikes(ZoneResolver({}), TARGET, CANDIDATES, ctx(), out.append)
    assert out == [] and outcome.checked == 6 and outcome.registered == 0


def test_every_candidate_failing_fails_the_check():
    failures = {(c.name, q): dns.resolver.NoNameservers for c in CANDIDATES for q in ("NS", "A")}
    with pytest.raises(CheckFailed) as err:
        run_lookalikes(ZoneResolver({}, failures), TARGET, CANDIDATES, ctx(), lambda _o: None)
    assert err.value.code == "lookalike_resolution_failed"


def test_rate_limit_spaces_queries():
    clock = Clock()
    resolver = ZoneResolver({}, clock=None)
    run_lookalikes(resolver, TARGET, CANDIDATES[:4], ctx(clock, rate=10), lambda _o: None)
    # 4 candidates, 1 NXDOMAIN query each, at most 10/s → at least 0.3 s of (fake) time.
    assert len(resolver.queries) == 4
    assert clock.now - 1000.0 == pytest.approx(0.3, abs=1e-6)


def test_time_budget_stops_the_run_and_keeps_evidence():
    clock = Clock()
    zones = {c.name: {"NS": ["ns.example.net."]} for c in CANDIDATES}
    resolver = ZoneResolver(zones, clock=clock, cost=1.0)  # each query takes 1 s
    out = []
    with pytest.raises(TargetTimeout):
        run_lookalikes(
            resolver, TARGET, CANDIDATES, ctx(clock, seconds=6), out.append, concurrency=1
        )
    assert 0 < len(out) < len(CANDIDATES)
    assert len(resolver.queries) <= 7


def test_stop_signal_aborts():
    stop = threading.Event()
    stop.set()
    with pytest.raises(CheckStopped):
        run_lookalikes(
            ZoneResolver({}), TARGET, CANDIDATES, ctx(should_stop=stop.is_set), lambda _o: None
        )


# --- parse_candidates ---------------------------------------------------------------------------


def test_parse_candidates_validates_the_server_list():
    snap = {"lookalike": {"candidates": [
        {"candidate": "exmple.com", "technique": "omission"},
        {"candidate": "exmple.com", "technique": "omission"},
        {"candidate": "thai.union.com", "technique": "subdomain_dot"},
    ]}}  # fmt: skip
    assert parse_candidates(snap, "example.com") == [
        Candidate("exmple.com", "omission"),
        Candidate("thai.union.com", "subdomain_dot"),
    ]


@pytest.mark.parametrize(
    "snapshot",
    [
        {},
        {"lookalike": {}},
        {"lookalike": {"candidates": "x"}},
        {"lookalike": {"candidates": [{"candidate": "Exmple.com", "technique": "omission"}]}},
        {"lookalike": {"candidates": [{"candidate": "exmple.com", "technique": "evil"}]}},
        {"lookalike": {"candidates": [{"candidate": "-x.com", "technique": "omission"}]}},
        {"lookalike": {"candidates": [{"candidate": "www.example.com", "technique": "omission"}]}},
        {"lookalike": {"candidates": [{"candidate": "example.com", "technique": "omission"}]}},
        {
            "lookalike": {
                "candidates": [{"candidate": "a.com", "technique": "omission"}]
                * (MAX_CANDIDATES + 1)
            }
        },
    ],
)
def test_parse_candidates_refuses_bad_lists(snapshot):
    with pytest.raises(CheckFailed) as err:
        parse_candidates(snapshot, "example.com")
    assert err.value.code == "lookalike_candidates_invalid"


def test_techniques_match_the_shared_contract():
    ts = (REPO / "packages/shared/src/api/observations.ts").read_text()
    block = re.search(r"LOOKALIKE_TECHNIQUES = \[(.*?)\] as const", ts, re.S)
    assert block is not None
    assert set(re.findall(r"'([a-z_]+)'", block.group(1))) == LOOKALIKE_TECHNIQUES
    cap = re.search(
        r"MAX_LOOKALIKE_CANDIDATES = (\d+)",
        (REPO / "packages/shared/src/domain/lookalike.ts").read_text(),
    )
    assert cap is not None and int(cap.group(1)) == MAX_CANDIDATES


# --- through the worker loop ----------------------------------------------------------------------


def brand_job(candidates):
    job = make_job(
        config=BRAND_CONFIG,
        targets=[{"id": APEX_ID, "hostname": "example.com", "ip": None}],
        profile="brand",
    )
    job["snapshot"]["lookalike"] = {
        "generatorVersion": 1,
        "candidates": [{"candidate": c.name, "technique": c.technique} for c in candidates],
    }
    return job


@pytest.fixture
def no_sockets(monkeypatch):
    """Anything other than the (mocked) resolver opening a connection fails the test."""

    def refuse(*_a, **_k):
        raise AssertionError("lookalike checks must never open a connection")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", refuse)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", refuse)


def test_brand_job_end_to_end_never_connects(setup, no_sockets):  # noqa: F811
    resolver = ZoneResolver(REGISTERED)
    worker, api, _, rdap_seen = setup(
        brand_job(CANDIDATES[:5]), resolver=resolver, env={"EXDV_PROFILES": "brand"}
    )
    assert worker.run_once() == "job"
    assert "failures" not in [e for e, _ in api.calls]
    assert rdap_seen == []
    results = api.endpoint_calls("results")
    targets = [t for r in results for t in r["targets"]]
    assert targets == [{"targetId": APEX_ID, "status": "succeeded"}]
    observations = [o for r in results for o in r["observations"]]
    assert {o["candidate"] for o in observations} == {
        "exmple.com", "exampel.com", "example.co", "exam.ple.com",
    }  # fmt: skip
    assert all(o["kind"] == "lookalike" and o["targetId"] == APEX_ID for o in observations)
    assert results[-1]["complete"] is True
    # Only the candidates were queried; never the job's own domain.
    assert {n for n, _ in resolver.queries} <= {c.name for c in CANDIDATES}


def test_brand_job_with_nothing_registered_succeeds(setup, no_sockets):  # noqa: F811
    worker, api, _, _ = setup(brand_job(CANDIDATES[:3]), resolver=ZoneResolver({}))
    worker.run_once()
    targets = [t for r in api.endpoint_calls("results") for t in r["targets"]]
    assert targets == [{"targetId": APEX_ID, "status": "succeeded"}]


def test_brand_job_without_candidates_fails_the_target(setup):  # noqa: F811
    job = brand_job([])
    del job["snapshot"]["lookalike"]
    worker, api, _, _ = setup(job, resolver=ZoneResolver({}))
    worker.run_once()
    targets = [t for r in api.endpoint_calls("results") for t in r["targets"]]
    assert targets == [
        {"targetId": APEX_ID, "status": "failed", "errorCode": "lookalike_candidates_invalid"}
    ]


def test_active_brand_profile_is_refused(setup):  # noqa: F811
    job = brand_job(CANDIDATES[:1])
    job["snapshot"]["profile"]["config"]["active"] = True
    worker, api, resolver, _ = setup(job, resolver=ZoneResolver({}))
    worker.run_once()
    failure = api.endpoint_calls("failures")[0]
    assert failure["errorCode"] in {"invalid_profile", "active_scanning_disabled"}
    assert resolver.queries == []


def test_techniques_listed():
    assert "subdomain_dot" in LOOKALIKE_TECHNIQUES and len(LOOKALIKE_TECHNIQUES) == 11
