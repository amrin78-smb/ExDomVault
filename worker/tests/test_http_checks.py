"""HTTP availability / header check: observation building from fake net.HttpResult values."""

import ipaddress
import json

import pytest

from app import http_checks, net
from app.checks import CheckFailed
from app.scope import ScopeError

from .test_tls_checks import TARGET_ID, FakePolicy, assert_http_schema, make_ctx

V4 = ipaddress.ip_address("203.0.113.10")
V4B = ipaddress.ip_address("203.0.113.20")


def hop(url, address=V4, status=200, headers=None, decision="final", error=None):
    return net.HttpHop(
        url=url, address=address, status=status, headers=headers or {}, decision=decision,
        error=error,
    )  # fmt: skip


def result(*hops):
    return net.HttpResult(hops=tuple(hops))


def build(res, include_headers=True):
    return http_checks.build_http_observation(TARGET_ID, res, include_headers=include_headers)


def test_redirect_chain_with_hsts():
    res = result(
        hop("https://example.com/", status=301, decision="followed",
            headers={"location": "https://www.example.com/"}),
        hop("https://www.example.com/", address=V4B, status=200, headers={
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "server": "nginx/1.25.3",
            "x-powered-by": "PHP/8.2.1",
        }),
    )  # fmt: skip
    o = build(res)
    assert_http_schema(o)
    assert o["resultStatus"] == "success"
    assert o["url"] == "https://example.com/"
    assert o["ipAddress"] == "203.0.113.10"
    assert o["statusCode"] == 200
    assert o["finalUrl"] == "https://www.example.com/"
    assert o["redirectCount"] == 1
    assert o["hstsEnabled"] is True
    ev = o["evidence"]
    assert ev["hops"] == [
        {
            "url": "https://example.com/",
            "ip": "203.0.113.10",
            "status": 301,
            "decision": "followed",
        },
        {
            "url": "https://www.example.com/",
            "ip": "203.0.113.20",
            "status": 200,
            "decision": "final",
        },
    ]
    assert ev["securityHeaders"] == {
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "x-frame-options": None,
        "referrer-policy": None,
        "permissions-policy": None,
    }
    assert ev["server"] == "nginx/1.25.3"
    assert ev["xPoweredBy"] == "PHP/8.2.1"


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ({}, False),
        ({"strict-transport-security": "max-age=0"}, False),
        ({"strict-transport-security": "includeSubDomains"}, False),
        ({"strict-transport-security": 'max-age="600"'}, True),
        ({"strict-transport-security": "MAX-AGE=1"}, True),
        ({"strict-transport-security": "max-age=abc"}, False),
    ],
)
def test_hsts_parsing(headers, expected):
    o = build(result(hop("https://www.example.com/", headers=headers)))
    assert o["hstsEnabled"] is expected


def test_hsts_is_null_when_final_response_is_plain_http():
    o = build(
        result(hop("http://www.example.com/", headers={"strict-transport-security": "max-age=600"}))
    )
    assert o["hstsEnabled"] is None


def test_refused_redirect_is_partial_and_stops_at_the_refusal():
    res = result(
        hop("https://www.example.com/", status=302, decision="followed",
            headers={"location": "https://login.other.net/"}),
        hop("https://login.other.net/", address=None, status=None,
            decision="redirect_out_of_scope"),
    )  # fmt: skip
    o = build(res)
    assert_http_schema(o)
    assert o["resultStatus"] == "partial"
    assert o["statusCode"] == 302
    assert o["finalUrl"] == "https://login.other.net/"
    assert o["redirectCount"] == 1
    assert o["evidence"]["hops"][-1] == {
        "url": "https://login.other.net/",
        "ip": None,
        "status": None,
        "decision": "redirect_out_of_scope",
    }


def test_redirect_to_private_address_is_recorded_as_refused_hop():
    res = result(
        hop("https://www.example.com/", status=301, decision="followed",
            headers={"location": "https://internal.example.com/"}),
        hop("https://internal.example.com/", address=None, status=None,
            decision="no_allowed_address"),
    )  # fmt: skip
    o = build(res)
    assert o["resultStatus"] == "partial"
    assert o["evidence"]["hops"][-1]["decision"] == "no_allowed_address"


def test_header_values_are_truncated_and_sanitised():
    long_csp = "default-src " + "a" * 2000
    o = build(
        result(
            hop("https://www.example.com/", headers={
                "content-security-policy": long_csp,
                "server": "café\x00srv",
            })
        )
    )  # fmt: skip
    assert len(o["evidence"]["securityHeaders"]["content-security-policy"]) == 512
    assert o["evidence"]["server"] == "caf??srv"


def test_cookies_and_bodies_are_never_stored():
    o = build(
        result(
            hop("https://www.example.com/", headers={
                "set-cookie": "session=SECRET-COOKIE-VALUE; HttpOnly",
                "x-frame-options": "DENY",
            })
        )
    )  # fmt: skip
    dumped = json.dumps(o)
    assert "SECRET-COOKIE-VALUE" not in dumped
    assert "set-cookie" not in dumped


def test_availability_only_omits_header_evidence():
    o = build(result(hop("https://www.example.com/", headers={"server": "x"})), False)
    assert set(o["evidence"]) == {"hops"}
    assert o["hstsEnabled"] is False


def test_connect_failure_without_response_is_error_or_timeout():
    o = build(
        result(hop("https://www.example.com/", status=None, decision="error", error="timeout"))
    )
    assert_http_schema(o)
    assert o["resultStatus"] == "timeout"
    assert o["statusCode"] is None
    assert o["hstsEnabled"] is None
    assert o["evidence"]["hops"][0]["error"] == "timeout"
    o = build(
        result(
            hop("https://www.example.com/", status=None, decision="error",
                error="connection_refused")
        )
    )  # fmt: skip
    assert o["resultStatus"] == "error"


def test_no_observation_when_first_hop_never_connected():
    assert build(result(hop("https://www.example.com/", address=None, status=None,
                            decision="prohibited_address"))) is None  # fmt: skip


def test_evidence_stays_under_the_size_cap():
    headers = {name: "\\" * 600 for name in http_checks.SECURITY_HEADERS}
    headers.update({"server": "\\" * 600, "x-powered-by": "\\" * 600})
    hops = [
        hop(f"https://www.example.com/{'x' * 1500}{i}", status=301, decision="followed")
        for i in range(5)
    ]
    hops.append(hop("https://www.example.com/end", headers=headers))
    o = build(result(*hops))
    assert_http_schema(o)


# -- check orchestration ------------------------------------------------------------------------


@pytest.fixture
def gets(monkeypatch):
    calls = []
    responses = {}

    def fake(policy, url, resolver, *, timeout, tier="web", **_kw):
        calls.append((url, tier, timeout))
        value = responses[url]
        if isinstance(value, BaseException):
            raise value
        return value

    monkeypatch.setattr(net, "http_get", fake)
    return calls, responses


def run(include_headers=True):
    out = []
    http_checks.check_http(
        FakePolicy(), None, TARGET_ID, "www.example.com", make_ctx(), out.append,
        include_headers=include_headers,
    )  # fmt: skip
    return out


def test_https_answer_means_no_plain_http_request(gets):
    calls, responses = gets
    responses["https://www.example.com/"] = result(hop("https://www.example.com/"))
    out = run()
    assert [c[0] for c in calls] == ["https://www.example.com/"]
    assert calls[0][1] == "web"
    assert len(out) == 1


def test_https_connect_failure_falls_back_to_http(gets):
    calls, responses = gets
    responses["https://www.example.com/"] = result(
        hop("https://www.example.com/", status=None, decision="error", error="connection_refused")
    )
    responses["http://www.example.com/"] = result(hop("http://www.example.com/"))
    out = run()
    assert [c[0] for c in calls] == ["https://www.example.com/", "http://www.example.com/"]
    assert [(o["url"], o["resultStatus"]) for o in out] == [
        ("https://www.example.com/", "error"),
        ("http://www.example.com/", "success"),
    ]
    for o in out:
        assert_http_schema(o)


def test_refusal_before_connecting_emits_nothing_and_raises_the_code(gets):
    calls, responses = gets
    responses["https://www.example.com/"] = result(
        hop("https://www.example.com/", address=None, status=None, decision="no_allowed_address")
    )
    with pytest.raises(ScopeError) as err:
        run()
    assert err.value.code == "no_allowed_address"
    assert len(calls) == 1  # plain HTTP would be refused the same way


def test_dns_failure_maps_to_resolution_failed(gets):
    _, responses = gets
    responses["https://www.example.com/"] = result(
        hop("https://www.example.com/", address=None, status=None, decision="error",
            error="nxdomain")
    )  # fmt: skip
    with pytest.raises(ScopeError) as err:
        run()
    assert err.value.code == "resolution_failed"


def test_unexpected_os_errors_are_check_failures(gets):
    _, responses = gets
    responses["https://www.example.com/"] = OSError("boom")
    responses["http://www.example.com/"] = TimeoutError()
    with pytest.raises(CheckFailed) as err:
        run()
    assert err.value.code == "http_timeout"
