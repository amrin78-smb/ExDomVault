import pytest

from app.scope import (
    NETWORK_CHECKS,
    ScopeError,
    assert_passive_allowed,
    assert_registrable_domain,
    name_within_domain,
    normalise_hostname,
    validate_job_targets,
)


@pytest.mark.parametrize("check", ["dns", "rdap"])
def test_passive_checks_are_allowed(check):
    assert_passive_allowed(check)


@pytest.mark.parametrize("check", sorted(NETWORK_CHECKS))
def test_network_checks_are_refused(check):
    with pytest.raises(ScopeError) as err:
        assert_passive_allowed(check)
    assert err.value.code == "active_scanning_disabled"


def test_unknown_checks_are_refused():
    with pytest.raises(ScopeError) as err:
        assert_passive_allowed("nmap -sS")
    assert err.value.code == "unsupported_check"


@pytest.mark.parametrize(
    ("name", "domain", "expected"),
    [
        ("example.com", "example.com", True),
        ("www.example.com", "example.com", True),
        ("WWW.Example.COM.", "example.com", True),
        ("a.b.example.com", "example.com", True),
        ("_dmarc.example.com", "example.com", True),
        ("evil-example.com", "example.com", False),
        ("notexample.com", "example.com", False),
        ("example.com.evil.net", "example.com", False),
        ("example.co", "example.com", False),
        ("com", "example.com", False),
        ("www.example.com", "", False),
        ("www..example.com", "example.com", False),
        ("-bad.example.com", "example.com", False),
    ],
)
def test_name_within_domain_label_boundaries(name, domain, expected):
    assert name_within_domain(name, domain) is expected


def test_normalise_hostname():
    assert normalise_hostname("WWW.Example.com.") == "www.example.com"
    for bad in ["", ".", "a b.com", "x" * 64 + ".com", "exa*mple.com", "1.2.3.4/32"]:
        with pytest.raises(ScopeError):
            normalise_hostname(bad)


def test_validate_job_targets():
    validate_job_targets(
        "example.com", ["example.com", "www.example.com"], ["example.com", "www.example.com"]
    )
    with pytest.raises(ScopeError) as err:
        validate_job_targets("example.com", ["www.other.com"], ["www.other.com"])
    assert err.value.code == "scope_rejected"
    with pytest.raises(ScopeError) as err:
        validate_job_targets("example.com", ["api.example.com"], ["www.example.com"])
    assert err.value.code == "scope_rejected"
    with pytest.raises(ScopeError):
        validate_job_targets("example.com", ["bad host.example.com"], ["bad host.example.com"])


@pytest.mark.parametrize(
    "domain",
    ["com", "localhost", "arpa", "in-addr.arpa", "1.0.0.127.in-addr.arpa", "ip6.arpa", "co.uk",
     "CO.UK.", "github.io", "workers.dev", "pages.dev", "herokuapp.com", "com.au",
     "s3.amazonaws.com"],
)  # fmt: skip
def test_public_suffix_and_single_label_domains_are_refused(domain):
    with pytest.raises(ScopeError) as err:
        assert_registrable_domain(domain)
    assert err.value.code == "scope_rejected"
    with pytest.raises(ScopeError):
        validate_job_targets(domain, [], [])


@pytest.mark.parametrize(
    "domain", ["example.com", "example.co.uk", "me.github.io", "a.workers.dev"]
)
def test_registrable_domains_are_accepted(domain):
    assert assert_registrable_domain(domain) == domain
