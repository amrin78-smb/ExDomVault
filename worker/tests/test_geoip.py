"""Offline IP geolocation (app.geoip): loader, lookup, refresh and DNS observation wiring.

Synthetic data only: every DB-IP download goes to an httpx.MockTransport; nothing touches the
network (conftest also replaces the default transport with one that refuses).
"""

import gzip
import ipaddress
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from app import geoip
from app.config import load_config
from app.dns_checks import DnsAnswer, check_dns, geo_entries, query_to_observation
from app.geoip import (
    MAX_AGE_SECONDS,
    GeoIp,
    GeoIpUnavailable,
    candidate_months,
    load_database,
)

from .test_dns_checks import TARGET, FakeResolver, ctx

# Public (non-documentation) ranges so lookups are not refused as prohibited.
ROWS = [
    "1.0.0.0,1.0.0.255,AU",
    "1.0.1.0,1.0.3.255,CN",
    "8.8.8.0,8.8.8.255,US",
    "9.9.9.0,9.9.9.255,ZZ",  # unknown: skipped
    "not-an-ip,1.2.3.4,US",  # malformed
    "8.8.9.0,8.8.8.255,US",  # start > end
    "8.8.8.100,8.8.8.200,DE",  # overlaps the previous range
    "1.1.1.0,1.1.1.255,au",  # lowercase code
    "1.2.3.0,1.2.3.255",  # too few fields
    "10.0.0.0,10.255.255.255,US",  # private: loads, but lookups refuse it
    "2001:200::,2001:200:ffff:ffff:ffff:ffff:ffff:ffff,JP",
    "2a00:1450::,2a00:1450:ffff:ffff:ffff:ffff:ffff:ffff,IE",
    "2a00:1450:4000::,2a00:1450:4000::ffff,GB",  # overlaps the previous IPv6 range
    "2c0f:fb50::,2c0f:fb50:ffff:ffff:ffff:ffff:ffff:ffff,KE",
]

NOW = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)


def gz(rows):
    return gzip.compress(("\n".join(rows) + "\n").encode())


def write_gz(path, rows):
    path.write_bytes(gz(rows))
    return str(path)


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class Server:
    """Fake download.db-ip.com: ``responses`` maps month -> httpx.Response (default 404)."""

    def __init__(self, responses=None):
        self.responses = responses or {}
        self.requests: list[httpx.Request] = []

    def __call__(self, request):
        self.requests.append(request)
        match = re.fullmatch(r"/free/dbip-country-lite-(\d{4}-\d{2})\.csv\.gz", request.url.path)
        assert match, request.url
        response = self.responses.get(match.group(1))
        if callable(response):
            return response(request)
        return response or httpx.Response(404)


def make_geo(tmp_path, server, **kwargs):
    clock = kwargs.pop("monotonic", Clock())
    return GeoIp(
        str(tmp_path / "geoip"),
        transport=httpx.MockTransport(server),
        now=kwargs.pop("now", lambda: NOW),
        monotonic=clock,
        min_ranges=kwargs.pop("min_ranges", 1),
        **kwargs,
    )


def seed_cache(geo, rows, *, age_seconds=0.0, month="2026-10"):
    os.makedirs(geo.cache_dir, exist_ok=True)
    write_gz(Path(geo.path), rows)
    stamp = NOW.timestamp() - age_seconds
    os.utime(geo.path, (stamp, stamp))
    with open(geo.meta_path, "w") as fh:
        json.dump({"month": month}, fh)


# -- loader / lookup -----------------------------------------------------------------------------


def test_loader_skips_malformed_unknown_inverted_and_overlapping_rows(tmp_path):
    db = load_database(write_gz(tmp_path / "db.csv.gz", ROWS))
    stats = db.stats()
    assert stats.ipv4_ranges == 4
    assert stats.ipv6_ranges == 3
    assert stats.skipped_rows == 7
    assert sorted(db.countries) == ["AU", "CN", "IE", "JP", "KE", "US"]


@pytest.mark.parametrize(
    ("ip", "country"),
    [
        ("1.0.0.0", "AU"),  # range start
        ("1.0.0.255", "AU"),  # range end
        ("1.0.1.0", "CN"),  # next range start
        ("1.0.3.255", "CN"),
        ("1.0.4.0", None),  # between ranges
        ("0.255.255.255", None),  # before the first range
        ("8.8.8.150", "US"),  # the overlapping DE row was skipped
        ("8.8.9.0", None),
        ("9.9.9.9", None),  # ZZ row skipped
        ("223.255.255.255", None),  # after the last range
        ("2001:200::", "JP"),
        ("2001:200:ffff:ffff:ffff:ffff:ffff:ffff", "JP"),
        ("2001:201::", None),
        ("2a00:1450:4000::1", "IE"),
        ("2c0f:fb50::1", "KE"),
        ("2c0f:fb51::", None),
        ("2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff", None),
    ],
)
def test_lookup_boundaries(tmp_path, ip, country):
    db = load_database(write_gz(tmp_path / "db.csv.gz", ROWS))
    assert db.lookup(ipaddress.ip_address(ip)) == country


@pytest.mark.parametrize(
    "ip",
    ["10.1.2.3", "127.0.0.1", "192.168.1.1", "100.64.0.1", "169.254.169.254", "::1",
     "fe80::1", "fc00::1", "::ffff:1.0.0.1", "2001:db8::1", "192.0.2.1", "not-an-ip", ""],
)  # fmt: skip
def test_prohibited_or_invalid_addresses_are_never_looked_up(tmp_path, ip):
    geo = make_geo(tmp_path, Server())
    seed_cache(geo, ROWS)
    geo.maybe_refresh()
    assert geo.loaded
    assert geo.country(ip) is None
    assert geo.country("1.0.0.1") == "AU"


def test_truncated_gzip_is_rejected(tmp_path):
    data = gz(ROWS)
    path = tmp_path / "bad.csv.gz"
    path.write_bytes(data[: len(data) // 2])
    with pytest.raises(GeoIpUnavailable):
        load_database(str(path))


def test_decompressed_size_cap(tmp_path):
    path = write_gz(tmp_path / "db.csv.gz", ROWS * 50)
    with pytest.raises(GeoIpUnavailable) as exc:
        load_database(path, max_decompressed_bytes=1024)
    assert exc.value.code == "decompressed_too_large"


def test_minimum_ranges(tmp_path):
    with pytest.raises(GeoIpUnavailable) as exc:
        load_database(write_gz(tmp_path / "db.csv.gz", ROWS), min_ranges=100)
    assert exc.value.code == "too_few_ranges"


def test_candidate_months_wrap_the_year():
    assert candidate_months(datetime(2026, 1, 2, tzinfo=UTC)) == ["2026-01", "2025-12"]
    assert candidate_months(NOW) == ["2026-10", "2026-09"]


# -- refresh -------------------------------------------------------------------------------------


def ok(rows=ROWS):
    return httpx.Response(200, content=gz(rows), headers={"Content-Type": "application/gzip"})


def test_fresh_cache_is_loaded_without_downloading(tmp_path):
    server = Server({"2026-10": ok()})
    geo = make_geo(tmp_path, server)
    seed_cache(geo, ROWS, age_seconds=3600)
    geo.maybe_refresh()
    assert server.requests == []
    assert geo.country("8.8.8.8") == "US"


def test_missing_cache_downloads_current_month(tmp_path):
    server = Server({"2026-10": ok()})
    geo = make_geo(tmp_path, server)
    geo.maybe_refresh()
    assert [str(r.url) for r in server.requests] == [
        "https://download.db-ip.com/free/dbip-country-lite-2026-10.csv.gz"
    ]
    request = server.requests[0]
    assert request.headers["User-Agent"].startswith("ExDomainVault-worker/")
    assert geo.country("2001:200::1") == "JP"
    assert json.loads(Path(geo.meta_path).read_text())["month"] == "2026-10"
    # Atomic write: no temp files left behind.
    assert sorted(os.listdir(geo.cache_dir)) == [geoip.CACHE_FILENAME, geoip.META_FILENAME]


def test_falls_back_to_previous_month_and_does_not_refetch_it(tmp_path):
    server = Server({"2026-09": ok()})
    clock = Clock()
    geo = make_geo(tmp_path, server, monotonic=clock)
    geo.maybe_refresh()
    assert [r.url.path[-14:] for r in server.requests] == ["2026-10.csv.gz", "2026-09.csv.gz"]
    assert geo.country("1.0.0.1") == "AU"
    os.utime(geo.path, (NOW.timestamp(), NOW.timestamp()))
    # A day later the current month is still unpublished: one 404, no second download of 09.
    later = NOW.timestamp() + geoip.NEWER_MONTH_CHECK_SECONDS + 60
    geo._now = lambda: datetime.fromtimestamp(later, UTC)
    clock.t += geoip.NEWER_MONTH_CHECK_SECONDS + 60
    server.requests.clear()
    geo.maybe_refresh()
    assert [r.url.path[-14:] for r in server.requests] == ["2026-10.csv.gz"]
    # ...and it is not retried on every loop iteration.
    server.requests.clear()
    geo.maybe_refresh()
    assert server.requests == []


def test_stale_cache_is_replaced(tmp_path):
    server = Server({"2026-10": ok(["1.0.0.0,1.0.0.255,NZ"])})
    geo = make_geo(tmp_path, server)
    seed_cache(geo, ROWS, age_seconds=MAX_AGE_SECONDS + 60, month="2026-09")
    geo.maybe_refresh()
    assert len(server.requests) == 1
    assert geo.country("1.0.0.1") == "NZ"
    assert geo.country("8.8.8.8") is None


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(500),
        httpx.Response(403),
        httpx.Response(200, content=b"<html>not gzip</html>"),
        httpx.Response(200, content=gz(ROWS)[:40]),  # truncated
        httpx.Response(200, content=b""),
    ],
)
def test_download_failure_keeps_the_existing_file(tmp_path, response):
    server = Server({"2026-10": response})
    geo = make_geo(tmp_path, server)
    seed_cache(geo, ROWS, age_seconds=MAX_AGE_SECONDS + 60, month="2026-08")
    before = Path(geo.path).read_bytes()
    geo.maybe_refresh()
    assert len(server.requests) == 1  # only a 404 falls back to the previous month
    assert Path(geo.path).read_bytes() == before
    assert geo.country("8.8.8.8") == "US"
    assert sorted(os.listdir(geo.cache_dir)) == [geoip.CACHE_FILENAME, geoip.META_FILENAME]


def test_failure_backs_off_instead_of_retrying_every_loop(tmp_path):
    server = Server({"2026-10": httpx.Response(503)})
    clock = Clock()
    geo = make_geo(tmp_path, server, monotonic=clock)
    geo.maybe_refresh()
    geo.maybe_refresh()
    assert len(server.requests) == 1
    clock.t += geoip.RETRY_BACKOFF_SECONDS + 1
    geo.maybe_refresh()
    assert len(server.requests) == 2


def test_connection_error_without_cache_omits_geo_and_logs_once(tmp_path, caplog):
    def refuse(request):
        raise httpx.ConnectError("down", request=request)

    clock = Clock()
    geo = make_geo(tmp_path, Server({"2026-10": refuse}), monotonic=clock)
    with caplog.at_level("WARNING"):
        geo.maybe_refresh()
        clock.t += geoip.RETRY_BACKOFF_SECONDS + 1
        geo.maybe_refresh()
    assert not geo.loaded
    assert geo.country("8.8.8.8") is None
    assert sum("geoip_unavailable" in r.getMessage() for r in caplog.records) == 1


def test_size_cap_aborts_and_keeps_the_old_file(tmp_path):
    big = gz([f"1.{i // 256}.{i % 256}.0,1.{i // 256}.{i % 256}.255,US" for i in range(5000)])
    server = Server({"2026-10": httpx.Response(200, content=big)})
    geo = make_geo(tmp_path, server, max_compressed_bytes=len(big) - 1)
    seed_cache(geo, ROWS, age_seconds=MAX_AGE_SECONDS + 60, month="2026-08")
    geo.maybe_refresh()
    assert geo.country("1.0.0.1") == "AU"  # old data, not the oversized download
    assert sorted(os.listdir(geo.cache_dir)) == [geoip.CACHE_FILENAME, geoip.META_FILENAME]


def test_too_few_ranges_in_a_download_is_rejected(tmp_path):
    server = Server({"2026-10": ok()})
    geo = make_geo(tmp_path, server, min_ranges=10_000)
    geo.maybe_refresh()
    assert not geo.loaded
    assert not os.path.exists(geo.path)


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_redirects_are_never_followed(tmp_path, status):
    server = Server(
        {"2026-10": httpx.Response(status, headers={"Location": "https://evil.example/x.gz"})}
    )
    geo = make_geo(tmp_path, server)
    geo.maybe_refresh()
    assert len(server.requests) == 1
    assert server.requests[0].url.host == "download.db-ip.com"
    assert not geo.loaded


def test_disabled_never_downloads_or_answers(tmp_path):
    server = Server({"2026-10": ok()})
    geo = make_geo(tmp_path, server, enabled=False)
    geo.maybe_refresh()
    assert server.requests == []
    assert geo.country("8.8.8.8") is None


def test_reloads_after_the_cache_file_changes(tmp_path):
    geo = make_geo(tmp_path, Server())
    seed_cache(geo, ROWS)
    geo.maybe_refresh()
    assert geo.country("1.0.0.1") == "AU"
    seed_cache(geo, ["1.0.0.0,1.0.0.255,NZ"], age_seconds=-10)
    geo.maybe_refresh()
    assert geo.country("1.0.0.1") == "NZ"


# -- DNS observations ----------------------------------------------------------------------------

GEO_ENTRY_KEYS = {"ip", "country"}


def assert_geo_contract(observation):
    """Mirrors dnsObservationSchema.geo: strict {ip<=45, country ^[A-Z]{2}$}, <= 100 entries."""
    geo = observation["geo"]
    assert observation["recordType"] in ("A", "AAAA")
    assert 1 <= len(geo) <= 100
    for entry in geo:
        assert set(entry) == GEO_ENTRY_KEYS
        assert len(entry["ip"]) <= 45
        assert re.fullmatch(r"[A-Z]{2}", entry["country"])
    order = [observation["values"].index(entry["ip"]) for entry in geo]
    assert order == sorted(order)


def loaded_geo(tmp_path):
    geo = make_geo(tmp_path, Server())
    seed_cache(geo, ROWS)
    geo.maybe_refresh()
    return geo


def test_dns_observations_carry_geo_only_for_a_and_aaaa(tmp_path):
    geo = loaded_geo(tmp_path)
    resolver = FakeResolver(
        {
            ("example.com", "A"): DnsAnswer(300, ["8.8.8.8", "1.0.0.1", "1.0.4.4"], "example.com"),
            ("example.com", "AAAA"): DnsAnswer(300, ["2001:200::1", "2001:db8::1"], "example.com"),
            ("example.com", "MX"): DnsAnswer(300, ["10 mx.example.com."], "example.com"),
            ("www.example.com", "A"): DnsAnswer(300, ["1.0.4.4"], "www.example.com"),
        }
    )
    out = []
    check_dns(resolver, TARGET, "example.com", True, ctx(), out.append, geo=geo.country)
    by_type = {o["recordType"]: o for o in out if o["hostname"] == "example.com"}
    assert by_type["A"]["values"] == ["1.0.0.1", "1.0.4.4", "8.8.8.8"]
    assert by_type["A"]["geo"] == [
        {"ip": "1.0.0.1", "country": "AU"},
        {"ip": "8.8.8.8", "country": "US"},
    ]
    assert by_type["AAAA"]["geo"] == [{"ip": "2001:200::1", "country": "JP"}]
    for o in out:
        if "geo" in o:
            assert_geo_contract(o)
    assert "geo" not in by_type["MX"]
    assert "geo" not in by_type["CNAME"]  # NODATA
    # No covered address -> field omitted, not empty.
    www = []
    check_dns(resolver, TARGET, "www.example.com", False, ctx(), www.append, geo=geo.country)
    assert all("geo" not in o for o in www)


def test_geo_is_capped_at_100_entries(tmp_path):
    geo = loaded_geo(tmp_path)
    values = [f"1.0.{i // 256 + 1}.{i % 256}" for i in range(150)]
    resolver = FakeResolver({("example.com", "A"): DnsAnswer(60, values, "example.com")})
    o = query_to_observation(resolver, TARGET, "example.com", "A", 1.0, geo.country)
    assert len(o["values"]) == 100
    assert len(o["geo"]) == 100
    assert_geo_contract(o)


def test_geo_errors_never_fail_the_dns_check():
    def broken(_ip):
        raise RuntimeError("boom")

    resolver = FakeResolver({("example.com", "A"): DnsAnswer(60, ["8.8.8.8"], "example.com")})
    o = query_to_observation(resolver, TARGET, "example.com", "A", 1.0, broken)
    assert o["resultStatus"] == "success"
    assert o["values"] == ["8.8.8.8"]
    assert "geo" not in o


def test_geo_entries_rejects_bad_codes_and_other_types():
    assert geo_entries(lambda _ip: "us", "A", ["8.8.8.8"]) == []
    assert geo_entries(lambda _ip: "USA", "A", ["8.8.8.8"]) == []
    assert geo_entries(lambda _ip: "US", "TXT", ["8.8.8.8"]) == []
    assert geo_entries(None, "A", ["8.8.8.8"]) == []


def test_without_geo_the_observation_is_unchanged():
    resolver = FakeResolver({("example.com", "A"): DnsAnswer(60, ["8.8.8.8"], "example.com")})
    o = query_to_observation(resolver, TARGET, "example.com", "A", 1.0)
    assert "geo" not in o


# -- config --------------------------------------------------------------------------------------


def test_config_defaults_and_flag(valid_env, tmp_path):
    config = load_config(valid_env)
    assert config.geoip_enabled is True
    assert config.geoip_dir == str(tmp_path / "geoip")  # next to the health file
    config = load_config({**valid_env, "EXDV_GEOIP_ENABLED": "false", "EXDV_GEOIP_DIR": "/srv/g"})
    assert config.geoip_enabled is False
    assert config.geoip_dir == "/srv/g"


@pytest.mark.parametrize(
    ("name", "value"),
    [("EXDV_GEOIP_ENABLED", "yes"), ("EXDV_GEOIP_ENABLED", "1"), ("EXDV_GEOIP_DIR", "rel/dir")],
)
def test_config_rejects_invalid_geo_settings(valid_env, name, value):
    from app.config import ConfigError

    with pytest.raises(ConfigError):
        load_config({**valid_env, name: value})


def test_load_database_reads_crlf_and_blank_lines(tmp_path):
    raw = b"1.0.0.0,1.0.0.255,AU\r\n\r\n2001:200::,2001:200::ffff,JP\r\n"
    path = tmp_path / "db.csv.gz"
    with gzip.open(path, "wb") as fh:
        fh.write(raw)
    db = load_database(str(path))
    assert db.stats().ipv4_ranges == 1
    assert db.stats().ipv6_ranges == 1
