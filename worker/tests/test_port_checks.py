"""TCP port check: fixed Nmap argv, destination validation, safe XML parsing, bounded subprocess.

Nmap is never executed: ``run_nmap`` is faked for the check tests, and the subprocess tests run
the Python interpreter as a stand-in process (no network).
"""

import ipaddress
import sys
import time

import pytest

from app import port_checks
from app.checks import CheckFailed, CheckStopped, TargetTimeout
from app.port_checks import PortScanSettings, build_nmap_argv, parse_nmap_xml, run_nmap
from app.scope import ScopeError

from .test_tls_checks import TARGET_ID, FakePolicy, assert_port_schema, make_ctx

STANDARD_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 1433, 1521,
                  3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]  # fmt: skip
DEEP_PORTS = [21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587,
              636, 873, 993, 995, 1080, 1194, 1433, 1521, 1723, 2049, 2375, 2376, 3000, 3306, 3389,
              5000, 5432, 5601, 5900, 5984, 6379, 6443, 7001, 8000, 8008, 8080, 8081, 8088, 8443,
              8888, 9000, 9090, 9200, 9443, 10250, 11211, 15672, 27017]  # fmt: skip
V4 = ipaddress.ip_address("198.51.100.7")
V6 = ipaddress.ip_address("2001:db8:1::7")


# -- argv ---------------------------------------------------------------------------------------


def test_standard_profile_argv_is_exact():
    argv = build_nmap_argv(
        "/usr/bin/nmap", [V4], STANDARD_PORTS, service_identification=True,
        rate_per_second=1, concurrency=2, host_timeout_seconds=600,
    )  # fmt: skip
    assert argv == [
        "/usr/bin/nmap", "-sT", "-Pn", "-n", "--unprivileged",
        "--max-retries", "1",
        "--host-timeout", "600s",
        "--max-rate", "10",
        "--max-parallelism", "8",
        "-p", "21,22,23,25,53,80,110,143,443,445,465,587,993,995,1433,1521,3306,3389,5432,5900,"
              "6379,8080,8443,9200,27017",
        "-sV", "--version-light",
        "-oX", "-",
        "198.51.100.7",
    ]  # fmt: skip


def test_deep_profile_argv_is_exact_ipv6():
    argv = build_nmap_argv(
        "/usr/bin/nmap", [V6], DEEP_PORTS, service_identification=True,
        rate_per_second=0.5, concurrency=1, host_timeout_seconds=1800,
    )  # fmt: skip
    assert argv == [
        "/usr/bin/nmap", "-sT", "-Pn", "-n", "--unprivileged",
        "--max-retries", "1",
        "--host-timeout", "1800s",
        "--max-rate", "5",
        "--max-parallelism", "4",
        "-p", ",".join(str(p) for p in DEEP_PORTS),
        "-sV", "--version-light",
        "-6",
        "-oX", "-",
        "2001:db8:1::7",
    ]  # fmt: skip


def test_argv_without_service_identification_and_never_dangerous_flags():
    argv = build_nmap_argv(
        "/usr/bin/nmap", [V4, ipaddress.ip_address("198.51.100.8")], [443, 22, 443],
        service_identification=False, rate_per_second=50, concurrency=16, host_timeout_seconds=5,
    )  # fmt: skip
    assert argv[argv.index("-p") + 1] == "22,443"
    assert argv[argv.index("--max-rate") + 1] == "100"
    assert argv[argv.index("--max-parallelism") + 1] == "16"
    assert argv[-2:] == ["198.51.100.7", "198.51.100.8"]
    for flag in ("-sV", "--script", "-sC", "-O", "-sS", "-A", "-sU", "-6", "--open"):
        assert flag not in argv


def test_argv_refuses_mixed_ip_versions_and_empty_targets():
    with pytest.raises(ValueError):
        build_nmap_argv("/usr/bin/nmap", [V4, V6], [80], service_identification=False,
                        rate_per_second=1, concurrency=1, host_timeout_seconds=60)  # fmt: skip
    with pytest.raises(ValueError):
        build_nmap_argv("/usr/bin/nmap", [], [80], service_identification=False,
                        rate_per_second=1, concurrency=1, host_timeout_seconds=60)  # fmt: skip


@pytest.mark.parametrize("bad", [[0], [65536], [True], ["80"], [80.0], ["80 --script=x"]])
def test_invalid_profile_ports_are_refused(bad):
    with pytest.raises(CheckFailed) as err:
        port_checks.validate_ports(bad)
    assert err.value.code == "invalid_profile"


# -- XML ----------------------------------------------------------------------------------------

HEADER = (
    '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun>\n'
    '<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>\n'
)


def nmap_xml(hosts, header=HEADER):
    return (header + '<nmaprun scanner="nmap" args="nmap">' + hosts + "</nmaprun>").encode()


def host(addr, ports, addrtype="ipv4"):
    return f'<host><status state="up"/><address addr="{addr}" addrtype="{addrtype}"/><ports>{ports}</ports></host>'  # noqa: E501


def port(number, state, reason="syn-ack", service=""):
    return (
        f'<port protocol="tcp" portid="{number}"><state state="{state}" reason="{reason}"/>'
        f"{service}</port>"
    )


def test_parse_states_services_and_ignores_unrequested_data():
    xml = nmap_xml(
        host("198.51.100.7",
             port(22, "open", service='<service name="ssh" product="OpenSSH" version="9.6p1" '
                                     'method="probed" conf="10"/>')
             + port(80, "closed", reason="conn-refused")
             + port(443, "filtered", reason="no-response")
             + port(8080, "open|filtered")
             + port(9999, "open")  # not in the profile
             + '<port protocol="udp" portid="53"><state state="open"/></port>')
        + host("198.51.100.99", port(22, "open"))  # not a validated address
    )  # fmt: skip
    results = parse_nmap_xml(
        xml, {"198.51.100.7"}, {22, 80, 443, 8080}, service_identification=True
    )
    assert [(r.ip, r.port, r.state, r.service) for r in results] == [
        ("198.51.100.7", 22, "open", "ssh"),
        ("198.51.100.7", 80, "closed", None),
        ("198.51.100.7", 443, "filtered", None),
        ("198.51.100.7", 8080, "filtered", None),
    ]
    o = port_checks.build_port_observation(TARGET_ID, results[0])
    assert_port_schema(o)
    assert o["evidence"] == {
        "method": "nmap-sT",
        "reason": "syn-ack",
        "product": "OpenSSH",
        "version": "9.6p1",
        "serviceMethod": "probed",
    }
    assert o["service"] == "ssh"


def test_service_is_null_without_service_identification():
    xml = nmap_xml(
        host("198.51.100.7", port(22, "open", service='<service name="ssh" method="table"/>'))
    )
    (result,) = parse_nmap_xml(xml, {"198.51.100.7"}, {22}, service_identification=False)
    assert result.service is None and result.product is None


def test_extraports_are_expanded_from_extrareasons():
    xml = nmap_xml(
        host("198.51.100.7",
             '<extraports state="closed" count="3"><extrareasons reason="conn-refused" count="3" '
             'proto="tcp" ports="21-23,9999"/></extraports>'
             '<extraports state="filtered" count="1"><extrareasons reason="no-response" count="1" '
             'proto="tcp" ports="25"/></extraports>'
             + port(443, "open"))
    )  # fmt: skip
    results = parse_nmap_xml(
        xml, {"198.51.100.7"}, {21, 22, 23, 25, 443}, service_identification=False
    )
    assert [(r.port, r.state) for r in results] == [
        (21, "closed"), (22, "closed"), (23, "closed"), (25, "filtered"), (443, "open"),
    ]  # fmt: skip


def test_single_extraports_group_without_port_list_covers_unlisted_ports():
    xml = nmap_xml(
        host("2001:db8:1::7",
             '<extraports state="filtered" count="2"><extrareasons reason="no-response" '
             'count="2"/></extraports>' + port(443, "open"),
             addrtype="ipv6")
    )  # fmt: skip
    results = parse_nmap_xml(xml, {"2001:db8:1::7"}, {22, 80, 443}, service_identification=False)
    assert [(r.ip, r.port, r.state) for r in results] == [
        ("2001:db8:1::7", 22, "filtered"),
        ("2001:db8:1::7", 80, "filtered"),
        ("2001:db8:1::7", 443, "open"),
    ]


def test_ambiguous_extraports_without_port_lists_are_not_guessed():
    xml = nmap_xml(
        host("198.51.100.7",
             '<extraports state="filtered" count="1"/><extraports state="closed" count="1"/>')
    )  # fmt: skip
    assert parse_nmap_xml(xml, {"198.51.100.7"}, {22, 80}, service_identification=False) == []


@pytest.mark.parametrize(
    "header",
    [
        '<?xml version="1.0"?>\n<!DOCTYPE nmaprun [<!ENTITY a "aaaa">]>\n',
        '<?xml version="1.0"?>\n<!DOCTYPE nmaprun SYSTEM "file:///etc/passwd">\n',
        '<?xml version="1.0"?>\n<!DOCTYPE nmaprun>\n<!doctype nmaprun>\n',
        '<?xml version="1.0"?>\n<!ENTITY x "y">\n',
    ],
)
def test_dtds_and_entities_are_refused(header):
    with pytest.raises(CheckFailed) as err:
        parse_nmap_xml(
            nmap_xml("", header=header), {"198.51.100.7"}, {22}, service_identification=False
        )
    assert err.value.code == "nmap_output_invalid"


@pytest.mark.parametrize("data", [b"not xml", b"<other/>", b"<nmaprun>"])
def test_malformed_xml_is_refused(data):
    with pytest.raises(CheckFailed) as err:
        parse_nmap_xml(data, {"198.51.100.7"}, {22}, service_identification=False)
    assert err.value.code == "nmap_output_invalid"


# -- subprocess (Python stands in for Nmap; no network) ------------------------------------------


def py(code):
    return [sys.executable, "-I", "-c", code]


def test_run_returns_stdout_with_minimal_env_and_rlimits():
    out = run_nmap(
        py(
            "import os, resource; "
            "print(sorted(os.environ)); "
            "print(resource.getrlimit(resource.RLIMIT_NOFILE)[1] <= 1024); "
            "print(resource.getrlimit(resource.RLIMIT_AS)[0] <= 512 * 1024 * 1024); "
            "print(resource.getrlimit(resource.RLIMIT_CORE)); "
            "print(os.getpgid(0) == os.getpid())"
        ),
        timeout=20,
    )
    lines = out.decode().split("\n")
    assert lines[0] in ("['PATH']", "['LC_CTYPE', 'PATH']")
    assert lines[1:5] == ["True", "True", "(0, 0)", "True"]


def test_rlimits_are_applied_without_preexec_fn(monkeypatch):
    """preexec_fn is unsafe in a multi-threaded process; the limits come from an exec stub."""
    seen = {}
    real_popen = port_checks.subprocess.Popen

    def spy(argv, **kwargs):
        seen["argv"], seen["kwargs"] = argv, kwargs
        return real_popen(argv, **kwargs)

    monkeypatch.setattr(port_checks.subprocess, "Popen", spy)
    target = py("print('ok')")
    assert run_nmap(target, timeout=20) == b"ok\n"
    assert "preexec_fn" not in seen["kwargs"]
    assert seen["kwargs"]["process_group"] == 0 and seen["kwargs"]["shell"] is False
    assert seen["argv"][:3] == [sys.executable, "-I", "-S"]
    assert seen["argv"][-len(target) :] == target  # the target argv is passed through unchanged


def test_limited_argv_requires_an_absolute_program():
    with pytest.raises(ValueError):
        port_checks.limited_argv(["nmap", "-sT"], 10)


def test_oversized_output_kills_the_process():
    start = time.monotonic()
    with pytest.raises(CheckFailed) as err:
        run_nmap(
            py(
                "import sys\nwhile True:\n    sys.stdout.write('x' * 65536)\n    sys.stdout.flush()"
            ),
            timeout=20,
            max_output=256 * 1024,
        )
    assert err.value.code == "nmap_output_too_large"
    assert time.monotonic() - start < 10


def test_timeout_kills_the_process_group():
    start = time.monotonic()
    with pytest.raises(CheckFailed) as err:
        run_nmap(
            py("import subprocess, sys, time; "
               "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
               "time.sleep(60)"),
            timeout=1,
        )  # fmt: skip
    assert err.value.code == "nmap_timeout"
    assert time.monotonic() - start < 10


def test_non_zero_exit_is_a_failure():
    with pytest.raises(CheckFailed) as err:
        run_nmap(py("import sys; sys.stderr.write('QUITTING!'); sys.exit(1)"), timeout=20)
    assert err.value.code == "nmap_failed"


def test_stop_request_kills_the_process():
    with pytest.raises(CheckStopped):
        run_nmap(py("import time; time.sleep(60)"), timeout=30, should_stop=lambda: True)


# -- check orchestration ------------------------------------------------------------------------


def settings(**overrides):
    base = {
        "ports": (22, 80, 443),
        "service_identification": True,
        "rate_per_second": 1,
        "concurrency": 2,
        "target_seconds": 600,
        "nmap_path": "/usr/bin/nmap",
        "nmap_available": True,
    }
    return PortScanSettings(**{**base, **overrides})


@pytest.fixture
def nmap_runs(monkeypatch):
    runs = []
    outputs = []

    def fake(argv, *, timeout, should_stop=lambda: False, **_kw):
        runs.append((argv, timeout))
        return outputs.pop(0) if outputs else nmap_xml("")

    monkeypatch.setattr(port_checks, "run_nmap", fake)
    return runs, outputs


def check(policy, sett=None, ctx=None):
    out = []
    port_checks.check_tcp_ports(
        policy, None, TARGET_ID, "www.example.com", ctx or make_ctx(), out.append,
        sett or settings(),
    )  # fmt: skip
    return out


def test_scan_runs_on_validated_network_tier_addresses(nmap_runs):
    runs, outputs = nmap_runs
    outputs.append(
        nmap_xml(
            host(
                "198.51.100.7",
                port(22, "open", service='<service name="ssh" method="probed"/>')
                + port(80, "closed")
                + port(443, "filtered"),
            )
        )
    )
    policy = FakePolicy({"network": {"www.example.com": ["198.51.100.7"]}})
    out = check(policy)
    assert ("resolve", "www.example.com", "network") in policy.calls
    assert ("assert_destination", "198.51.100.7", "network") in policy.calls
    assert len(runs) == 1
    argv, timeout = runs[0]
    assert argv[-1] == "198.51.100.7"
    assert argv[argv.index("--host-timeout") + 1] == "600s"
    assert timeout == 630
    assert [(o["port"], o["state"], o["service"]) for o in out] == [
        (22, "open", "ssh"), (80, "closed", None), (443, "filtered", None),
    ]  # fmt: skip
    for o in out:
        assert_port_schema(o)


def test_ipv4_and_ipv6_are_scanned_separately(nmap_runs):
    runs, outputs = nmap_runs
    outputs.extend(
        [
            nmap_xml(host("198.51.100.7", port(22, "open"))),
            nmap_xml(host("2001:db8:1::7", port(22, "closed"), addrtype="ipv6")),
        ]
    )
    policy = FakePolicy({"network": {"www.example.com": ["198.51.100.7", "2001:db8:1::7"]}})
    out = check(policy, settings(service_identification=False))
    assert [r[0][-1] for r in runs] == ["198.51.100.7", "2001:db8:1::7"]
    assert "-6" not in runs[0][0] and "-6" in runs[1][0]
    assert [(o["ipAddress"], o["state"]) for o in out] == [
        ("198.51.100.7", "open"), ("2001:db8:1::7", "closed"),
    ]  # fmt: skip


def test_any_refused_address_aborts_before_nmap_runs(nmap_runs):
    runs, _ = nmap_runs
    policy = FakePolicy(
        {"network": {"www.example.com": ["198.51.100.7", "198.51.100.8"]}},
        refuse={"198.51.100.8"},
    )
    with pytest.raises(ScopeError) as err:
        check(policy)
    assert err.value.code == "prohibited_address"
    assert runs == []


def test_no_approved_address_is_refused(nmap_runs):
    runs, _ = nmap_runs
    policy = FakePolicy({"network": {"www.example.com": "network_not_approved"}})
    with pytest.raises(ScopeError) as err:
        check(policy)
    assert err.value.code == "network_not_approved"
    assert runs == []


def test_missing_nmap_fails_without_resolving(nmap_runs):
    runs, _ = nmap_runs
    policy = FakePolicy({"network": {"www.example.com": ["198.51.100.7"]}})
    with pytest.raises(CheckFailed) as err:
        check(policy, settings(nmap_available=False))
    assert err.value.code == "nmap_unavailable"
    assert policy.calls == [] and runs == []


def test_no_results_is_a_failure(nmap_runs):
    policy = FakePolicy({"network": {"www.example.com": ["198.51.100.7"]}})
    with pytest.raises(CheckFailed) as err:
        check(policy)
    assert err.value.code == "nmap_no_results"


def test_too_little_budget_left_is_a_target_timeout(nmap_runs):
    runs, _ = nmap_runs
    policy = FakePolicy({"network": {"www.example.com": ["198.51.100.7"]}})
    with pytest.raises(TargetTimeout):
        check(policy, ctx=make_ctx(remaining=3))
    assert runs == []


def test_host_timeout_is_capped_by_the_remaining_budget(nmap_runs):
    runs, outputs = nmap_runs
    outputs.append(nmap_xml(host("198.51.100.7", port(22, "open"))))
    policy = FakePolicy({"network": {"www.example.com": ["198.51.100.7"]}})
    check(policy, ctx=make_ctx(remaining=120.5))
    argv, timeout = runs[0]
    assert argv[argv.index("--host-timeout") + 1] == "120s"
    assert timeout == 150
