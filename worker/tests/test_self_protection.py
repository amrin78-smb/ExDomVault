"""Home-network self-protection: parsing fixtures, egress detection (DNS faked), refresh state.

No live network: ``dns.query.udp`` is replaced; /proc content comes from fixtures.
"""

import ipaddress

import dns.message
import dns.rrset
import pytest

from app import self_protection as sp
from app.self_protection import (
    EGRESS_IP_UNKNOWN,
    SelfProtection,
    detect_egress_addresses,
    parse_fib_trie,
    parse_if_inet6,
    query_egress_address,
)

FIB_TRIE = """Main:
  +-- 0.0.0.0/0 4 1 11
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 10.0.3.0/24 2 0 2
        |-- 10.0.3.0
           /24 link UNICAST
        |-- 10.0.3.1
           /32 host LOCAL
        |-- 10.0.3.255
           /32 link BROADCAST
     |-- 81.2.69.142
        /32 host LOCAL
        /32 link UNICAST
     +-- 127.0.0.0/8 2 0 2
        |-- 127.0.0.1
           /32 host LOCAL
Local:
  +-- 0.0.0.0/0 4 1 11
     |-- 10.0.3.1
        /32 host LOCAL
     |-- 81.2.69.142
        /32 host LOCAL
"""

IF_INET6 = """00000000000000000000000000000001 01 80 10 80       lo
fe800000000000000a0027fffe123456 02 40 20 80     eth0
2001047000010002020027fffe123456 02 40 00 00     eth0
fd00000000000000020027fffe123456 02 40 00 00     eth0
garbage line
2001047000010002zz0027fffe123456 02 40 00 00     eth0
"""


def test_fib_trie_yields_only_local_host_entries():
    assert parse_fib_trie(FIB_TRIE) == [
        ipaddress.IPv4Address("10.0.3.1"),
        ipaddress.IPv4Address("81.2.69.142"),
        ipaddress.IPv4Address("127.0.0.1"),
    ]


def test_if_inet6_global_addresses_become_their_64():
    assert parse_if_inet6(IF_INET6) == [
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fe80::a00:27ff:fe12:3456/128"),
        ipaddress.ip_network("2001:470:1:2::/64"),
        ipaddress.ip_network("fd00::200:27ff:fe12:3456/128"),
    ]


def test_read_local_networks_uses_proc_files(monkeypatch, tmp_path):
    fib = tmp_path / "fib_trie"
    fib.write_text(FIB_TRIE)
    inet6 = tmp_path / "if_inet6"
    inet6.write_text(IF_INET6)
    monkeypatch.setattr(sp, "_FIB_TRIE_PATHS", (str(tmp_path / "missing"), str(fib)))
    monkeypatch.setattr(sp, "_IF_INET6_PATHS", (str(inet6),))
    networks = sp.read_local_networks()
    assert ipaddress.ip_network("81.2.69.142/32") in networks
    assert ipaddress.ip_network("2001:470:1:2::/64") in networks


def test_read_local_networks_falls_back_to_ioctl(monkeypatch, tmp_path):
    monkeypatch.setattr(sp, "_FIB_TRIE_PATHS", (str(tmp_path / "missing"),))
    monkeypatch.setattr(sp, "_IF_INET6_PATHS", (str(tmp_path / "missing"),))
    monkeypatch.setattr(sp, "_ioctl_ipv4_addresses", lambda: [ipaddress.IPv4Address("81.2.69.1")])
    assert sp.read_local_networks() == [ipaddress.ip_network("81.2.69.1/32")]


def test_ioctl_fallback_reads_this_hosts_loopback():
    # Local syscall only (no packets): the loopback interface has 127.0.0.1.
    assert ipaddress.IPv4Address("127.0.0.1") in sp._ioctl_ipv4_addresses()


def _txt_response(query, *texts, rdtype="TXT"):
    response = dns.message.make_response(query)
    response.answer.append(
        dns.rrset.from_text("whoami.cloudflare.", 0, "CH", rdtype, *[f'"{t}"' for t in texts])
    )
    return response


def test_egress_query_is_a_chaos_txt_query_to_the_given_resolver(monkeypatch):
    sent = []

    def fake_udp(query, where, timeout):
        sent.append((query, where, timeout))
        return _txt_response(query, "81.2.69.160")

    monkeypatch.setattr(sp.dns.query, "udp", fake_udp)
    assert query_egress_address("1.1.1.1", 2.0) == ipaddress.IPv4Address("81.2.69.160")
    ((query, where, timeout),) = sent
    question = query.question[0]
    assert str(question.name) == "whoami.cloudflare."
    assert dns.rdataclass.to_text(question.rdclass) == "CH"
    assert dns.rdatatype.to_text(question.rdtype) == "TXT"
    assert (where, timeout) == ("1.1.1.1", 2.0)


@pytest.mark.parametrize("text", ["not-an-ip", "127.1", "81.2.69.160 10.0.0.1", ""])
def test_malformed_egress_answers_are_rejected(monkeypatch, text):
    monkeypatch.setattr(sp.dns.query, "udp", lambda q, where, timeout: _txt_response(q, text))
    with pytest.raises(Exception):  # noqa: B017 - any failure: the address stays unknown
        query_egress_address("1.1.1.1")


def test_detect_egress_skips_failing_resolvers():
    def query(server):
        if server == "1.1.1.1":
            raise OSError("network unreachable")
        return ipaddress.ip_address("2001:470:1:2::99")

    assert detect_egress_addresses(query) == [ipaddress.ip_address("2001:470:1:2::99")]


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_refresh_builds_the_deny_list_and_is_hourly():
    clock = Clock()
    detections = []

    def egress():
        detections.append(1)
        return [ipaddress.ip_address("81.2.69.160"), ipaddress.ip_address("2001:470:1:2::99")]

    protection = SelfProtection(
        configured_deny=("192.0.2.0/24",),
        local_reader=lambda: [ipaddress.ip_network("10.0.3.1/32")],
        egress_detector=egress,
        monotonic=clock,
    )
    assert protection.blocking_reason() is None  # an explicit deny list is enough
    protection.maybe_refresh()
    assert protection.deny_networks() == (
        "192.0.2.0/24", "10.0.3.1/32", "81.2.69.160/32", "2001:470:1:2::/64",
    )  # fmt: skip
    clock.now += 3599
    protection.maybe_refresh()
    assert len(detections) == 1
    clock.now += 1
    protection.maybe_refresh()
    assert len(detections) == 2


def test_unknown_egress_fails_closed_until_detection_succeeds():
    answers = [[], [ipaddress.ip_address("2001:470:1:2::99")], [ipaddress.ip_address("81.2.69.1")]]
    protection = SelfProtection(
        local_reader=lambda: [], egress_detector=lambda: answers.pop(0), refresh_seconds=0
    )
    assert protection.blocking_reason() == EGRESS_IP_UNKNOWN  # never detected
    protection.refresh()
    assert protection.blocking_reason() == EGRESS_IP_UNKNOWN
    protection.refresh()  # IPv6 only: the IPv4 egress (NAT) is still unknown
    assert protection.blocking_reason() == EGRESS_IP_UNKNOWN
    protection.refresh()
    assert protection.blocking_reason() is None


def test_a_failed_detection_keeps_earlier_addresses_denied_and_fails_closed():
    answers = [[ipaddress.ip_address("81.2.69.1")], []]
    protection = SelfProtection(local_reader=lambda: [], egress_detector=lambda: answers.pop(0))
    protection.refresh()
    protection.refresh()
    assert "81.2.69.1/32" in protection.deny_networks()
    assert protection.blocking_reason() == EGRESS_IP_UNKNOWN


def test_detector_exceptions_never_escape():
    def boom():
        raise RuntimeError("bug")

    protection = SelfProtection(local_reader=boom, egress_detector=boom)
    protection.refresh()
    assert protection.blocking_reason() == EGRESS_IP_UNKNOWN
    assert protection.deny_networks() == ()
