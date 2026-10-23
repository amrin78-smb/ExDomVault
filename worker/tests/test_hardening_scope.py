# ruff: noqa: RUF001, RUF003, S311, UP031, E501 - homoglyph and encoding test data; seeded random
"""Milestone 11/12 hardening: property-style scope-validation tests.

test_redteam.py already covers a fixed corpus of alternative encodings (BYPASS_TEXTS). This file
adds the gaps as seeded, randomised properties:

* every address inside every prohibited IPv4 range, written in every alternative encoding
  (integer, hex, octal, short forms, leading zeros, IPv4-mapped / -compatible / SIIT, NAT64 well-known
  and local-use prefixes, 6to4, Teredo server and obfuscated client), is refused by the parser or the
  prohibited-range check, at the policy entry point and from DNS answers;
* random addresses inside every prohibited IPv6 range are refused, while random public addresses
  in canonical form are allowed (so the refusals are meaningful);
* hostname label-boundary checks hold for IDN homographs, Unicode dot separators, zero-width and
  compatibility characters, trailing/leading dots and look-alike suffixes, and normalisation never
  produces a non-ASCII name.

Nothing here opens a socket: name resolution is faked and connects are counted.
"""

from __future__ import annotations

import ipaddress
import random
import socket

import pytest

from app.net import connect_tcp
from app.policy import (
    ScopeError,
    address_prohibited_reason,
    parse_address,
)
from app.scope import name_within_domain, normalise_hostname, validate_job_targets

from .test_redteam import Resolver, make_policy

SEED = 20261023
SAMPLES_PER_RANGE = 12

PROHIBITED_V4 = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
]  # fmt: skip

PROHIBITED_V6 = [
    "::/128", "::1/128", "::ffff:0:0/96", "::/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64",
    "2001::/32", "2001:2::/48", "2001:10::/28", "2001:20::/28", "2001:db8::/32", "3fff::/20",
    "2002::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
    # Outside 2000::/3 (not allocated for global unicast)
    "4000::/2", "8000::/1", "::2/127", "1::/16",
]  # fmt: skip

# Public space used for positive controls (well-known anycast/provider blocks, not special).
PUBLIC_V4 = ["8.8.8.0/24", "1.1.1.0/24", "93.184.216.0/24", "151.101.0.0/16"]
PUBLIC_V6 = ["2606:4700::/32", "2a00:1450::/32", "2001:4860::/32"]


def _sample(network: str, rng: random.Random, n: int = SAMPLES_PER_RANGE):
    net = ipaddress.ip_network(network)
    picks = {net.network_address, net.broadcast_address}
    while len(picks) < min(n, net.num_addresses):
        picks.add(net.network_address + rng.randrange(net.num_addresses))
    return sorted(picks)


def _v4_encodings(addr: ipaddress.IPv4Address) -> list[str]:
    """Every alternative text form of an IPv4 address an attacker might try (not the canonical)."""
    n = int(addr)
    o = list(addr.packed)
    out = [
        str(n),  # integer
        hex(n),  # 0x7f000001
        "0X%X" % n,
        "0%o" % n,  # octal integer
        ".".join("0%o" % b for b in o),  # dotted octal
        ".".join("0x%x" % b for b in o),  # dotted hex
        ".".join("%03d" % b for b in o),  # leading zeros
        f"{o[0]}.{(o[1] << 16) | (o[2] << 8) | o[3]}",  # a.b (24-bit tail)
        f"{o[0]}.{o[1]}.{(o[2] << 8) | o[3]}",  # a.b.c (16-bit tail)
        f"{addr}.",  # trailing dot
        f"{addr}:0",
        f"[{addr}]",
        f"{addr}/32",
        f"{addr}%00",
        f"{addr}​",
        f"{addr}".replace(".", "。"),  # ideographic full stop
        f"{addr}".replace(".", "．"),  # fullwidth full stop
        "".join(chr(0xFF10 + int(c)) if c.isdigit() else c for c in str(addr)),  # fullwidth digits
    ]
    hi, lo = n >> 16, n & 0xFFFF
    v6 = [
        f"::ffff:{addr}", f"::ffff:{hi:x}:{lo:x}", f"0:0:0:0:0:ffff:{addr}", f"::FFFF:{hi:X}:{lo:X}",
        f"::{addr}", f"::{hi:x}:{lo:x}",  # IPv4-compatible
        f"::ffff:0:{addr}", f"::ffff:0:{hi:x}:{lo:x}",  # SIIT
        f"64:ff9b::{addr}", f"64:ff9b::{hi:x}:{lo:x}",  # NAT64 well-known prefix
        f"64:ff9b:1::{hi:x}:{lo:x}", f"64:ff9b:1:{hi:x}:{lo:x}::",  # NAT64 local-use
        f"2002:{hi:x}:{lo:x}::1", f"2002:{hi:x}:{lo:x}:1::",  # 6to4
        # Teredo: server IPv4 in bits 32-63, client IPv4 obfuscated (XOR 0xffffffff) in the low 32.
        f"2001:0:{hi:x}:{lo:x}::1",
        f"2001:0:4136:e378:8000:63bf:{hi ^ 0xFFFF:x}:{lo ^ 0xFFFF:x}",
    ]  # fmt: skip
    # Some forms coincide with the canonical text for some addresses (e.g. 151.101.104.244 with
    # zero padding); those are not alternative encodings.
    return [t for t in out + v6 if t != str(addr)]


def _refused(text) -> bool:
    try:
        address = parse_address(text)
    except ScopeError:
        return True
    return address_prohibited_reason(address) is not None


@pytest.fixture
def sockets_created(monkeypatch):
    created: list[tuple] = []
    original_init = socket.socket.__init__

    def init(self, *args, **kwargs):
        created.append(args)
        original_init(self, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "__init__", init)
    return created


# ================================================================================================
# Addresses


@pytest.mark.parametrize("network", PROHIBITED_V4)
def test_every_encoding_of_prohibited_ipv4_is_refused(network):
    rng = random.Random(f"{SEED}-{network}")
    failures = []
    for addr in _sample(network, rng):
        for text in [str(addr), *_v4_encodings(addr)]:
            if not _refused(text):
                failures.append(text)
    assert failures == []


@pytest.mark.parametrize("network", PUBLIC_V4)
def test_public_ipv4_only_the_canonical_form_is_allowed(network):
    rng = random.Random(f"{SEED}-{network}")
    for addr in _sample(network, rng):
        if address_prohibited_reason(addr) is not None:
            continue  # e.g. a .0 / .255 that the stdlib backstop flags; not this test's concern
        assert parse_address(str(addr)) == addr
        assert address_prohibited_reason(parse_address(str(addr))) is None
        # Every alternative spelling (including transition forms of a PUBLIC address) is refused:
        # the worker never contacts IPv4 through an IPv6 transition mechanism.
        allowed = [t for t in _v4_encodings(addr) if not _refused(t)]
        assert allowed == [], allowed


@pytest.mark.parametrize("network", PROHIBITED_V6)
def test_random_addresses_in_prohibited_ipv6_ranges_are_refused(network):
    rng = random.Random(f"{SEED}-{network}")
    for addr in _sample(network, rng):
        for text in {str(addr), addr.exploded, addr.exploded.upper(), str(addr).upper()}:
            assert _refused(text), text


@pytest.mark.parametrize("network", PUBLIC_V6)
def test_random_public_ipv6_is_allowed_in_every_valid_spelling(network):
    rng = random.Random(f"{SEED}-{network}")
    for addr in _sample(network, rng):
        for text in {str(addr), addr.exploded, str(addr).upper()}:
            assert not _refused(text), text
        # ...but never with a zone id, brackets, prefix length or surrounding noise.
        for text in (f"{addr}%eth0", f"[{addr}]", f"{addr}/128", f" {addr}", f"{addr}\n"):
            assert _refused(text), text


@pytest.mark.parametrize(
    "network", ["127.0.0.0/8", "10.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10"]
)
def test_policy_never_connects_to_any_encoding(network, sockets_created):
    rng = random.Random(f"{SEED}-connect-{network}")
    policy = make_policy(approved=["93.184.216.0/24", "2606:4700::/32"])
    for addr in _sample(network, rng, 4):
        for text in [str(addr), *_v4_encodings(addr)]:
            for tier in ("web", "network"):
                with pytest.raises(ScopeError):
                    policy.assert_destination(text, tier=tier)
                with pytest.raises(ScopeError):
                    connect_tcp(policy, text, 443, timeout=1, tier=tier)
    assert sockets_created == []


@pytest.mark.parametrize("network", ["127.0.0.0/8", "10.0.0.0/8", "169.254.0.0/16"])
def test_dns_answers_in_any_encoding_never_yield_an_address(network):
    rng = random.Random(f"{SEED}-dns-{network}")
    policy = make_policy()
    for addr in _sample(network, rng, 4):
        encodings = [str(addr), *_v4_encodings(addr)]
        a_answers = [e for e in encodings if ":" not in e]
        aaaa_answers = [e for e in encodings if ":" in e]
        resolver = Resolver(
            {("www.example.com", "A"): a_answers, ("www.example.com", "AAAA"): aaaa_answers}
        )
        with pytest.raises(ScopeError) as err:
            policy.resolve("www.example.com", resolver, tier="web", lifetime=1)
        assert err.value.code == "no_allowed_address"


def test_a_public_answer_survives_while_every_bad_sibling_is_dropped():
    policy = make_policy()
    bad = [*_v4_encodings(ipaddress.IPv4Address("127.0.0.1")), "10.0.0.1", "169.254.169.254"]
    resolver = Resolver(
        {
            ("www.example.com", "A"): [e for e in bad if ":" not in e] + ["93.184.216.34"],
            ("www.example.com", "AAAA"): [e for e in bad if ":" in e],
        }
    )
    resolved = policy.resolve("www.example.com", resolver, tier="web", lifetime=1)
    assert [str(a) for a in resolved.addresses] == ["93.184.216.34"]


# ================================================================================================
# Hostnames and label boundaries

APEX = "example.com"

OUTSIDE = [
    # IDN homographs (Cyrillic а/е/о, Greek ο, Latin small capital, dotless i) at label boundaries
    "exаmple.com", "www.exаmple.com", "examplе.com", "examplе.com", "exаmple.com",
    "www.example.cοm", "www.exampⅼe.com", "www.еxample.com", "exampıe.com",
    # Their punycode forms are different names entirely
    "xn--exmple-cua.com", "www.xn--exmple-cua.com", "xn--example-9c.com",
    # Unicode dot separators would turn one label into a boundary
    "www。example.com", "www．example.com", "www｡example.com", "evil.com。example.com",
    "example。com", "www.example．com",
    # Zero-width / invisible characters inside labels
    "exa‍mple.com", "www.exa​mple.com", "www.example.com​", "﻿www.example.com",
    # Fullwidth letters
    "ｗｗｗ.example.com", "ＥＸＡＭＰＬＥ.com",
    # Look-alike suffixes and boundary tricks
    "evil-example.com", "evilexample.com", "example.com.evil.net", "example.co", "example.com-evil.net",
    "www.example.com.evil", "wwwexample.com", "example.comm", "xexample.com",
    # Dots and separators
    "example.com..", "www.example.com..", ".example.com", "..example.com", "www..example.com",
    "www.example.com/", "www.example.com\\", "www.example.com:443", "user@www.example.com",
    "www.example.com%2e", "www%2eexample.com", "www.example.com\x00.evil.net", "www.example.com\nHost: evil.net",
    "*.example.com", "www.*.example.com", "www.example.com#", "www.example.com?x",
    # IP-literal look-alikes
    "127.0.0.1", "[::1]", "2130706433",
]  # fmt: skip

INSIDE = [
    "example.com", "EXAMPLE.COM", "example.com.", "www.example.com", "WWW.Example.Com.",
    "a.b.c.example.com", "_dmarc.example.com", "xn--bcher-kva.example.com", "x-1.example.com",
]  # fmt: skip


@pytest.mark.parametrize("name", OUTSIDE)
def test_names_outside_the_domain_are_refused(name):
    assert name_within_domain(name, APEX) is False
    with pytest.raises(ScopeError):
        validate_job_targets(APEX, [name], [name])


@pytest.mark.parametrize("name", INSIDE)
def test_names_inside_the_domain_are_accepted(name):
    assert name_within_domain(name, APEX) is True


@pytest.mark.parametrize(
    "domain", ["exаmple.com", "example。com", "ＥＸＡＭＰＬＥ.com", "example.com..", ".example.com"]
)
def test_a_malformed_job_domain_puts_nothing_in_scope(domain):
    for name in ("example.com", "www.example.com", "www.exаmple.com"):
        assert name_within_domain(name, domain) is False


def test_normalisation_only_ever_produces_ascii_ldh_names():
    rng = random.Random(SEED)
    alphabet = (
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
        "аеоοıİKſß。．｡​‍"
        "﻿ａ０․⸮\u0000 \t%@:/\\*"
    )
    for _ in range(5000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(1, 40)))
        try:
            out = normalise_hostname(text)
        except ScopeError:
            continue
        assert out.isascii(), (text, out)
        assert all(ch in "abcdefghijklmnopqrstuvwxyz0123456789-_." for ch in out), (text, out)
        assert not out.endswith(".") and ".." not in out and not out.startswith(".")


def test_kelvin_sign_lowercases_to_ascii_but_cannot_escape_the_domain():
    # str.lower() maps U+212A KELVIN SIGN to ASCII "k" (UTS #46 maps it the same way), so the
    # normalised name is the same DNS name; it can never land outside the job's domain.
    assert normalise_hostname("K.example.com") == "k.example.com"
    assert name_within_domain("www.Kexample.com", "kexample.com") is True
    assert name_within_domain("Kexample.com", APEX) is False


def test_surrounding_whitespace_is_stripped_to_the_same_name_only():
    # normalise_hostname strips surrounding whitespace; the result is the same DNS name and the
    # normalised value (not the raw text) is what callers use. Inner whitespace is refused.
    assert normalise_hostname(" www.example.com\n") == "www.example.com"
    for bad in ("www .example.com", "www.example.com\nHost: evil.net", "www.example.com\r\nx"):
        with pytest.raises(ScopeError):
            normalise_hostname(bad)


def test_label_and_name_length_limits():
    assert name_within_domain("a" * 63 + ".example.com", APEX) is True
    assert name_within_domain("a" * 64 + ".example.com", APEX) is False
    long_ok = ".".join(["a" * 61] * 3) + ".example.com"  # 3*62 + 11 = 197 chars
    assert name_within_domain(long_ok, APEX) is True
    too_long = ".".join(["a" * 63] * 4) + ".example.com"
    assert name_within_domain(too_long, APEX) is False
