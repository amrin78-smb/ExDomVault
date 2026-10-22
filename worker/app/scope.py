"""Job-level scope guard: check catalogue, hostname normalisation and label-boundary checks.

The worker runs passive checks (``dns`` queries public resolvers, ``rdap`` queries the registry's
RDAP service) and, only when ``EXDV_ACTIVE_SCANNING_ENABLED=true``, network-connecting checks. Every
connection those checks make goes through the Milestone 6 scope validator in :mod:`app.policy`
(resolve, validate every address against the prohibited ranges and the deny list, pin it,
revalidate every redirect and CNAME hop); this module provides the name-level building blocks.

* :func:`normalise_hostname` / :func:`name_within_domain` enforce exact DNS label boundaries: every
  target of a job must be the job's domain or a name beneath it.
* :func:`assert_registrable_domain` refuses a job domain that is a single label, under ``.arpa``
  or a well-known public suffix (``co.uk``, ``github.io``, ...), so a buggy or compromised server
  snapshot cannot put every name under a TLD in scope. The server already enforces the full Public
  Suffix List when a domain is added (``packages/shared`` hostname normalisation via ``tldts``);
  the compact built-in list here is a backstop, not a replacement.
* :func:`validate_job_targets` refuses a job whose targets are outside its domain or not listed in
  its immutable scope snapshot.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

PASSIVE_CHECKS: frozenset[str] = frozenset({"dns", "rdap"})
NETWORK_CHECKS: frozenset[str] = frozenset(
    {
        "tls_certificate",
        "http_availability",
        "http_headers",
        "tcp_ports",
        "service_identification",
        "tls_configuration",
    }
)
KNOWN_CHECKS: frozenset[str] = PASSIVE_CHECKS | NETWORK_CHECKS

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_MAX_NAME_LENGTH = 253


#: Common multi-label public suffixes (ICANN second-level registries and popular hosting suffixes
#: under which unrelated parties own names). Backstop only: the server checks the full PSL.
PUBLIC_SUFFIXES: frozenset[str] = frozenset(
    {
        # ICANN second-level registries
        "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "ac.uk", "gov.uk", "nhs.uk",
        "sch.uk", "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
        "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "com.br", "net.br", "org.br", "gov.br",
        "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "co.za", "org.za", "gov.za", "ac.za",
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "com.sg", "net.sg", "org.sg", "edu.sg",
        "gov.sg", "com.hk", "org.hk", "net.hk", "edu.hk", "gov.hk", "com.tw", "org.tw", "net.tw",
        "co.in", "net.in", "org.in", "gen.in", "firm.in", "ac.in", "gov.in", "co.id", "or.id",
        "ac.id", "go.id", "web.id", "com.my", "net.my", "org.my", "gov.my", "edu.my", "co.th",
        "in.th", "ac.th", "go.th", "or.th", "com.vn", "net.vn", "org.vn", "gov.vn", "edu.vn",
        "com.ph", "net.ph", "org.ph", "gov.ph", "co.kr", "or.kr", "ne.kr", "go.kr", "ac.kr",
        "com.mx", "org.mx", "gob.mx", "net.mx", "edu.mx", "com.ar", "net.ar", "org.ar", "gob.ar",
        "com.co", "net.co", "org.co", "gov.co", "com.pe", "com.tr", "net.tr", "org.tr", "gov.tr",
        "com.ua", "net.ua", "org.ua", "co.il", "org.il", "ac.il", "gov.il", "com.eg", "com.sa",
        "com.pk", "com.ng", "co.ke", "or.ke", "com.pl", "net.pl", "org.pl", "co.at", "or.at",
        "com.es", "org.es", "com.gr", "com.pt", "com.ru", "net.ru", "org.ru", "co.ve", "com.ve",
        # Hosting / platform suffixes (each subdomain belongs to a different customer)
        "github.io", "githubusercontent.com", "gitlab.io", "workers.dev", "pages.dev",
        "herokuapp.com", "azurewebsites.net", "cloudapp.net", "azurestaticapps.net",
        "trafficmanager.net", "blob.core.windows.net", "cloudfront.net",
        "elasticbeanstalk.com", "s3.amazonaws.com", "blogspot.com", "appspot.com",
        "firebaseapp.com", "web.app", "netlify.app", "vercel.app", "now.sh",
        "fly.dev", "onrender.com", "glitch.me", "repl.co", "ngrok.io", "ngrok-free.app",
        "myshopify.com",
        "global.ssl.fastly.net", "r.appspot.com", "run.app", "cloudfunctions.net",
        "digitaloceanspaces.com", "ondigitalocean.app", "dyndns.org", "duckdns.org", "no-ip.org",
        "ddns.net", "readthedocs.io", "surge.sh", "bitbucket.io",
    }
)  # fmt: skip


class ScopeError(Exception):
    """A check or target is outside what this worker may do. ``code`` is the API error code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def assert_passive_allowed(check: str) -> None:
    """Permits only passive checks. Network-connecting checks raise ``active_scanning_disabled``;
    unknown checks raise ``unsupported_check``."""
    if check in PASSIVE_CHECKS:
        return
    if check in NETWORK_CHECKS:
        raise ScopeError(
            "active_scanning_disabled",
            f"Check '{check}' connects to target hosts; active scanning is disabled.",
        )
    raise ScopeError("unsupported_check", "The profile lists a check this worker does not know.")


def normalise_hostname(name: str) -> str:
    """Lowercase A-label without a trailing dot; raises ScopeError(``invalid_hostname``)."""
    if not isinstance(name, str):
        raise ScopeError("invalid_hostname", "Hostname must be a string.")
    value = name.strip().lower()
    if value.endswith("."):
        value = value[:-1]
    if not value or len(value) > _MAX_NAME_LENGTH:
        raise ScopeError("invalid_hostname", "Hostname is empty or too long.")
    if not all(_LABEL_RE.fullmatch(label) for label in value.split(".")):
        raise ScopeError("invalid_hostname", "Hostname is not a valid A-label name.")
    return value


def assert_registrable_domain(domain: str) -> str:
    """The normalised job domain, or ScopeError(``scope_rejected``) when it is a single label
    (``com``, ``localhost``), lies under the ``arpa`` infrastructure TLD (``in-addr.arpa``), or is a
    built-in public suffix (:data:`PUBLIC_SUFFIXES`). Such a domain would put names owned by
    unrelated parties in scope."""
    try:
        name = normalise_hostname(domain)
    except ScopeError as exc:
        raise ScopeError("scope_rejected", "The job's domain is not a valid name.") from exc
    labels = name.split(".")
    if len(labels) < 2:
        raise ScopeError("scope_rejected", "The job's domain is a single label (a TLD).")
    if labels[-1] == "arpa":
        raise ScopeError("scope_rejected", "The job's domain is under the arpa TLD.")
    if name in PUBLIC_SUFFIXES:
        raise ScopeError("scope_rejected", "The job's domain is a public suffix.")
    return name


def name_within_domain(name: str, domain: str) -> bool:
    """True when ``name`` equals ``domain`` or lies beneath it at a label boundary.

    ``evil-example.com`` and ``example.com.evil.net`` are *not* within ``example.com``.
    """
    try:
        n = normalise_hostname(name)
        d = normalise_hostname(domain)
    except ScopeError:
        return False
    return n == d or n.endswith("." + d)


def validate_job_targets(
    domain: str,
    target_hostnames: Iterable[str],
    snapshot_hostnames: Iterable[str],
) -> None:
    """Refuses a job (``scope_rejected``) unless every claimed target is a valid name within the
    job's domain and is listed in the job's immutable scope snapshot."""
    apex = assert_registrable_domain(domain)
    allowed: set[str] = set()
    for raw in snapshot_hostnames:
        try:
            allowed.add(normalise_hostname(raw))
        except ScopeError:
            continue
    for raw in target_hostnames:
        try:
            host = normalise_hostname(raw)
        except ScopeError as exc:
            raise ScopeError("scope_rejected", "A target hostname is not a valid name.") from exc
        if not name_within_domain(host, apex):
            raise ScopeError("scope_rejected", "A target is outside the job's domain.")
        if host not in allowed:
            raise ScopeError("scope_rejected", "A target is not in the job's scope snapshot.")
