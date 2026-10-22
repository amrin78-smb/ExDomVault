"""TCP port and limited service-identification checks — Milestone 6.

These checks connect to target hosts, so they are refused while active scanning is disabled.
There is no network code here (and no Nmap invocation): the entry points only consult the scope
guard, which raises :class:`app.scope.ScopeError` (``active_scanning_disabled``). They will be
implemented together with the Milestone 6 scope validator, using server-defined profiles only.
"""

from __future__ import annotations

from typing import Any, NoReturn

from app.scope import ScopeError, assert_passive_allowed


def check_tcp_ports(*_args: Any, **_kwargs: Any) -> NoReturn:
    assert_passive_allowed("tcp_ports")
    raise ScopeError("active_scanning_disabled", "Port checks are not available.")


def check_service_identification(*_args: Any, **_kwargs: Any) -> NoReturn:
    assert_passive_allowed("service_identification")
    raise ScopeError("active_scanning_disabled", "Port checks are not available.")
