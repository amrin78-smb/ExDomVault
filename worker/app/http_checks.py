"""HTTP availability and security-header checks — Milestone 6.

These checks connect to target hosts, so they are refused while active scanning is disabled.
There is no network code here: the entry points only consult the scope guard, which raises
:class:`app.scope.ScopeError` (``active_scanning_disabled``). They will be implemented together
with the Milestone 6 scope validator (destination validation, address pinning, redirect checks).
"""

from __future__ import annotations

from typing import Any, NoReturn

from app.scope import ScopeError, assert_passive_allowed


def check_http_availability(*_args: Any, **_kwargs: Any) -> NoReturn:
    assert_passive_allowed("http_availability")
    raise ScopeError("active_scanning_disabled", "HTTP checks are not available.")


def check_http_headers(*_args: Any, **_kwargs: Any) -> NoReturn:
    assert_passive_allowed("http_headers")
    raise ScopeError("active_scanning_disabled", "HTTP checks are not available.")
