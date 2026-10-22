"""Passive subdomain discovery (design §7) — not implemented in this milestone.

Certificate Transparency discovery arrives in Milestone 9. This module deliberately contains no
network code. When implemented, discovered names will be submitted as ``pending`` candidates and
are never scanned until a user approves them into scope.
"""

from __future__ import annotations

AVAILABLE = False
