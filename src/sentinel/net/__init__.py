"""Network core for Sentinel (Phase 3).

Hardened HTTP client with SSRF defenses, URL allow-list, HMAC-signed disk
cache, and per-source retry budgets.  See prod_imp.md § 8 for the full
spec.

Public API is re-exported at module bottom after the submodules exist.
"""

from __future__ import annotations

__all__: list[str] = []
