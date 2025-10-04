from __future__ import annotations

from typing import Any

# Import inside function to avoid circular imports during app startup
def compute_severity_from_entities(entities: dict[str, Any] | None) -> str:
    """Cross-reference entities against watchlist to assign a simple severity.

    Rules (first match wins):
    - critical: any email/domain/ip/btc matches watchlist
    - high: contains >= 100 emails or domains
    - medium: contains >= 10 emails or domains
    - zero severity: has entities but none match the watchlist
    - unknown: no entities
    """
    from .assets_db import get_assets_sets  # lazy import

    wl = get_assets_sets()
    e = entities or {}
    emails = set(map(str.lower, e.get('emails', []) or []))
    domains = set(map(str.lower, e.get('domains', []) or []))
    ips = set(map(str.lower, e.get('ips', []) or []))
    btcs = set(map(str.lower, e.get('btc_wallets', []) or []))

    if (emails & wl['email']) or (domains & wl['domain']) or (ips & wl['ip']) or (btcs & wl['btc']):
        return 'critical'
    total = len(emails) + len(domains)
    if total >= 100:
        return 'high'
    if total >= 10:
        return 'medium'
    if emails or domains or ips or btcs:
        return 'zero severity'
    return 'unknown'
