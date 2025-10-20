from __future__ import annotations

from typing import Any

# Import inside function to avoid circular imports during app startup
def compute_severity_from_entities(entities: dict[str, Any] | None) -> str:
    """Cross-reference entities against watchlist to assign a simple severity.

    Rules (first match wins):
    - critical: any email/domain/ip/btc matches watchlist
    - high: contains SSNs or passwords, or >=100 emails/domains
    - medium: contains phone numbers, physical addresses, or >=10 emails/domains
    - zero severity: has entities but none match
    - unknown: no entities
    """
    from .assets_db import get_assets_sets  # lazy import

    wl = get_assets_sets()
    e = entities or {}

    emails = set(map(str.lower, e.get('emails', []) or []))
    domains = set(map(str.lower, e.get('domains', []) or []))
    ips = set(map(str.lower, e.get('ips', []) or []))
    btcs = set(map(str.lower, e.get('btc_wallets', []) or []))
    passwords = e.get('passwords') or []
    ssns = e.get('ssns') or []
    phones = e.get('phone_numbers') or []
    addresses = e.get('physical_addresses') or []

    # Normalize single string fields to list if needed
    if isinstance(passwords, str):
        passwords = [passwords]
    if isinstance(ssns, str):
        ssns = [ssns]
    if isinstance(phones, str):
        phones = [phones]
    if isinstance(addresses, str):
        addresses = [addresses]


    # Critical
    if (emails & wl['email']) or (domains & wl['domain']) or (ips & wl['ip']) or (btcs & wl['btc']):
        return 'critical'
    if ssns or passwords:
        return 'critical'
    
    # High
    total = len(emails) + len(domains)
    if total >= 100:
        return 'high'
    
    # Medium
    if phones or addresses or total >= 10:
        return 'medium'
    
    # Zero severity: entities exist but don't match above rules
    if emails or domains or ips or btcs or phones or addresses or ssns or passwords:
        return 'zero severity'
    
    return 'unknown'
