from __future__ import annotations

from typing import Any, Dict, Set
import hashlib


def _to_list(v: Any) -> list:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def compute_severity_from_entities(entities: dict[str, Any] | None) -> str:
    """Compute a baseline severity from entities only (no watchlist).

    Design:
    - Used as a fallback. Final severity should be derived with assets where possible.
    - If no entities present, returns 'zero severity'.
    """
    e = entities or {}

    # Normalize lists
    emails = [str(x).lower() for x in _to_list(e.get('emails'))]
    domains = [str(x).lower() for x in _to_list(e.get('domains'))]
    ips = [str(x).lower() for x in _to_list(e.get('ips'))]
    btcs = [str(x).lower() for x in _to_list(e.get('btc_wallets'))]
    passwords = _to_list(e.get('passwords'))
    ssns = _to_list(e.get('ssns'))
    phones = _to_list(e.get('phone_numbers'))
    addresses = _to_list(e.get('physical_addresses'))
    names = _to_list(e.get('names'))

    any_entities = any([emails, domains, ips, btcs, passwords, ssns, phones, addresses, names])
    if not any_entities:
        return 'zero severity'

    # Weights per type (tuned to emphasize sensitive data)
    weights = {
        'ssns': 40,
        'passwords': 25,
        'physical_addresses': 18,
        'phone_numbers': 12,
        'btc_wallets': 12,
        'ips': 8,
        'emails': 5,
        'domains': 3,
        'names': 1,
    }
    # Cap per-type counts
    caps = {
        'ssns': 3,
        'passwords': 5,
        'physical_addresses': 5,
        'phone_numbers': 8,
        'btc_wallets': 5,
        'ips': 10,
        'emails': 20,
        'domains': 20,
        'names': 20,
    }

    counts = {
        'ssns': len(ssns),
        'passwords': len(passwords),
        'physical_addresses': len(addresses),
        'phone_numbers': len(phones),
        'btc_wallets': len(btcs),
        'ips': len(ips),
        'emails': len(emails),
        'domains': len(domains),
        'names': len(names),
    }

    score = 0
    for k, n in counts.items():
        n_cap = min(n, caps[k])
        score += n_cap * weights[k]

    # Map numeric score to severity label
    if score >= 40:
        return 'critical'
    if score >= 20:
        return 'high'
    if score >= 8:
        return 'medium'
    if score >= 1:
        return 'low'
    return 'zero severity'


def _sha256(value: str) -> str:
    try:
        return hashlib.sha256(value.strip().encode('utf-8')).hexdigest()
    except Exception:
        return value


def compute_severity_with_assets(
    entities: Dict[str, Any] | None,
    assets: Dict[str, Set[str]] | None,
) -> str:
    """Compute severity using only matched entities against the user's assets.

    Behavior:
    - If nothing matches the user's assets, return 'zero severity'.
    - Otherwise score based on which entity TYPES matched (sensitive > less sensitive).
    - Sensitive asset types may be hashed in the DB; we hash the extracted entity before comparing.
    - Mapping of asset types to entity keys expected in `assets`:
        emails, domains, ips, btc_wallets, ssns, phone_numbers, passwords, physical_addresses, names
    """
    e = entities or {}
    a = assets or {}

    # Normalize entity lists
    emails = [str(x).lower() for x in _to_list(e.get('emails'))]
    domains = [str(x).lower() for x in _to_list(e.get('domains'))]
    ips = [str(x).lower() for x in _to_list(e.get('ips'))]
    btcs = _to_list(e.get('btc_wallets'))
    passwords = _to_list(e.get('passwords'))
    ssns = _to_list(e.get('ssns'))
    phones = _to_list(e.get('phone_numbers'))
    addresses = _to_list(e.get('physical_addresses'))
    names = _to_list(e.get('names'))

    # Asset sets (emails/domains/ips plain lowercase; sensitive stored as sha256 hex).
    aset = {
        'emails': set(x.lower() for x in a.get('emails', set())),
        'domains': set(x.lower() for x in a.get('domains', set())),
        'ips': set(x.lower() for x in a.get('ips', set())),
        'btc_wallets': a.get('btc_wallets', set()),  # hashed
        'passwords': a.get('passwords', set()),      # hashed
        'ssns': a.get('ssns', set()),                # hashed
        'phone_numbers': a.get('phone_numbers', set()),  # hashed
        'physical_addresses': a.get('physical_addresses', set()),  # hashed
        'names': a.get('names', set()),              # hashed
    }

    # Matched counts (only matched items contribute to score)
    matched_counts = {
        'emails': len([x for x in emails if x in aset['emails']]),
        'domains': len([x for x in domains if x in aset['domains']]),
        'ips': len([x for x in ips if x in aset['ips']]),
        'btc_wallets': len([x for x in btcs if _sha256(str(x)) in aset['btc_wallets'] or str(x) in aset['btc_wallets']]),
        'passwords': len([x for x in passwords if _sha256(str(x)) in aset['passwords'] or str(x) in aset['passwords']]),
        'ssns': len([x for x in ssns if _sha256(str(x)) in aset['ssns'] or str(x) in aset['ssns']]),
        'phone_numbers': len([x for x in phones if _sha256(str(x)) in aset['phone_numbers'] or str(x) in aset['phone_numbers']]),
        'physical_addresses': len([x for x in addresses if _sha256(str(x)) in aset['physical_addresses'] or str(x) in aset['physical_addresses']]),
        'names': len([x for x in names if _sha256(str(x)) in aset['names'] or str(x) in aset['names']]),
    }

    if sum(matched_counts.values()) == 0:
        return 'zero severity'

    # Weights for matched types only
    weights = {
        'ssns': 40,
        'passwords': 25,
        'physical_addresses': 18,
        'phone_numbers': 12,
        'btc_wallets': 12,
        'ips': 8,
        'emails': 5,
        'domains': 3,
        'names': 1,
    }
    caps = {
        'ssns': 3,
        'passwords': 5,
        'physical_addresses': 5,
        'phone_numbers': 8,
        'btc_wallets': 5,
        'ips': 10,
        'emails': 20,
        'domains': 20,
        'names': 20,
    }
    score = 0
    for k, n in matched_counts.items():
        score += min(n, caps[k]) * weights[k]

    if score >= 40:
        return 'critical'
    if score >= 20:
        return 'high'
    if score >= 8:
        return 'medium'
    if score >= 1:
        return 'low'
    return 'zero severity'
