"""Analytics helpers for deriving alert and risk data from stored leaks.

This module provides lightweight, read-only aggregation over the leaks table
to support frontend pages (alerts & risk analysis) without adding new DB
structures. For larger datasets you'd move these into SQL (GROUP BY / indexes),
but simple in-Python aggregation keeps it easy while prototyping.
"""
from __future__ import annotations

from typing import List, Dict, Any

from .assets_db import get_assets_sets
from . import database




def get_critical_leaks(limit: int = 50, user_id: int | None = None) -> List[Dict[str, Any]]:
    """Return dicts for latest critical leaks up to limit."""
    out: List[Dict[str, Any]] = []
    try:
        leaks_iter = database._iter_recent_leaks(limit=limit or 500, user_id=user_id)
    except TypeError:
        leaks_iter = database._iter_recent_leaks(limit=limit or 500)

    for leak in leaks_iter:  # scan a window to find critical
        if user_id is not None and leak.user_id != user_id:
            continue
        
        if (leak.severity or '').lower() == 'critical':
            norm = leak.normalized or {}
            out.append({
                'id': leak.id,
                'source': leak.source,
                'title': (norm or {}).get('title'),
                'severity': leak.severity,
                'timestamp': leak.timestamp.isoformat() if leak.timestamp else None,
                'entities': (norm or {}).get('entities') or {},
                'ssn': leak.ssn,
                'names': leak.names,
                'phone_numbers': leak.phone_numbers,
                'physical_addresses': leak.physical_addresses,
                'passwords': leak.passwords,
            })
            if len(out) >= limit:
                break
    return out


def severity_counts(limit: int | None = None, user_id: int | None = None) -> Dict[str, int]:
    """Return a frequency map of severities among recent leaks, optionally filtered by user_id."""
    counts: Dict[str, int] = {}

    try:
        leaks_iter = database._iter_recent_leaks(limit=limit, user_id=user_id)
    except TypeError:
        leaks_iter = database._iter_recent_leaks(limit=limit)

    for leak in leaks_iter:
        sev = (leak.severity or 'unknown').lower()
        counts[sev] = counts.get(sev, 0) + 1

    return counts



def asset_risk(limit: int | None = None, user_id: int | None = None) -> List[Dict[str, Any]]:
    """Return per-watchlist-asset risk inference based on leaks referencing it.

    Simple heuristic:
      - HIGH: asset appears in any critical leak
      - MEDIUM: asset appears in >=5 leaks (non-critical) but no critical
      - LOW: asset appears in >=1 leak
      - NONE: otherwise (omitted unless include_none=True)
    """
    # Build reverse index from entity value -> list of (severity, leak_id)
    appearances: Dict[str, list[str]] = {}
    crit_hits: set[str] = set()

    try:
        leaks_iter = database._iter_recent_leaks(limit=limit or 1000, user_id=user_id)
    except TypeError:
        leaks_iter = database._iter_recent_leaks(limit=limit or 1000)

    for leak in leaks_iter:
        norm = leak.normalized or {}
        ents = (norm or {}).get('entities') or {}
        values = []

        for key in ('emails', 'domains', 'ips', 'btc_wallets'):
            for v in ents.get(key, []) or []:
                if not isinstance(v, str):
                    continue
                vv = v.lower().strip()
                values.append(vv)
        if leak.ssn:
            values.append(str(leak.ssn).strip().lower())

        if leak.names:
            try:
                import json
                parsed = json.loads(leak.names) if isinstance(leak.names, str) else leak.names
                for n in parsed:
                    values.append(str(n).strip().lower())
            except Exception:
                values.append(str(leak.names).strip().lower())

        if leak.phone_numbers:
            try:
                import json
                parsed = json.loads(leak.phone_numbers) if isinstance(leak.phone_numbers, str) else leak.phone_numbers
                for p in parsed:
                    values.append(str(p).strip().lower())
            except Exception:
                values.append(str(leak.phone_numbers).strip().lower())

        if leak.physical_addresses:
            try:
                import json
                parsed = json.loads(leak.physical_addresses) if isinstance(leak.physical_addresses, str) else leak.physical_addresses
                for addr in parsed:
                    values.append(str(addr).strip().lower())
            except Exception:
                values.append(str(leak.physical_addresses).strip().lower())

        if leak.passwords:
            try:
                import json
                parsed = json.loads(leak.passwords) if isinstance(leak.passwords, str) else leak.passwords
                for pwd in parsed:
                    values.append(str(pwd).strip().lower())
            except Exception:
                values.append(str(leak.passwords).strip().lower())


        for v in set(values):  # de-dup for this leak
            appearances.setdefault(v, []).append((leak.severity or 'unknown').lower())
            if (leak.severity or '').lower() == 'critical':
                crit_hits.add(v)

    # Map watchlist assets to risk tiers
    wl_sets = get_assets_sets()  # {'email': set(), 'domain': set(), ...}
    flat_assets: list[tuple[str, str]] = []
    for t, aset in wl_sets.items():
        for v in aset:
            flat_assets.append((t, v))

    results: List[Dict[str, Any]] = []
    for a_type, value in flat_assets:
        sev_list = appearances.get(value, [])
        total = len(sev_list)
        if value in crit_hits:
            risk = 'high'
        elif total >= 5:
            risk = 'medium'
        elif total >= 1:
            risk = 'low'
        else:
            risk = 'none'
        results.append({
            'type': a_type,
            'value': value,
            'risk': risk,
            'leak_count': total,
        })

    # Sort: high -> medium -> low -> none, then by leak_count desc
    order = {'high': 0, 'medium': 1, 'low': 2, 'none': 3}
    results.sort(key=lambda r: (order.get(r['risk'], 9), -r['leak_count'], r['value']))
    return results


def risk_summary(user_id: int | None = None) -> Dict[str, Any]:
    """Aggregate everything needed by the risk_analysis page, optionally filtered by user."""
    counts = severity_counts(limit=1000, user_id=user_id)
    assets = asset_risk(limit=1000, user_id=user_id)
    return {
        'severity_counts': counts,
        'assets': assets,
        'total_leaks_indexed': sum(counts.values()),
    }


def risk_time_series(days: int = 7, user_id: int | None = None) -> List[Dict[str, Any]]:
    """Return a daily time series of an overall risk score for the past `days` days.

    Simple scoring heuristic:
      critical -> 10, high -> 5, medium -> 2, low -> 1, unknown/other -> 0

    Returns a list of {"date": "YYYY-MM-DD", "score": <number>} ordered by date ascending.
    """
    from datetime import datetime, timedelta

    # Build date buckets
    today = datetime.utcnow().date()
    start_date = today - timedelta(days=max(0, int(days) - 1))
    buckets: Dict[str, int] = {}
    date_list: List[str] = []
    for i in range(0, int(days)):
        d = start_date + timedelta(days=i)
        ds = d.isoformat()
        buckets[ds] = 0
        date_list.append(ds)

    # Severity weights
    weights = {
        'critical': 10,
        'high': 5,
        'medium': 2,
        'low': 1,
    }

    try:
        leaks_iter = database._iter_recent_leaks(limit=None, user_id=user_id)
    except TypeError:
        leaks_iter = database._iter_recent_leaks()

    for leak in leaks_iter:
        if user_id is not None and getattr(leak, 'user_id', None) != user_id:
            continue
        ts = getattr(leak, 'timestamp', None)
        if not ts:
            continue
        try:
            leak_date = ts.date().isoformat()
        except Exception:
            # If timestamp is a string, try slicing
            try:
                leak_date = str(ts)[:10]
            except Exception:
                continue
        if leak_date < start_date.isoformat() or leak_date > today.isoformat():
            continue
        sev = (leak.severity or 'unknown').lower()
        w = weights.get(sev, 0)
        buckets[leak_date] = buckets.get(leak_date, 0) + w

    # Build ordered list
    out: List[Dict[str, Any]] = []
    for ds in date_list:
        out.append({'date': ds, 'score': buckets.get(ds, 0)})
    return out


def severity_time_series(days: int = 7, user_id: int | None = None) -> List[Dict[str, Any]]:
    """Return daily counts per severity for the past `days` days.

    Returns a list of {"date": "YYYY-MM-DD", "critical": n, "high": n, "medium": n, "low": n, "unknown": n}
    ordered by date ascending.
    """
    from datetime import datetime, timedelta

    today = datetime.utcnow().date()
    start_date = today - timedelta(days=max(0, int(days) - 1))

    # Initialize buckets
    buckets: Dict[str, Dict[str, int]] = {}
    date_list: List[str] = []
    sev_keys = ['critical', 'high', 'medium', 'low', 'unknown']
    for i in range(0, int(days)):
        d = start_date + timedelta(days=i)
        ds = d.isoformat()
        buckets[ds] = {k: 0 for k in sev_keys}
        date_list.append(ds)

    try:
        leaks_iter = database._iter_recent_leaks(limit=None, user_id=user_id)
    except TypeError:
        leaks_iter = database._iter_recent_leaks()

    for leak in leaks_iter:
        if user_id is not None and getattr(leak, 'user_id', None) != user_id:
            continue
        ts = getattr(leak, 'timestamp', None)
        if not ts:
            continue
        try:
            leak_date = ts.date().isoformat()
        except Exception:
            try:
                leak_date = str(ts)[:10]
            except Exception:
                continue
        if leak_date < start_date.isoformat() or leak_date > today.isoformat():
            continue
        sev = (leak.severity or 'unknown').lower()
        if sev not in sev_keys:
            sev = 'unknown'
        buckets[leak_date][sev] = buckets[leak_date].get(sev, 0) + 1

    out: List[Dict[str, Any]] = []
    for ds in date_list:
        row = {'date': ds}
        row.update(buckets.get(ds, {k: 0 for k in sev_keys}))
        out.append(row)
    return out

