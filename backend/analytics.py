"""Analytics helpers for deriving alert and risk data from stored leaks.

This module provides lightweight, read-only aggregation over the leaks table
to support frontend pages (alerts & risk analysis) without adding new DB
structures. For larger datasets you'd move these into SQL (GROUP BY / indexes),
but simple in-Python aggregation keeps it easy while prototyping.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Dict, Any

from .database import SessionLocal, Leak
from .assets_db import get_assets_sets, list_assets


def _iter_recent_leaks(limit: int | None = None) -> Iterable[Leak]:
    """Yield leaks newest-first. Optional limit (None = no explicit cap)."""
    session = SessionLocal()
    try:
        q = session.query(Leak).order_by(Leak.timestamp.desc())
        if limit:
            q = q.limit(int(limit))
        for row in q.all():
            yield row
    finally:
        session.close()


def get_critical_leaks(limit: int = 50) -> List[Dict[str, Any]]:
    """Return dicts for latest critical leaks up to limit."""
    out: List[Dict[str, Any]] = []
    for leak in _iter_recent_leaks(limit=500):  # scan a window to find critical
        if (leak.severity or '').lower() == 'critical':
            norm = leak.normalized or {}
            out.append({
                'id': leak.id,
                'source': leak.source,
                'title': (norm or {}).get('title'),
                'severity': leak.severity,
                'timestamp': leak.timestamp.isoformat() if leak.timestamp else None,
                'entities': (norm or {}).get('entities') or {},
            })
            if len(out) >= limit:
                break
    return out


def severity_counts(limit: int | None = None) -> Dict[str, int]:
    """Return a frequency map of severities among recent leaks."""
    counts: Dict[str, int] = {}
    for leak in _iter_recent_leaks(limit=limit):
        sev = (leak.severity or 'unknown').lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def asset_risk(limit: int | None = None) -> List[Dict[str, Any]]:
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
    for leak in _iter_recent_leaks(limit=limit or 1000):
        norm = leak.normalized or {}
        ents = (norm or {}).get('entities') or {}
        values = []
        for key in ('emails', 'domains', 'ips', 'btc_wallets'):
            for v in ents.get(key, []) or []:
                if not isinstance(v, str):
                    continue
                vv = v.lower().strip()
                values.append(vv)
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


def risk_summary() -> Dict[str, Any]:
    """Aggregate everything needed by the risk_analysis page."""
    counts = severity_counts(limit=1000)
    assets = asset_risk(limit=1000)
    return {
        'severity_counts': counts,
        'assets': assets,
        'total_leaks_indexed': sum(counts.values()),
    }
