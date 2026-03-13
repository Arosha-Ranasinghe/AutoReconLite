from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

import requests


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


@dataclass(frozen=True)
class HeaderCheckResult:
    url: str
    status_code: int
    final_url: str
    present: Dict[str, str]
    missing: List[str]


def guess_base_urls(domain: str) -> List[str]:
    domain = domain.strip()
    if "://" in domain:
        return [domain]
    return [f"https://{domain}", f"http://{domain}"]


def check_security_headers(domain_or_url: str, timeout: float = 6.0, verify_tls: bool = True) -> Optional[HeaderCheckResult]:
    headers = {"User-Agent": "AutoReconLite/1.0 (educational)"}

    resp = None
    used = None
    for u in guess_base_urls(domain_or_url):
        try:
            resp = requests.get(u, headers=headers, allow_redirects=True, timeout=timeout, verify=verify_tls)
            used = u
            break
        except requests.RequestException:
            continue

    if resp is None:
        return None

    observed = dict(resp.headers)
    lower = {k.lower(): v for k, v in observed.items()}

    present: Dict[str, str] = {}
    missing: List[str] = []

    for h in SECURITY_HEADERS:
        v = lower.get(h.lower())
        if v and str(v).strip():
            present[h] = str(v).strip()
        else:
            missing.append(h)

    return HeaderCheckResult(
        url=used or domain_or_url,
        status_code=int(resp.status_code),
        final_url=str(resp.url),
        present=present,
        missing=missing,
    )
