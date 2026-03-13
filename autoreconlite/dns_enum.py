from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Set

import dns.resolver


@dataclass(frozen=True)
class SubdomainResult:
    fqdn: str
    record_type: str
    values: List[str]


def enumerate_subdomains(domain: str, candidates: Iterable[str], timeout: float = 2.0) -> List[SubdomainResult]:
    """
    Candidate-based subdomain enumeration using active DNS queries.
    Tries A and CNAME for each candidate.domain.
    """
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    results: List[SubdomainResult] = []
    seen: Set[str] = set()

    for sub in candidates:
        sub = sub.strip().strip(".")
        if not sub:
            continue
        fqdn = f"{sub}.{domain}".lower()
        if fqdn in seen:
            continue
        seen.add(fqdn)

        # A record
        try:
            ans = resolver.resolve(fqdn, "A")
            vals = sorted({r.to_text() for r in ans})
            if vals:
                results.append(SubdomainResult(fqdn=fqdn, record_type="A", values=vals))
                continue
        except Exception:
            pass

        # CNAME record
        try:
            ans = resolver.resolve(fqdn, "CNAME")
            vals = sorted({r.to_text().rstrip(".") for r in ans})
            if vals:
                results.append(SubdomainResult(fqdn=fqdn, record_type="CNAME", values=vals))
        except Exception:
            pass

    return results
