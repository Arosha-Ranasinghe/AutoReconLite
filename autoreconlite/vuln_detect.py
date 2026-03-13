from __future__ import annotations

from typing import List

from .dir_bruteforce import DirResult
from .headers_check import HeaderCheckResult
from .utils import Finding


ADMIN_KEYWORDS = (
    "/admin",
    "/administrator",
    "/wp-admin",
    "/phpmyadmin",
    "dashboard",
    "console",
)


def findings_from_headers(h: HeaderCheckResult) -> List[Finding]:
    findings: List[Finding] = []

    if h.missing:
        findings.append(
            Finding(
                title="Missing HTTP security headers",
                severity="MEDIUM",
                description="One or more recommended HTTP security headers are missing.",
                evidence=", ".join(h.missing),
            )
        )

    if h.final_url.lower().startswith("http://"):
        findings.append(
            Finding(
                title="Site served over HTTP (not HTTPS)",
                severity="HIGH",
                description="The final URL is HTTP; consider enforcing HTTPS redirection and HSTS.",
                evidence=h.final_url,
            )
        )

    return findings


def findings_from_dirs(dir_results: List[DirResult]) -> List[Finding]:
    findings: List[Finding] = []
    for r in dir_results:
        u = r.url.lower()
        if any(k in u for k in ADMIN_KEYWORDS) and r.status_code in (200, 301, 302, 401, 403):
            findings.append(
                Finding(
                    title="Potential exposed admin panel",
                    severity="MEDIUM",
                    description="Admin-like endpoint discovered. Ensure access controls, MFA, and monitoring.",
                    evidence=f"{r.status_code} {r.url}",
                )
            )
    return findings
