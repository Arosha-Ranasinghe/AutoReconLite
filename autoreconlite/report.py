from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from .dir_bruteforce import DirResult
from .dns_enum import SubdomainResult
from .headers_check import HeaderCheckResult
from .port_scanner import PortResult
from .utils import Finding, Style, c, hr, severity_color


@dataclass(frozen=True)
class ReportData:
    target: str
    resolved_ip: Optional[str]
    subdomains: List[SubdomainResult]
    ports: List[PortResult]
    headers: Optional[HeaderCheckResult]
    dirs: List[DirResult]
    findings: List[Finding]
    timestamp_utc: str


def print_report(data: ReportData, no_color: bool = False, show_header_values: bool = False) -> None:
    color_on = (not no_color)

    print(c(hr(ch="=", width=88), color_on, Style.CYAN))
    print(c(f"{'AUTORECONLITE':^88}", color_on, Style.CYAN, Style.BOLD))
    print(c(f"{'Lightweight Recon (Educational)':^88}", color_on, Style.CYAN))
    print(c(hr(ch="=", width=88), color_on, Style.CYAN))

    print(f"{'Target':<18}: {data.target}")
    print(f"{'Resolved IP':<18}: {data.resolved_ip or 'N/A'}")
    print(f"{'Timestamp':<18}: {data.timestamp_utc}")
    print(c(hr(width=88), color_on, Style.GRAY))
    print()

    print(c("[*] Subdomain Enumeration (DNS)", color_on, Style.BLUE, Style.BOLD))
    if not data.subdomains:
        print("No subdomains found (from the candidate list).")
    else:
        for s in data.subdomains:
            print(f"- {s.fqdn} ({s.record_type}): {', '.join(s.values)}")
    print()

    print(c("[*] Port Scan (TCP connect)", color_on, Style.BLUE, Style.BOLD))
    open_ports = [p for p in data.ports if p.open]
    if not open_ports:
        print("No open ports detected (on the scanned list).")
    else:
        for p in open_ports:
            b = f" | banner: {p.banner}" if p.banner else ""
            print(f"- {p.host}:{p.port} OPEN{b}")
    print()

    print(c("[*] HTTP Security Headers", color_on, Style.BLUE, Style.BOLD))
    if data.headers is None:
        print("HTTP check failed (target unreachable over HTTP/HTTPS).")
    else:
        print(f"{'Checked URL':<18}: {data.headers.url}")
        print(f"{'Final URL':<18}: {data.headers.final_url}")
        print(f"{'Status Code':<18}: {data.headers.status_code}")
        if data.headers.missing:
            print(c("Missing:", color_on, Style.RED, Style.BOLD), ", ".join(data.headers.missing))
        else:
            print(c("Missing:", color_on, Style.GREEN, Style.BOLD), "None")

        if show_header_values and data.headers.present:
            print()
            print(c("Present header values:", color_on, Style.GRAY))
            for k, v in data.headers.present.items():
                print(f"- {k}: {v}")
    print()

    print(c("[*] Directory Brute Force (wordlist)", color_on, Style.BLUE, Style.BOLD))
    if not data.dirs:
        print("No interesting paths found (200/30x/401/403).")
    else:
        for r in sorted(data.dirs, key=lambda x: (x.status_code, x.url)):
            print(f"- {r.status_code} {r.url}")
    print()

    print(c("[*] Potential Findings", color_on, Style.MAGENTA, Style.BOLD))
    if not data.findings:
        print(c("No findings flagged by heuristics.", color_on, Style.GREEN, Style.BOLD))
    else:
        for f in data.findings:
            sev = f.severity.upper()
            sev_txt = c(sev, color_on, severity_color(sev), Style.BOLD)
            ev = f" | evidence: {f.evidence}" if f.evidence else ""
            print(f"- [{sev_txt}] {f.title}: {f.description}{ev}")
    print()

    print(c(hr(ch="=", width=88), color_on, Style.CYAN))
    print(c("Scan complete. Use responsibly.", color_on, Style.CYAN, Style.BOLD))
    print(c(hr(ch="=", width=88), color_on, Style.CYAN))
