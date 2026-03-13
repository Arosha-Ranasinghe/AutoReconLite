#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os

from autoreconlite.dns_enum import enumerate_subdomains
from autoreconlite.dir_bruteforce import brute_force_dirs, load_wordlist
from autoreconlite.headers_check import check_security_headers, guess_base_urls
from autoreconlite.port_scanner import scan_ports
from autoreconlite.report import ReportData, print_report
from autoreconlite.utils import now_utc, resolve_host
from autoreconlite.vuln_detect import findings_from_dirs, findings_from_headers


COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]

DEFAULT_SUBDOMAIN_CANDIDATES = [
    "www", "mail", "smtp", "imap", "pop", "vpn", "portal", "sso",
    "dev", "test", "staging", "api", "admin"
]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="AutoReconLite",
        description="Recon tool: DNS subdomains, ports, headers, directory brute force, basic findings.",
    )
    p.add_argument("target", help="Target domain (e.g., example.com). Do not include paths.")
    p.add_argument("--threads", type=int, default=200, help="Port scan threads. Default: 200")
    p.add_argument("--dir-threads", type=int, default=50, help="Directory brute force threads. Default: 50")
    p.add_argument("--timeout", type=float, default=2.0, help="Socket/DNS timeout seconds. Default: 2.0")
    p.add_argument("--http-timeout", type=float, default=6.0, help="HTTP timeout seconds. Default: 6.0")
    p.add_argument(
        "--subdomains",
        default=",".join(DEFAULT_SUBDOMAIN_CANDIDATES),
        help="Comma-separated subdomain candidates (active DNS queries).",
    )
    p.add_argument("--wordlist", default=os.path.join("data", "wordlist.txt"), help="Directory brute force wordlist.")
    p.add_argument("--no-color", action="store_true", help="Disable colored output.")
    p.add_argument("--show-header-values", action="store_true", help="Print observed header values.")
    p.add_argument("--insecure", action="store_true", help="Disable TLS verification (not recommended).")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    target = args.target.strip()

    ip = resolve_host(target)

    # 1) DNS subdomain enum (candidate based)
    subs = [s.strip() for s in args.subdomains.split(",") if s.strip()]
    sub_results = enumerate_subdomains(target, subs, timeout=args.timeout)

    # 2) Port scan (threaded)
    scan_host = ip or target
    port_results = scan_ports(scan_host, COMMON_PORTS, threads=args.threads, timeout=args.timeout)

    # 3) HTTP headers
    header_result = check_security_headers(target, timeout=args.http_timeout, verify_tls=(not args.insecure))

    # 4) Directory brute force
    base_url = guess_base_urls(target)[0]
    if header_result is not None:
        base_url = header_result.final_url.split("#")[0]

    dir_results = []
    try:
        words = load_wordlist(args.wordlist)
        dir_results = brute_force_dirs(
            base_url, words, threads=args.dir_threads, timeout=args.http_timeout, verify_tls=(not args.insecure)
        )
    except FileNotFoundError:
        dir_results = []

    # 5) Findings
    findings = []
    if header_result is not None:
        findings.extend(findings_from_headers(header_result))
    findings.extend(findings_from_dirs(dir_results))

    report = ReportData(
        target=target,
        resolved_ip=ip,
        subdomains=sub_results,
        ports=port_results,
        headers=header_result,
        dirs=dir_results,
        findings=findings,
        timestamp_utc=now_utc(),
    )

    print_report(report, no_color=args.no_color, show_header_values=args.show_header_values)


if __name__ == "__main__":
    main()
