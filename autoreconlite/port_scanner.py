from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class PortResult:
    host: str
    port: int
    open: bool
    banner: str = ""


def _scan_one(host: str, port: int, timeout: float) -> PortResult:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        banner = ""
        try:
            s.settimeout(0.6)
            banner = s.recv(128).decode(errors="ignore").strip()
        except Exception:
            banner = ""
        return PortResult(host=host, port=port, open=True, banner=banner)
    except Exception:
        return PortResult(host=host, port=port, open=False, banner="")
    finally:
        try:
            s.close()
        except Exception:
            pass


def scan_ports(host: str, ports: List[int], threads: int = 200, timeout: float = 1.5) -> List[PortResult]:
    results: List[PortResult] = []
    with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        futs = [ex.submit(_scan_one, host, p, timeout) for p in ports]
        for f in as_completed(futs):
            results.append(f.result())
    return sorted(results, key=lambda r: r.port)
