from __future__ import annotations

import socket
import sys
import time
from dataclasses import dataclass
from typing import Optional


class Style:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GRAY = "\033[90m"


def color_enabled(no_color: bool) -> bool:
    return (not no_color) and sys.stdout.isatty()


def c(text: str, enable: bool, *styles: str) -> str:
    if not enable:
        return text
    return "".join(styles) + text + Style.RESET


def hr(width: int = 88, ch: str = "-") -> str:
    return ch * width


def now_utc() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())


def resolve_host(host: str) -> Optional[str]:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


@dataclass(frozen=True)
class Finding:
    title: str
    severity: str  # INFO/LOW/MEDIUM/HIGH
    description: str
    evidence: str = ""


def severity_color(sev: str) -> str:
    sev = sev.upper()
    if sev == "HIGH":
        return Style.RED
    if sev == "MEDIUM":
        return Style.YELLOW
    if sev == "LOW":
        return Style.CYAN
    return Style.GRAY
