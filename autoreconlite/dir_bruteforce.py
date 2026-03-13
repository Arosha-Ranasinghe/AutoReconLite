from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Iterable, List, Optional
from urllib.parse import urljoin

import requests


@dataclass(frozen=True)
class DirResult:
    url: str
    status_code: int
    content_length: int


def load_wordlist(path: str, limit: int = 5000) -> List[str]:
    words: List[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.strip()
            if not w or w.startswith("#"):
                continue
            words.append(w.lstrip("/"))
            if len(words) >= limit:
                break
    return words


def _probe(base_url: str, word: str, timeout: float, verify_tls: bool) -> Optional[DirResult]:
    url = urljoin(base_url.rstrip("/") + "/", word)
    headers = {"User-Agent": "AutoReconLite/1.0 (educational)"}
    try:
        r = requests.get(url, headers=headers, allow_redirects=True, timeout=timeout, verify=verify_tls)
        if r.status_code in (200, 204, 301, 302, 307, 308, 401, 403):
            return DirResult(
                url=str(r.url),
                status_code=int(r.status_code),
                content_length=int(r.headers.get("Content-Length") or 0),
            )
        return None
    except requests.RequestException:
        return None


def brute_force_dirs(
    base_url: str,
    words: Iterable[str],
    threads: int = 50,
    timeout: float = 6.0,
    verify_tls: bool = True,
) -> List[DirResult]:
    results: List[DirResult] = []
    with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        futs = [ex.submit(_probe, base_url, w, timeout, verify_tls) for w in words]
        for f in as_completed(futs):
            r = f.result()
            if r:
                results.append(r)

    # De-dupe
    seen = set()
    uniq: List[DirResult] = []
    for r in sorted(results, key=lambda x: (x.status_code, x.url)):
        if r.url not in seen:
            seen.add(r.url)
            uniq.append(r)
    return uniq
