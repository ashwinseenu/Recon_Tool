"""Small HTTP helpers shared by modules."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

import httpx


@dataclass
class Fetched:
    url: str
    status: int
    headers: httpx.Headers
    body: bytes
    history: List[str] = field(default_factory=list)
    cookies: List[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


def fetch_limited(client: httpx.Client, url: str, max_bytes: int = 65536,
                  headers: Optional[dict] = None) -> Fetched:
    """GET that reads at most max_bytes of the body (never downloads large files)."""
    with client.stream("GET", url, headers=headers) as r:
        chunks, n = [], 0
        for chunk in r.iter_bytes():
            chunks.append(chunk)
            n += len(chunk)
            if n >= max_bytes:
                break
        return Fetched(url=str(r.url), status=r.status_code, headers=r.headers,
                       body=b"".join(chunks)[:max_bytes],
                       history=[str(h.url) for h in r.history],
                       cookies=r.headers.get_list("set-cookie"))
