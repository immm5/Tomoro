"""Round-robin proxy pool dengan auto-failover.

Format proxy.txt yang diterima:
    host:port
    host:port:user:pass
    user:pass@host:port
    http://user:pass@host:port
    https://...
    socks5://host:port
    socks5://user:pass@host:port

Aturan:
  - Proxy diambil round-robin urut sesuai file. Setelah proxy terakhir,
    balik ke index 0.
  - Kalau sebuah proxy ditandai 'mati' (mark_dead), dia di-skip pada
    putaran berikutnya. Tidak dihapus permanen — kalau Anda restart
    skrip, dia ikut lagi.
  - Kalau semua proxy mati, raise NoLiveProxyError.

Thread-safe via RLock (re-entrant) supaya aman dipakai dari worker pool nanti.
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


class NoLiveProxyError(RuntimeError):
    pass


@dataclass
class ProxyEntry:
    raw: str          # baris asli dari proxy.txt
    url: str          # URL siap requests, mis. http://user:pass@host:port
    dead: bool = False
    fail_count: int = 0
    last_used: float = 0.0

    def to_requests(self) -> dict[str, str]:
        return {"http": self.url, "https": self.url}


_HAS_SCHEME = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.I)


def _parse_line(line: str) -> Optional[str]:
    """Normalisasi satu baris jadi URL proxy lengkap."""
    s = line.strip()
    if not s or s.startswith("#"):
        return None

    # Sudah berskema
    if _HAS_SCHEME.match(s):
        return s

    # user:pass@host:port (tanpa skema)
    if "@" in s:
        return f"http://{s}"

    parts = s.split(":")
    if len(parts) == 2:
        # host:port
        return f"http://{parts[0]}:{parts[1]}"
    if len(parts) == 4:
        # host:port:user:pass
        host, port, user, pwd = parts
        return f"http://{user}:{pwd}@{host}:{port}"

    # Tidak dikenali
    return None


def load_proxies(path: Path) -> list[ProxyEntry]:
    if not path.exists():
        return []
    out: list[ProxyEntry] = []
    seen: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        url = _parse_line(raw)
        if not url:
            continue
        if url in seen:
            continue
        seen.add(url)
        out.append(ProxyEntry(raw=raw.strip(), url=url))
    return out


class ProxyPool:
    """Round-robin pool dengan failover ke proxy berikutnya."""

    def __init__(self, proxies: list[ProxyEntry]):
        self._proxies = list(proxies)
        self._idx = 0
        self._lock = threading.RLock()

    @classmethod
    def from_file(cls, path: Path) -> "ProxyPool":
        return cls(load_proxies(path))

    @property
    def empty(self) -> bool:
        return not self._proxies

    def __len__(self) -> int:
        return len(self._proxies)

    def alive_count(self) -> int:
        return sum(1 for p in self._proxies if not p.dead)

    def all(self) -> list[ProxyEntry]:
        return list(self._proxies)

    def get_next(self) -> ProxyEntry:
        """Ambil proxy hidup berikutnya (round-robin). Skip yang mati.
        Raises NoLiveProxyError kalau semuanya mati / list kosong.
        """
        with self._lock:
            if not self._proxies:
                raise NoLiveProxyError("proxy.txt kosong / tidak ada proxy")
            n = len(self._proxies)
            for _ in range(n):
                p = self._proxies[self._idx]
                self._idx = (self._idx + 1) % n
                if not p.dead:
                    return p
            raise NoLiveProxyError(
                f"Semua proxy ({n}) sudah ditandai mati di sesi ini."
            )

    def mark_dead(self, entry: ProxyEntry) -> None:
        with self._lock:
            entry.dead = True
            entry.fail_count += 1

    def mark_alive(self, entry: ProxyEntry) -> None:
        with self._lock:
            entry.dead = False
            entry.fail_count = 0


def is_proxy_error(exc: BaseException) -> bool:
    """Klasifikasi: ini error proxy atau error API yang valid?"""
    import requests as _r
    return isinstance(exc, (
        _r.exceptions.ProxyError,
        _r.exceptions.ConnectTimeout,
        _r.exceptions.SSLError,
    )) or (
        isinstance(exc, _r.exceptions.ConnectionError)
        and "proxy" in str(exc).lower()
    )
