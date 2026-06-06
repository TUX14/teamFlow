"""Utilitários de transferência de arquivos por chunks."""

from __future__ import annotations

import base64
import math
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

CHUNK_SIZE    = 64 * 1024  # 64 KB por chunk
OFFER_TIMEOUT = 60         # segundos para aceitar a oferta
SEND_WINDOW   = 16         # chunks enviados antes de ceder o event loop


@dataclass
class IncomingOffer:
    file_id:      str
    sender_name:  str
    filename:     str
    size:         int
    total_chunks: int
    _dir:         Path | None = field(default=None,  init=False, repr=False)
    _fh:          object      = field(default=None,  init=False, repr=False)
    _tmp:         Path | None = field(default=None,  init=False, repr=False)
    _received:    set[int]    = field(default_factory=set, init=False)
    _written:     int         = field(default=0,     init=False, repr=False)
    _speed_ts:    float       = field(default=0.0,   init=False, repr=False)
    _speed_buf:   int         = field(default=0,     init=False, repr=False)
    _speed_now:   float       = field(default=0.0,   init=False, repr=False)

    @property
    def complete(self) -> bool:
        return len(self._received) == self.total_chunks

    @property
    def is_active(self) -> bool:
        return self._fh is not None

    def open_tmp(self) -> None:
        d = Path.home() / "Downloads"
        if not d.exists():
            d = Path.cwd() / "received"
        d.mkdir(parents=True, exist_ok=True)
        self._dir      = d
        self._tmp      = d / f".teamflow_{self.file_id}"
        self._fh       = open(self._tmp, "wb")
        self._speed_ts = time.time()

    def write_chunk(self, index: int, data: bytes) -> None:
        if index in self._received or self._fh is None:
            return
        self._received.add(index)
        self._fh.seek(index * CHUNK_SIZE)
        self._fh.write(data)
        n = len(data)
        self._written   += n
        self._speed_buf += n

    def finalize(self) -> Path:
        self._fh.close()
        self._fh = None
        dest = self._dir / self.filename
        n = 1
        while dest.exists():
            dest = self._dir / f"{Path(self.filename).stem}_{n}{Path(self.filename).suffix}"
            n += 1
        self._tmp.rename(dest)
        return dest

    def abort(self) -> None:
        try:
            if self._fh is not None:
                self._fh.close()
        except Exception:
            pass
        if self._tmp is not None:
            self._tmp.unlink(missing_ok=True)
        self._fh = self._tmp = self._dir = None

    def progress_line(self) -> str:
        now     = time.time()
        pct     = int(self._written / self.size * 100) if self.size else 0
        elapsed = now - self._speed_ts
        if elapsed >= 0.4:
            s               = self._speed_buf / elapsed
            self._speed_now = 0.3 * s + 0.7 * self._speed_now
            self._speed_buf = 0
            self._speed_ts  = now

        speed_str = (human_size(int(self._speed_now)) + "/s") if self._speed_now > 1 else "…"

        remaining = self.size - self._written
        if self._speed_now > 1 and remaining > 0:
            eta     = int(remaining / self._speed_now)
            eta_str = f"~{eta}s" if eta < 60 else f"~{eta // 60}m{eta % 60:02d}s"
        else:
            eta_str = "…"

        return (
            f"[bold]{self.filename}[/bold]  "
            f"[cyan]{pct}%[/cyan] · "
            f"{human_size(self._written)} / {human_size(self.size)} · "
            f"[green]{speed_str}[/green] · {eta_str}"
        )


def chunk_count(path: Path) -> int:
    size = path.stat().st_size
    return max(1, math.ceil(size / CHUNK_SIZE)) if size > 0 else 1


def iter_chunks(path: Path) -> Iterator[str]:
    """Gera chunks base64 lendo CHUNK_SIZE bytes por vez."""
    with open(path, "rb") as f:
        while True:
            data = f.read(CHUNK_SIZE)
            if not data:
                break
            yield base64.b64encode(data).decode()


def human_size(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    if n >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n} B"
