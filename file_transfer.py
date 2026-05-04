"""Utilitários de transferência de arquivos por chunks."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from pathlib import Path

CHUNK_SIZE    = 64 * 1024  # 64 KB por chunk
OFFER_TIMEOUT = 60         # segundos para aceitar a oferta


@dataclass
class IncomingOffer:
    file_id:      str
    sender_name:  str
    filename:     str
    size:         int
    total_chunks: int
    chunks:       dict[int, bytes] = field(default_factory=dict)

    @property
    def complete(self) -> bool:
        return len(self.chunks) == self.total_chunks

    def reassemble(self) -> bytes:
        return b"".join(self.chunks[i] for i in range(self.total_chunks))


def read_chunks(path: Path) -> list[str]:
    """Divide o arquivo em chunks base64."""
    data = path.read_bytes()
    return [
        base64.b64encode(data[i : i + CHUNK_SIZE]).decode()
        for i in range(0, len(data), CHUNK_SIZE)
    ]


def save_file(filename: str, data: bytes) -> Path:
    """Salva em ~/Downloads (ou ./received se não existir), renomeia se já houver conflito."""
    dest_dir = Path.home() / "Downloads"
    if not dest_dir.exists():
        dest_dir = Path.cwd() / "received"
    dest_dir.mkdir(parents=True, exist_ok=True)

    dest = dest_dir / filename
    n = 1
    while dest.exists():
        dest = dest_dir / f"{Path(filename).stem}_{n}{Path(filename).suffix}"
        n += 1
    dest.write_bytes(data)
    return dest


def human_size(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    return f"{n // 1024} KB"
