"""
Push-to-talk — captura de microfone e reprodução de áudio PCM.

PTTEngine  — abre InputStream do sounddevice; entrega chunks base64 via callback.
_Player    — reproduz chunks de múltiplos peers com jitter buffer; mistura para saída.

Ambos são importados de forma lazy em node.py para degradação elegante se
sounddevice não estiver disponível ou não houver dispositivo de áudio.

Fluxo de criptografia: os frames de voz são transmitidos como payloads JSON
sobre o WebSocket já protegido pelo ratchet de sessão (ChaCha20-Poly1305,
forward secrecy por mensagem). Nenhuma camada extra é necessária.
"""

import asyncio
import base64
import collections
import threading
from typing import Callable

import numpy as np
import sounddevice as sd

SAMPLE_RATE  = 16_000   # Hz — qualidade de voz adequada para LAN
CHANNELS     = 1
DTYPE        = np.int16
CHUNK_FRAMES = 320       # 20 ms @ 16 kHz → 640 bytes raw → ~880 bytes base64


class _Player:
    """Reproduz chunks PCM de múltiplos peers simultaneamente (mistura simples)."""

    def __init__(self) -> None:
        self._lock  = threading.Lock()
        self._bufs: dict[str, collections.deque[np.ndarray]] = {}
        self._stream = sd.OutputStream(
            samplerate = SAMPLE_RATE,
            channels   = CHANNELS,
            dtype      = DTYPE,
            blocksize  = CHUNK_FRAMES,
            callback   = self._cb,
        )
        self._stream.start()

    def feed(self, peer_key: str, b64: str) -> None:
        """Enfileira um chunk PCM base64 para reprodução."""
        try:
            raw = base64.b64decode(b64)
            arr = np.frombuffer(raw, dtype=DTYPE).copy()
        except Exception:
            return
        with self._lock:
            self._bufs.setdefault(peer_key, collections.deque()).append(arr)

    def flush(self, peer_key: str) -> None:
        """Descarta buffer de um peer (desconexão ou fim de transmissão)."""
        with self._lock:
            self._bufs.pop(peer_key, None)

    def _cb(self, outdata: np.ndarray, frames: int, time, status) -> None:
        mixed = np.zeros(frames, dtype=np.int32)
        with self._lock:
            for buf in self._bufs.values():
                if buf:
                    chunk = buf.popleft()
                    n = min(len(chunk), frames)
                    mixed[:n] += chunk[:n].astype(np.int32)
        np.clip(mixed, -32768, 32767, out=mixed)
        outdata[:] = mixed.astype(DTYPE).reshape(outdata.shape)

    def close(self) -> None:
        self._stream.stop()
        self._stream.close()


class PTTEngine:
    """
    Captura microfone em chunks de 20 ms.

    start(loop) — abre InputStream; on_frame(b64) é chamado por chunk capturado.
    stop()      — fecha InputStream e cancela a task asyncio.
    """

    def __init__(self, on_frame: Callable[[str], None]) -> None:
        self._on_frame = on_frame
        self._loop:   asyncio.AbstractEventLoop | None = None
        self._queue:  asyncio.Queue | None             = None
        self._stream: sd.InputStream | None            = None
        self._task:   asyncio.Task | None              = None
        self._active  = False

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        """Abre o microfone. Levanta sd.PortAudioError se não houver dispositivo."""
        if self._active:
            return
        self._active = True
        try:
            self._loop   = loop
            self._queue  = asyncio.Queue()
            self._stream = sd.InputStream(
                samplerate = SAMPLE_RATE,
                channels   = CHANNELS,
                dtype      = DTYPE,
                blocksize  = CHUNK_FRAMES,
                callback   = self._cb,
            )
            self._stream.start()
            self._task = loop.create_task(self._drain())
        except Exception:
            self._active = False
            self._stream = None
            self._queue  = None
            raise

    def stop(self) -> None:
        if not self._active:
            return
        self._active = False
        if self._stream:
            self._stream.stop()
            self._stream.close()
            self._stream = None
        if self._task:
            self._task.cancel()
            self._task = None

    @property
    def active(self) -> bool:
        return self._active

    def _cb(self, indata: np.ndarray, frames: int, time, status) -> None:
        if self._loop and self._queue is not None:
            self._loop.call_soon_threadsafe(self._queue.put_nowait, indata.copy().tobytes())

    async def _drain(self) -> None:
        while self._active:
            try:
                raw = await asyncio.wait_for(self._queue.get(), timeout=0.1)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            self._on_frame(base64.b64encode(raw).decode())
