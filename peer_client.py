"""
Cliente WebSocket P2P — conexões de saída para outros peers.

Espelho do handshake do peer_server, lado cliente:
  ← HELLO  : peer_x_pub(32) + peer_ed_pub(32) + username
  → HELLO  : my_x_pub(32) + my_ed_pub(32) + username
  ← CHALLENGE : nonce(32)
  → RESPONSE  : sign(nonce)
  ← OK / REJECT

Após handshake, gerencia fila de envio e reconexão com backoff.
"""

import asyncio
import json
import hashlib
from dataclasses import dataclass, field
from typing import Callable

import websockets

from crypto import (
    generate_session_keypair,
    x25519_exchange,
    x25519_public_to_bytes,
    public_key_from_bytes,
    public_key_to_bytes,
    derive_session_key,
    sign,
)
from identity import LocalIdentity
from ratchet import RatchetState, init_ratchet

HANDSHAKE_TIMEOUT = 10.0
RECONNECT_DELAYS  = [2, 4, 8, 16, 30]  # segundos


@dataclass
class OutSession:
    pub_key_hash:  str
    public_key_hex: str
    username:      str
    ratchet:       RatchetState
    ws:            object   # websockets.WebSocketClientProtocol
    _queue: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(maxsize=128))

    async def send(self, payload: dict) -> None:
        await self._queue.put(payload)

    async def _flush(self) -> None:
        while True:
            payload = await self._queue.get()
            data = self.ratchet.encrypt(json.dumps(payload).encode())
            await self.ws.send(data)


class PeerClient:
    def __init__(self, identity: LocalIdentity):
        self.identity  = identity
        self._sessions: dict[str, OutSession] = {}
        self._connecting: set[tuple] = set()
        self._on_message: Callable[[OutSession, dict], None] | None = None
        self._on_connect: Callable[[OutSession], None] | None = None
        self._on_disconnect: Callable[[str], None] | None = None

    def on_message(self, fn: Callable[[OutSession, dict], None]) -> None:
        self._on_message = fn

    def on_connect(self, fn: Callable[[OutSession], None]) -> None:
        self._on_connect = fn

    def on_disconnect(self, fn: Callable[[str], None]) -> None:
        self._on_disconnect = fn

    def get_session(self, pub_key_hash: str) -> OutSession | None:
        return self._sessions.get(pub_key_hash)

    def all_sessions(self) -> list[OutSession]:
        return list(self._sessions.values())

    def connect_to(self, ip: str, port: int, expected_pub_key_hash: str | None = None) -> None:
        key = (ip, port)
        if key in self._connecting:
            return
        self._connecting.add(key)
        asyncio.create_task(self._connect_loop(ip, port, expected_pub_key_hash))

    async def _handshake(self, ws, ip: str) -> OutSession | None:
        try:
            peer_hello = await asyncio.wait_for(ws.recv(), HANDSHAKE_TIMEOUT)
            if not isinstance(peer_hello, bytes) or len(peer_hello) < 64:
                return None

            peer_x_pub_bytes  = peer_hello[:32]
            peer_ed_pub_bytes = peer_hello[32:64]
            peer_username     = peer_hello[64:].decode("utf-8", errors="replace").strip()

            my_x_priv, my_x_pub = generate_session_keypair()
            my_ed_pub_bytes      = public_key_to_bytes(self.identity.public_key)
            my_hello             = (
                x25519_public_to_bytes(my_x_pub)
                + my_ed_pub_bytes
                + self.identity.username.encode("utf-8")
            )
            await asyncio.wait_for(ws.send(my_hello), HANDSHAKE_TIMEOUT)

            shared = x25519_exchange(my_x_priv, peer_x_pub_bytes)
            session_key = derive_session_key(
                shared,
                peer_x_pub_bytes,
                x25519_public_to_bytes(my_x_pub),
            )

            nonce = await asyncio.wait_for(ws.recv(), HANDSHAKE_TIMEOUT)
            if not isinstance(nonce, bytes):
                return None

            sig = sign(self.identity.private_key, nonce)
            await asyncio.wait_for(ws.send(sig), HANDSHAKE_TIMEOUT)

            result = await asyncio.wait_for(ws.recv(), HANDSHAKE_TIMEOUT)
            if result != b"OK":
                return None

            pk_hash = hashlib.sha256(peer_ed_pub_bytes).hexdigest()[:32]

            return OutSession(
                pub_key_hash=pk_hash,
                public_key_hex=peer_ed_pub_bytes.hex(),
                username=peer_username,
                ratchet=init_ratchet(session_key, is_initiator=False),
                ws=ws,
            )
        except Exception:
            return None

    async def _connect_loop(self, ip: str, port: int, expected_hash: str | None) -> None:
        delay_idx = 0
        try:
            while True:
                try:
                    uri = f"ws://{ip}:{port}"
                    async with websockets.connect(uri, open_timeout=5) as ws:
                        session = await self._handshake(ws, ip)
                        if session is None:
                            break
                        if expected_hash and session.pub_key_hash != expected_hash:
                            break  # chave não bate — possível MITM

                        self._sessions[session.pub_key_hash] = session
                        delay_idx = 0
                        if self._on_connect:
                            self._on_connect(session)

                        flush_task = asyncio.create_task(session._flush())
                        try:
                            async for raw in ws:
                                if not isinstance(raw, bytes):
                                    continue
                                try:
                                    payload = json.loads(
                                        session.ratchet.decrypt(raw).decode()
                                    )
                                except Exception:
                                    break  # ratchet chain corrompida; força reconexão
                                if self._on_message:
                                    self._on_message(session, payload)
                        except websockets.exceptions.ConnectionClosed:
                            pass
                        finally:
                            flush_task.cancel()
                            self._sessions.pop(session.pub_key_hash, None)
                            if self._on_disconnect:
                                self._on_disconnect(session.pub_key_hash)

                except (OSError, websockets.exceptions.WebSocketException):
                    pass

                delay = RECONNECT_DELAYS[min(delay_idx, len(RECONNECT_DELAYS) - 1)]
                delay_idx += 1
                await asyncio.sleep(delay)
        finally:
            self._connecting.discard((ip, port))
