"""
Servidor WebSocket P2P.

Cada peer roda este servidor. Quando outro peer conecta:
  1. Handshake X25519  → deriva session_key
  2. Auth challenge    → peer remoto assina um nonce com sua Ed25519 private_key
  3. Troca de mensagens criptografadas com ChaCha20-Poly1305

Protocolo de handshake (binário, frames separados):
  → HELLO  : pub_key_x25519(32) + pub_key_ed25519(32) + username_utf8
  ← HELLO  : pub_key_x25519(32) + pub_key_ed25519(32) + username_utf8
  → CHALLENGE: nonce(32)
  ← RESPONSE : sig_ed25519(64)   assinatura do nonce pelo cliente
  ← OK / REJECT

Após handshake, todas as frames são:
  encrypt(session_key, json_payload)
"""

import asyncio
import json
import os
from dataclasses import dataclass
from typing import Callable

import websockets
from websockets.server import WebSocketServerProtocol

from crypto import (
    generate_session_keypair,
    x25519_exchange,
    x25519_public_to_bytes,
    public_key_from_bytes,
    derive_session_key,
    verify,
    public_key_to_bytes,
)
from identity import LocalIdentity
from ratchet import RatchetState, init_ratchet

HANDSHAKE_TIMEOUT = 10.0


@dataclass
class PeerSession:
    pub_key_hash:  str
    public_key_hex: str
    username:      str
    ratchet:       RatchetState
    ws:            WebSocketServerProtocol

    async def send(self, payload: dict) -> None:
        data = self.ratchet.encrypt(json.dumps(payload).encode())
        await self.ws.send(data)

    async def recv(self) -> dict:
        raw = await self.ws.recv()
        return json.loads(self.ratchet.decrypt(raw).decode())


class PeerServer:
    def __init__(self, identity: LocalIdentity, port: int):
        self.identity  = identity
        self.port      = port
        self._sessions: dict[str, PeerSession] = {}
        self._on_message: Callable[[PeerSession, dict], None] | None = None
        self._on_connect: Callable[[PeerSession], None] | None = None
        self._on_disconnect: Callable[[str], None] | None = None
        self._server = None

    def on_message(self, fn: Callable[[PeerSession, dict], None]) -> None:
        self._on_message = fn

    def on_connect(self, fn: Callable[[PeerSession], None]) -> None:
        self._on_connect = fn

    def on_disconnect(self, fn: Callable[[str], None]) -> None:
        self._on_disconnect = fn

    def get_session(self, pub_key_hash: str) -> PeerSession | None:
        return self._sessions.get(pub_key_hash)

    def all_sessions(self) -> list[PeerSession]:
        return list(self._sessions.values())

    async def _handshake(self, ws: WebSocketServerProtocol) -> PeerSession | None:
        try:
            my_x_priv, my_x_pub = generate_session_keypair()
            my_ed_pub_bytes      = public_key_to_bytes(self.identity.public_key)
            my_hello             = (
                x25519_public_to_bytes(my_x_pub)
                + my_ed_pub_bytes
                + self.identity.username.encode("utf-8")
            )
            await asyncio.wait_for(ws.send(my_hello), HANDSHAKE_TIMEOUT)

            peer_hello = await asyncio.wait_for(ws.recv(), HANDSHAKE_TIMEOUT)
            if not isinstance(peer_hello, bytes) or len(peer_hello) < 64:
                return None

            peer_x_pub_bytes  = peer_hello[:32]
            peer_ed_pub_bytes = peer_hello[32:64]
            peer_username     = peer_hello[64:128].decode("utf-8", errors="replace").strip()

            shared = x25519_exchange(my_x_priv, peer_x_pub_bytes)
            session_key = derive_session_key(
                shared,
                x25519_public_to_bytes(my_x_pub),
                peer_x_pub_bytes,
            )

            nonce = os.urandom(32)
            await asyncio.wait_for(ws.send(nonce), HANDSHAKE_TIMEOUT)

            sig = await asyncio.wait_for(ws.recv(), HANDSHAKE_TIMEOUT)
            if not isinstance(sig, bytes):
                return None

            peer_ed_pub = public_key_from_bytes(peer_ed_pub_bytes)
            if not verify(peer_ed_pub, sig, nonce):
                await ws.send(b"REJECT")
                return None

            await asyncio.wait_for(ws.send(b"OK"), HANDSHAKE_TIMEOUT)

            import hashlib
            pk_hash = hashlib.sha256(peer_ed_pub_bytes).hexdigest()[:32]

            return PeerSession(
                pub_key_hash=pk_hash,
                public_key_hex=peer_ed_pub_bytes.hex(),
                username=peer_username,
                ratchet=init_ratchet(session_key, is_initiator=True),
                ws=ws,
            )
        except Exception:
            return None

    async def _handle(self, ws: WebSocketServerProtocol) -> None:
        session = await self._handshake(ws)
        if session is None:
            return

        self._sessions[session.pub_key_hash] = session
        if self._on_connect:
            self._on_connect(session)

        try:
            async for raw in ws:
                if not isinstance(raw, bytes):
                    continue
                try:
                    payload = json.loads(session.ratchet.decrypt(raw).decode())
                except Exception:
                    continue
                if self._on_message:
                    self._on_message(session, payload)
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self._sessions.pop(session.pub_key_hash, None)
            if self._on_disconnect:
                self._on_disconnect(session.pub_key_hash)

    async def start(self) -> None:
        self._server = await websockets.serve(self._handle, "0.0.0.0", self.port)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
