"""
Descoberta de peers na LAN via UDP broadcast.

Usa create_datagram_endpoint (compatível com uvloop usado pelo NiceGUI).
sock_sendto/sock_recvfrom não funcionam com uvloop — causa NotImplementedError.
"""

import asyncio
import json
import socket
import time
from dataclasses import dataclass, field
from typing import Callable

from identity import LocalIdentity

BROADCAST_PORT  = 47777
BEACON_INTERVAL = 5.0   # segundos entre broadcasts
TIMEOUT_S       = 30.0  # peer considerado fora do ar após 6 beacons perdidos


@dataclass
class PeerInfo:
    pub_key_hash:   str
    public_key_hex: str
    username:       str
    ip:             str
    ws_port:        int
    last_seen:      float = field(default_factory=time.time)
    connected:      bool  = False   # WebSocket ativo

    @property
    def online(self) -> bool:
        """Beacon recente — peer está na rede."""
        return (time.time() - self.last_seen) < TIMEOUT_S


class PeerRegistry:
    def __init__(self):
        self._peers: dict[str, PeerInfo] = {}
        self._callbacks: list[Callable[[PeerInfo, str], None]] = []

    def on_change(self, fn: Callable[[PeerInfo, str], None]) -> None:
        self._callbacks.append(fn)

    def _notify(self, peer: PeerInfo, event: str) -> None:
        for fn in self._callbacks:
            try:
                fn(peer, event)
            except Exception:
                pass

    def update(self, peer: PeerInfo) -> None:
        existing = self._peers.get(peer.pub_key_hash)
        if existing:
            peer.connected = existing.connected  # preserva estado WS
        was_offline = existing is None or not existing.online
        self._peers[peer.pub_key_hash] = peer
        if was_offline:
            self._notify(peer, "online")

    def mark_connected(self, pub_key_hash: str, connected: bool) -> None:
        peer = self._peers.get(pub_key_hash)
        if peer:
            peer.connected = connected

    def remove(self, pub_key_hash: str) -> None:
        """Remove peer imediatamente (beacon de bye recebido)."""
        peer = self._peers.pop(pub_key_hash, None)
        if peer:
            peer.connected = False
            self._notify(peer, "offline")

    def expire(self) -> None:
        for peer in list(self._peers.values()):
            if not peer.online:
                peer.connected = False
                del self._peers[peer.pub_key_hash]
                self._notify(peer, "offline")

    def all_online(self) -> list[PeerInfo]:
        """Peers visíveis na rede (beacon recente)."""
        return [p for p in self._peers.values() if p.online]

    def all_connected(self) -> list[PeerInfo]:
        """Peers com WebSocket ativo — podem receber mensagens agora."""
        return [p for p in self._peers.values() if p.connected]

    def get(self, pub_key_hash: str) -> PeerInfo | None:
        return self._peers.get(pub_key_hash)


# ---------------------------------------------------------------------------
# Protocolo UDP — usado com create_datagram_endpoint (compatível com uvloop)
# ---------------------------------------------------------------------------

class _ListenerProtocol(asyncio.DatagramProtocol):
    def __init__(self, discovery: "Discovery"):
        self._discovery = discovery
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        import hashlib
        ip = addr[0]
        try:
            payload = json.loads(data.decode())
        except Exception:
            return

        pub_key_hex  = payload.get("public_key_hex", "")
        pub_key_hash = payload.get("pub_key_hash", "")

        # Verifica que pub_key_hash é realmente SHA256(public_key_hex)[:32].
        # Impede beacons adulterados que atribuam um hash de outra identidade
        # a uma chave pública diferente, corrompendo o registry.
        try:
            expected_hash = hashlib.sha256(bytes.fromhex(pub_key_hex)).hexdigest()[:32]
        except Exception:
            return
        if pub_key_hash != expected_hash:
            return

        if pub_key_hash == self._discovery.identity.pub_key_hash:
            return  # ignora próprio beacon

        if payload.get("bye"):
            self._discovery.registry.remove(pub_key_hash)
            return

        peer = PeerInfo(
            pub_key_hash=pub_key_hash,
            public_key_hex=pub_key_hex,
            username=payload.get("username", ""),
            ip=ip,
            ws_port=payload["ws_port"],
        )
        self._discovery.registry.update(peer)

    def error_received(self, exc: Exception) -> None:
        pass

    def connection_lost(self, exc: Exception | None) -> None:
        pass


class _SenderProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        sock = transport.get_extra_info("socket")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.transport = transport

    def error_received(self, exc: Exception) -> None:
        pass

    def connection_lost(self, exc: Exception | None) -> None:
        pass


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

class Discovery:
    def __init__(self, identity: LocalIdentity, ws_port: int, registry: PeerRegistry,
                 db_path=None):  # db_path kept for call-site compatibility, unused
        self.identity  = identity
        self.ws_port   = ws_port
        self.registry  = registry
        self._running  = False
        self._sender:   _SenderProtocol | None  = None
        self._listener: _ListenerProtocol | None = None

    def _make_beacon(self) -> bytes:
        return json.dumps({
            "pub_key_hash":   self.identity.pub_key_hash,
            "public_key_hex": self.identity.pub_key_bytes.hex(),
            "username":       self.identity.username,
            "ws_port":        self.ws_port,
            "ts":             time.time(),
        }).encode()

    async def _broadcast_loop(self) -> None:
        while self._running:
            if self._sender and self._sender.transport:
                try:
                    self._sender.transport.sendto(
                        self._make_beacon(), ("255.255.255.255", BROADCAST_PORT)
                    )
                except Exception:
                    pass
            await asyncio.sleep(BEACON_INTERVAL)

    async def _expire_loop(self) -> None:
        while self._running:
            await asyncio.sleep(BEACON_INTERVAL)
            self.registry.expire()

    async def start(self) -> None:
        self._running = True
        loop = asyncio.get_running_loop()

        # sender — socket UDP com SO_BROADCAST habilitado manualmente
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        send_sock.setblocking(False)
        _, sender_proto = await loop.create_datagram_endpoint(
            _SenderProtocol, sock=send_sock
        )
        self._sender = sender_proto

        # listener — bind em 0.0.0.0 para receber beacons
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        recv_sock.bind(("0.0.0.0", BROADCAST_PORT))
        recv_sock.setblocking(False)
        _, listener_proto = await loop.create_datagram_endpoint(
            lambda: _ListenerProtocol(self), sock=recv_sock
        )
        self._listener = listener_proto

        asyncio.create_task(self._broadcast_loop())
        asyncio.create_task(self._expire_loop())

    def stop(self) -> None:
        self._running = False
        if self._sender and self._sender.transport:
            bye = json.dumps({"bye": True, "pub_key_hash": self.identity.pub_key_hash}).encode()
            try:
                self._sender.transport.sendto(bye, ("255.255.255.255", BROADCAST_PORT))
            except Exception:
                pass
            self._sender.transport.close()
        if self._listener and self._listener.transport:
            self._listener.transport.close()

