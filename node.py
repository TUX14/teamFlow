"""
Nó P2P — orquestra todos os serviços para um único usuário.

Uso:
    identity = load_or_create()
    node = Node(identity)
    await node.start()
    ...
    await node.stop()
"""

import asyncio
import hashlib
import time
import uuid as _uuid
from pathlib import Path
from typing import Callable, Any

from db import user_db_path, init_db, tofu_check, tofu_update
from identity import LocalIdentity
from discovery import Discovery, PeerRegistry, PeerInfo
from peer_server import PeerServer
from peer_client import PeerClient
from message_store import MessageStore, Message
from groups import GroupManager, GroupState
from protocol import (
    make_chat, make_group_msg, make_ack,
    make_group_state_payload, make_join_request,
    make_leave, make_dissolve, make_ping, make_pong,
    make_file_offer, make_file_chunk, make_file_accept, make_file_reject,
)
from wordlist import pub_to_words

WS_PORT = 47778


def _file_msg(text: str) -> "Message":
    from message_store import Message
    return Message(uuid=_uuid.uuid4().hex, sender_hash="", sender_name="📎", text=text)


class Node:
    def __init__(self, identity: LocalIdentity) -> None:
        self.identity  = identity
        self.registry  = PeerRegistry()
        self.store     = MessageStore()
        self.server    = PeerServer(identity, WS_PORT)
        self.client    = PeerClient(identity)
        self.groups: GroupManager | None = None
        self.discovery: Discovery | None = None

        # alertas TOFU pendentes: pub_key_hash → {username, pub_key_hex, words}
        self.tofu_alerts: dict[str, dict] = {}

        self._callbacks: list[Callable[[str, Any], None]] = []
        self._pending_pings: dict[str, tuple[float, asyncio.Future]] = {}
        self._incoming_offers: dict[str, Any] = {}   # peer_hash → IncomingOffer
        self._outgoing_transfers: dict[str, asyncio.Future] = {}  # file_id → Future
        self._start_time: float = 0.0

    # ------------------------------------------------------------------
    # Ciclo de vida
    # ------------------------------------------------------------------

    async def start(self) -> None:
        db_path = user_db_path(self.identity.username)
        init_db(db_path)
        self.identity._db_path = db_path

        self._start_time = time.time()
        self.groups = GroupManager(self.identity, db_path=db_path)
        self.groups.load_from_db()

        self._wire()
        self.registry.on_change(self._on_peer_change)
        self.discovery = Discovery(self.identity, WS_PORT, self.registry, db_path=db_path)

        await self.server.start()
        await self.discovery.start()

    async def stop(self) -> None:
        if self.discovery:
            self.discovery.stop()
        await self.server.stop()

    # ------------------------------------------------------------------
    # Eventos para a UI
    # ------------------------------------------------------------------

    def on_event(self, fn: Callable[[str, Any], None]) -> None:
        self._callbacks.append(fn)

    def _emit(self, event: str, data: Any = None) -> None:
        for fn in self._callbacks:
            try:
                fn(event, data)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Wiring interno
    # ------------------------------------------------------------------

    def _wire(self) -> None:
        self.server.on_connect(self._on_connect)
        self.server.on_disconnect(self._on_disconnect)
        self.server.on_message(lambda s, p: self._handle(p, s))
        self.client.on_connect(self._on_connect)
        self.client.on_disconnect(self._on_disconnect)
        self.client.on_message(lambda s, p: self._handle(p, s))

    def _on_connect(self, session) -> None:
        self.registry.mark_connected(session.pub_key_hash, True)
        self._check_tofu(session)
        if self.identity and self.groups:
            my_hex = self.identity.pub_key_bytes.hex()
            for gs in self.groups.all():
                if gs.admin_pub_key_hex == my_hex and session.pub_key_hash in gs.member_hashes:
                    self._send(session.pub_key_hash, make_group_state_payload(gs.to_dict()))
        self._emit("peers_changed")

    def _on_disconnect(self, pub_key_hash: str) -> None:
        self.registry.mark_connected(pub_key_hash, False)
        peer = self.registry.get(pub_key_hash)
        if peer and peer.online:
            self.client.connect_to(peer.ip, peer.ws_port, peer.pub_key_hash)
        self._emit("peers_changed")

    def _on_peer_change(self, peer: PeerInfo, event: str) -> None:
        if event == "online":
            self.client.connect_to(peer.ip, peer.ws_port, peer.pub_key_hash)
        self._emit("peers_changed")

    # ------------------------------------------------------------------
    # TOFU
    # ------------------------------------------------------------------

    def _check_tofu(self, session) -> None:
        result = tofu_check(
            session.pub_key_hash,
            session.public_key_hex,
            session.username,
            self.identity._db_path,
        )
        if result == "changed":
            self.tofu_alerts[session.pub_key_hash] = {
                "username":    session.username,
                "pub_key_hex": session.public_key_hex,
                "words":       pub_to_words(session.public_key_hex),
            }

    def dismiss_tofu(self, pub_key_hash: str) -> None:
        alert = self.tofu_alerts.pop(pub_key_hash, None)
        if alert and self.identity:
            tofu_update(pub_key_hash, alert["pub_key_hex"], alert["username"],
                        self.identity._db_path)

    # ------------------------------------------------------------------
    # Roteamento de mensagens recebidas
    # ------------------------------------------------------------------

    def _handle(self, payload: dict, session) -> None:
        t = payload.get("type")

        if t == "chat":
            msg = Message(uuid=payload["uuid"], sender_hash=payload["sender_hash"],
                          sender_name=payload["sender_name"], text=payload["text"],
                          ts=payload["ts"])
            self.store.add(session.pub_key_hash, msg)
            self._send(session.pub_key_hash, make_ack(payload["uuid"]))
            self._emit("message", session.pub_key_hash)

        elif t == "group_msg":
            gs = self.groups.get(payload.get("group_id")) if self.groups else None
            if gs is None:
                return
            msg = Message(uuid=payload["uuid"], sender_hash=payload["sender_hash"],
                          sender_name=payload["sender_name"], text=payload["text"],
                          ts=payload["ts"])
            self.store.add(gs.group_id, msg)
            self._emit("message", gs.group_id)

        elif t == "group_state":
            if self.groups:
                self.groups.apply_state(GroupState.from_dict(payload["state"]))
            self._emit("groups_changed")

        elif t == "invite":
            if self.groups:
                state = self.groups.accept_invite(payload)
                if state:
                    jr = make_join_request(state.group_id,
                                           self.identity.pub_key_bytes.hex(),
                                           self.identity.username)
                    self._send(self._hash_of(state.admin_pub_key_hex), jr)
            self._emit("groups_changed")

        elif t == "join_request":
            if self.groups and self.groups.am_admin(payload["group_id"]):
                new_state = self.groups.add_member(
                    payload["group_id"], payload["pub_key_hex"], payload["username"])
                if new_state:
                    self._broadcast_group(new_state)
            self._emit("groups_changed")

        elif t == "leave":
            gs = self.groups.get(payload.get("group_id")) if self.groups else None
            if gs and self.groups.am_admin(gs.group_id):
                new_state = self.groups.remove_member(gs.group_id, payload["pub_key_hex"])
                if new_state:
                    self._broadcast_group(new_state)
            self._emit("groups_changed")

        elif t == "dissolve":
            if self.groups:
                self.groups.apply_dissolve(payload)
            self._emit("groups_changed")

        elif t == "file_offer":
            from file_transfer import IncomingOffer, human_size
            offer = IncomingOffer(
                file_id      = payload["file_id"],
                sender_name  = payload["sender_name"],
                filename     = payload["filename"],
                size         = payload["size"],
                total_chunks = payload["total_chunks"],
            )
            self._incoming_offers[session.pub_key_hash] = offer
            self.store.add(session.pub_key_hash, _file_msg(
                f"[bold]{offer.sender_name}[/bold] quer enviar "
                f"[bold]{offer.filename}[/bold] ({human_size(offer.size)})\n"
                f"  /accept para receber · /reject para recusar"
            ))
            self._emit("file_offer", offer)

        elif t == "file_chunk":
            import base64 as _b64
            peer_hash = session.pub_key_hash
            offer = self._incoming_offers.get(peer_hash)
            if offer is None or offer.file_id != payload["file_id"]:
                return
            offer.chunks[payload["index"]] = _b64.b64decode(payload["data"])
            if offer.complete:
                from file_transfer import save_file
                saved = save_file(offer.filename, offer.reassemble())
                self._incoming_offers.pop(peer_hash)
                self.store.add(peer_hash, _file_msg(
                    f"[green]{offer.filename} salvo em {saved}[/green]"
                ))

        elif t == "file_accept":
            fut = self._outgoing_transfers.pop(payload["file_id"], None)
            if fut and not fut.done():
                fut.set_result(True)

        elif t == "file_reject":
            fut = self._outgoing_transfers.pop(payload["file_id"], None)
            if fut and not fut.done():
                fut.set_result(False)

        elif t == "ping":
            self._send(session.pub_key_hash, make_pong(payload["uuid"]))

        elif t == "pong":
            uid = payload.get("uuid", "")
            if uid in self._pending_pings:
                sent_ts, fut = self._pending_pings.pop(uid)
                if not fut.done():
                    fut.set_result((time.time() - sent_ts) * 1000)

    # ------------------------------------------------------------------
    # Envio
    # ------------------------------------------------------------------

    def _hash_of(self, pub_key_hex: str) -> str:
        return hashlib.sha256(bytes.fromhex(pub_key_hex)).hexdigest()[:32]

    def _send(self, pub_key_hash: str, payload: dict) -> None:
        session = (self.server.get_session(pub_key_hash)
                   or self.client.get_session(pub_key_hash))
        if session:
            asyncio.create_task(session.send(payload))

    def send_dm(self, peer_hash: str, text: str) -> None:
        payload = make_chat(self.identity.pub_key_hash, self.identity.username, text)
        self.store.add(peer_hash, Message(
            uuid=payload["uuid"], sender_hash=self.identity.pub_key_hash,
            sender_name=self.identity.username, text=text, is_mine=True,
            ts=payload["ts"]))
        self._send(peer_hash, payload)

    def send_group_msg(self, group_id: str, text: str) -> None:
        gs = self.groups.get(group_id) if self.groups else None
        if gs is None:
            return
        payload = make_group_msg(self.identity.pub_key_hash, self.identity.username,
                                  group_id, text)
        self.store.add(group_id, Message(
            uuid=payload["uuid"], sender_hash=self.identity.pub_key_hash,
            sender_name=self.identity.username, text=text, is_mine=True,
            ts=payload["ts"]))
        my_hex = self.identity.pub_key_bytes.hex()
        for member in gs.members:
            if member.pub_key_hex != my_hex:
                self._send(self._hash_of(member.pub_key_hex), payload)

    def send_invite(self, group_id: str, peer_hash: str) -> None:
        peer = self.registry.get(peer_hash)
        if peer and self.groups:
            token = self.groups.create_invite(group_id, peer.public_key_hex, peer.username)
            if token:
                self._send(peer_hash, token)

    def leave_group(self, group_id: str) -> None:
        gs = self.groups.get(group_id) if self.groups else None
        if gs is None:
            return
        admin_hash = self._hash_of(gs.admin_pub_key_hex)
        self._send(admin_hash, make_leave(group_id, self.identity.pub_key_bytes.hex()))
        self.groups.remove_local(group_id)

    def dissolve_group(self, group_id: str) -> None:
        gs = self.groups.get(group_id) if self.groups else None
        if gs is None or not self.groups.am_admin(group_id):
            return
        payload = make_dissolve(group_id)
        self._broadcast_group_raw(gs, payload)
        self.groups.remove_local(group_id)

    def _broadcast_group(self, state: GroupState) -> None:
        payload = make_group_state_payload(state.to_dict())
        my_hex = self.identity.pub_key_bytes.hex()
        for member in state.members:
            if member.pub_key_hex != my_hex:
                self._send(self._hash_of(member.pub_key_hex), payload)

    async def send_file(self, peer_hash: str, path: Path) -> None:
        from file_transfer import read_chunks, human_size, OFFER_TIMEOUT
        chunks  = read_chunks(path)
        file_id = _uuid.uuid4().hex[:12]
        size    = path.stat().st_size

        self.store.add(peer_hash, _file_msg(
            f"Enviando [bold]{path.name}[/bold] ({human_size(size)})…"
        ))
        fut = asyncio.get_running_loop().create_future()
        self._outgoing_transfers[file_id] = fut
        self._send(peer_hash, make_file_offer(
            file_id, self.identity.username, path.name, size, len(chunks)
        ))

        try:
            accepted = await asyncio.wait_for(asyncio.shield(fut), timeout=OFFER_TIMEOUT)
        except asyncio.TimeoutError:
            self._outgoing_transfers.pop(file_id, None)
            self.store.add(peer_hash, _file_msg(f"[red]{path.name}: tempo esgotado[/red]"))
            return

        if not accepted:
            self.store.add(peer_hash, _file_msg(f"[yellow]{path.name} recusado[/yellow]"))
            return

        for i, data_b64 in enumerate(chunks):
            self._send(peer_hash, make_file_chunk(file_id, i, len(chunks), data_b64))
            await asyncio.sleep(0)  # cede o event loop entre chunks

        self.store.add(peer_hash, _file_msg(f"[green]{path.name} enviado ✓[/green]"))

    def accept_file(self, peer_hash: str) -> None:
        offer = self._incoming_offers.get(peer_hash)
        if not offer:
            return
        self._send(peer_hash, make_file_accept(offer.file_id))
        self.store.add(peer_hash, _file_msg(f"Recebendo [bold]{offer.filename}[/bold]…"))

    def reject_file(self, peer_hash: str) -> None:
        offer = self._incoming_offers.pop(peer_hash, None)
        if not offer:
            return
        self._send(peer_hash, make_file_reject(offer.file_id))
        self.store.add(peer_hash, _file_msg(f"[yellow]{offer.filename} recusado[/yellow]"))

    def send_ping(self, peer_hash: str) -> asyncio.Future:
        uid = hashlib.sha256(str(time.time()).encode()).hexdigest()[:12]
        fut = asyncio.get_running_loop().create_future()
        self._pending_pings[uid] = (time.time(), fut)
        self._send(peer_hash, make_ping(uid))
        return fut

    def kick_member(self, group_id: str, username: str) -> bool:
        gs = self.groups.get(group_id) if self.groups else None
        if not gs or not self.groups.am_admin(group_id):
            return False
        target = next((m for m in gs.members if m.username.lower() == username.lower()), None)
        if target is None:
            return False
        new_state = self.groups.remove_member(group_id, target.pub_key_hex)
        if new_state:
            self._broadcast_group(new_state)
        return True

    def _broadcast_group_raw(self, state: GroupState, payload: dict) -> None:
        my_hex = self.identity.pub_key_bytes.hex()
        for member in state.members:
            if member.pub_key_hex != my_hex:
                self._send(self._hash_of(member.pub_key_hex), payload)
