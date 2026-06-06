"""
Nó P2P — orquestra todos os serviços para um único usuário.

Ciclo de vida típico:
    node = Node()
    node.set_identity(identity)   # chamado pela TUI após autenticação
    await node.start()
    ...
    await node.stop()

set_identity() deve ser chamado antes de start(). Isso permite que a TUI
gerencie o fluxo de autenticação (senha, TOFU, setup inicial) antes de
iniciar os serviços de rede.
"""

import asyncio
import hashlib
import time
import uuid as _uuid
from pathlib import Path
from typing import Callable, Any, TYPE_CHECKING

from crypto import encrypt as _group_encrypt, decrypt as _group_decrypt
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
    make_leave, make_ping, make_pong,
    make_file_offer, make_file_chunk, make_file_accept, make_file_reject,
    make_voice_start, make_voice_frame, make_voice_end,
)
from wordlist import pub_to_words

WS_PORT = 47778

_GROUP_AAD = b"group-msg"


def _file_msg(text: str) -> Message:
    return Message(uuid=_uuid.uuid4().hex, sender_hash="", sender_name="📎", text=text)


class Node:
    def __init__(self) -> None:
        self.identity:  LocalIdentity | None  = None   # definido via set_identity()
        self.registry   = PeerRegistry()
        self.store      = MessageStore()
        self.server:    PeerServer | None     = None
        self.client:    PeerClient | None     = None
        self.groups:    GroupManager | None   = None
        self.discovery: Discovery | None      = None

        # alertas TOFU pendentes: pub_key_hash → {username, pub_key_hex, words}
        self.tofu_alerts: dict[str, dict] = {}

        self._callbacks: list[Callable[[str, Any], None]] = []
        self._pending_pings: dict[str, tuple[float, asyncio.Future]] = {}
        self._incoming_offers: dict[str, Any] = {}
        self._outgoing_transfers: dict[str, asyncio.Future] = {}
        self._start_time: float = 0.0

        # PTT — push-to-talk
        self._ptt_conv:   str | None = None   # conv_id em transmissão
        self._ptt_engine: object     = None   # PTTEngine, lazy
        self._player:     object     = None   # _Player, lazy
        self._speakers:   dict[str, str] = {} # conv_id → pub_key_hash do falante

    # ------------------------------------------------------------------
    # Identidade — configurada pela TUI após autenticação
    # ------------------------------------------------------------------

    def set_identity(self, identity: LocalIdentity) -> None:
        """
        Vincula identidade e instancia server/client. Deve ser chamado
        antes de start(). Pode ser chamado apenas uma vez.
        """
        self.identity = identity
        self.server   = PeerServer(identity, WS_PORT)
        self.client   = PeerClient(identity)
        self._wire()
        self.registry.on_change(self._on_peer_change)

    # ------------------------------------------------------------------
    # Ciclo de vida
    # ------------------------------------------------------------------

    async def start(self) -> None:
        assert self.identity is not None, "set_identity() deve ser chamado antes de start()"
        db_path = user_db_path(self.identity.username)
        init_db(db_path)
        self.identity._db_path = db_path

        self._start_time = time.time()
        self.groups = GroupManager(self.identity, db_path=db_path)
        self.groups.load_from_db()

        self.discovery = Discovery(self.identity, WS_PORT, self.registry)
        await self.server.start()
        await self.discovery.start()

    async def stop(self) -> None:
        if self._ptt_conv:
            self.stop_ptt()
        if self._player:
            self._player.close()
            self._player = None
        if self.discovery:
            self.discovery.stop()
        if self.server:
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
        offer = self._incoming_offers.pop(pub_key_hash, None)
        if offer:
            offer.abort()
            self.store.add(pub_key_hash, _file_msg(
                f"[red]{offer.filename}: transferência interrompida (peer desconectou)[/red]"
            ))
        if self._player:
            self._player.flush(pub_key_hash)
        stale = [cid for cid, h in self._speakers.items() if h == pub_key_hash]
        for cid in stale:
            self._speakers.pop(cid, None)
            self._emit("voice_end", {"conv_id": cid, "name": ""})
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
        status, details = tofu_check(
            session.pub_key_hash,
            session.public_key_hex,
            session.username,
            self.identity._db_path,
        )
        if status == "hijacked":
            # Nick em uso por chave diferente da conhecida — possível personificação.
            known_hex = details["known_key_hex"]
            self.tofu_alerts[session.pub_key_hash] = {
                "alert_type":    "hijacked",
                "username":      details["username"],
                "pub_key_hex":   session.public_key_hex,
                "words":         pub_to_words(session.public_key_hex),
                "known_hash":    details["known_hash"],
                "known_key_hex": known_hex,
                "known_words":   pub_to_words(known_hex) if known_hex else "desconhecida",
            }
        elif status == "renamed":
            # Mesma chave, nick diferente — atualiza DB e emite notificação não-bloqueante.
            tofu_update(session.pub_key_hash, session.public_key_hex, session.username,
                        self.identity._db_path)
            self._emit("peer_renamed", {
                "pub_key_hash": session.pub_key_hash,
                "old_username": details["old_username"],
                "new_username": details["new_username"],
            })

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
            # sender_hash e sender_name vêm da sessão verificada, não do payload —
            # o payload poderia conter qualquer valor forjado pelo remetente.
            msg = Message(uuid=payload["uuid"],
                          sender_hash=session.pub_key_hash,
                          sender_name=session.username,
                          text=payload["text"],
                          ts=payload["ts"])
            self.store.add(session.pub_key_hash, msg)
            self._send(session.pub_key_hash, make_ack(payload["uuid"]))
            self._emit("message", session.pub_key_hash)

        elif t == "group_msg":
            gs = self.groups.get(payload.get("group_id")) if self.groups else None
            if gs is None:
                return
            try:
                enc_bytes = bytes.fromhex(payload["text"])
                text = _group_decrypt(
                    bytes.fromhex(gs.group_key_hex), enc_bytes, aad=_GROUP_AAD
                ).decode("utf-8")
            except Exception:
                return  # chave de grupo incompatível (ex.: mensagem anterior ao kick)
            # Idem: usa identidade verificada da sessão, não os campos do payload.
            msg = Message(uuid=payload["uuid"],
                          sender_hash=session.pub_key_hash,
                          sender_name=session.username,
                          text=text,
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
                # Verifica que pub_key_hex do payload bate com a chave autenticada
                # da sessão — impede que um peer adicione outro ao grupo em seu lugar.
                if payload.get("pub_key_hex") != session.public_key_hex:
                    return
                new_state = self.groups.add_member(
                    payload["group_id"], session.public_key_hex, session.username)
                if new_state:
                    self._broadcast_group(new_state)
            self._emit("groups_changed")

        elif t == "leave":
            gs = self.groups.get(payload.get("group_id")) if self.groups else None
            if gs and self.groups.am_admin(gs.group_id):
                # Usa a chave autenticada da sessão — ignora pub_key_hex do payload,
                # que poderia ser forjado para remover outros membros.
                new_state = self.groups.remove_member(gs.group_id, session.public_key_hex)
                if new_state:
                    self._broadcast_group(new_state)
            self._emit("groups_changed")

        elif t == "dissolve":
            if self.groups:
                self.groups.apply_dissolve(payload)
            self._emit("group_dissolved", payload.get("group_id"))

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
            idx = payload.get("index")
            if not isinstance(idx, int) or not (0 <= idx < offer.total_chunks):
                return
            try:
                raw = _b64.b64decode(payload["data"])
            except Exception:
                return  # chunk base64 inválido — ignora
            try:
                offer.write_chunk(idx, raw)
            except OSError as e:
                offer.abort()
                self._incoming_offers.pop(peer_hash, None)
                self.store.add(peer_hash, _file_msg(
                    f"[red]{offer.filename}: erro de disco — {e}[/red]"
                ))
                return
            if offer.complete:
                try:
                    saved = offer.finalize()
                except OSError as e:
                    offer.abort()
                    self._incoming_offers.pop(peer_hash, None)
                    self.store.add(peer_hash, _file_msg(
                        f"[red]{offer.filename}: falha ao salvar — {e}[/red]"
                    ))
                    return
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

        elif t == "voice_start":
            conv_id = payload.get("conv_id", "")
            # Valida que o remetente pertence à conversa que declara.
            gs = self.groups.get(conv_id) if self.groups else None
            if gs:
                if session.pub_key_hash not in gs.member_hashes:
                    return
            elif conv_id != session.pub_key_hash:
                return
            self._speakers[conv_id] = session.pub_key_hash
            self._emit("voice_start", {"conv_id": conv_id, "name": session.username})

        elif t == "voice_frame":
            if self._player is None:
                try:
                    from voice import _Player
                    self._player = _Player()
                except Exception:
                    self._player = False  # sentinel: sem saída de áudio, não tenta mais
            if not self._player:
                return
            self._player.feed(session.pub_key_hash, payload.get("data", ""))

        elif t == "voice_end":
            conv_id = payload.get("conv_id", "")
            # Mesma validação de conv_id.
            gs = self.groups.get(conv_id) if self.groups else None
            if gs:
                if session.pub_key_hash not in gs.member_hashes:
                    return
            elif conv_id != session.pub_key_hash:
                return
            if self._player:
                self._player.flush(session.pub_key_hash)
            self._speakers.pop(conv_id, None)
            self._emit("voice_end", {"conv_id": conv_id, "name": session.username})

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
        # Cifra o texto com a group_key antes de enviar (camada sobre o ratchet de sessão).
        # Quando um membro é removido e a group_key rotaciona, mensagens anteriores
        # capturadas pelo membro removido não podem ser decifradas com a nova chave.
        enc_text = _group_encrypt(
            bytes.fromhex(gs.group_key_hex), text.encode("utf-8"), aad=_GROUP_AAD
        ).hex()
        payload = make_group_msg(self.identity.pub_key_hash, self.identity.username,
                                  group_id, enc_text)
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
        if not self.groups:
            return
        gs = self.groups.get(group_id)
        if gs is None or not self.groups.am_admin(group_id):
            return
        # delete_group() assina o dissolve e remove o grupo localmente;
        # gs é salvo antes para manter a lista de membros para o broadcast.
        signed_payload = self.groups.delete_group(group_id)
        if signed_payload:
            self._broadcast_group_raw(gs, signed_payload)

    def _broadcast_group(self, state: GroupState) -> None:
        payload = make_group_state_payload(state.to_dict())
        my_hex = self.identity.pub_key_bytes.hex()
        for member in state.members:
            if member.pub_key_hex != my_hex:
                self._send(self._hash_of(member.pub_key_hex), payload)

    def _broadcast_group_raw(self, state: GroupState, payload: dict) -> None:
        my_hex = self.identity.pub_key_bytes.hex()
        for member in state.members:
            if member.pub_key_hex != my_hex:
                self._send(self._hash_of(member.pub_key_hex), payload)

    async def send_file(self, peer_hash: str, path: Path) -> None:
        from file_transfer import iter_chunks, chunk_count, human_size, OFFER_TIMEOUT, SEND_WINDOW
        size = path.stat().st_size
        if size == 0:
            self.store.add(peer_hash, _file_msg(f"[red]{path.name}: arquivo vazio, envio não suportado.[/red]"))
            return
        total   = chunk_count(path)   # calcula sem ler o arquivo
        file_id = _uuid.uuid4().hex[:12]

        self.store.add(peer_hash, _file_msg(
            f"Enviando [bold]{path.name}[/bold] ({human_size(size)})…"
        ))
        fut = asyncio.get_running_loop().create_future()
        self._outgoing_transfers[file_id] = fut
        self._send(peer_hash, make_file_offer(
            file_id, self.identity.username, path.name, size, total
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

        # iter_chunks lê CHUNK_SIZE bytes por vez — sem carregar o arquivo inteiro na RAM.
        # Cede o event loop a cada SEND_WINDOW chunks para não monopolizar a task.
        for i, data_b64 in enumerate(iter_chunks(path)):
            self._send(peer_hash, make_file_chunk(file_id, i, total, data_b64))
            if (i + 1) % SEND_WINDOW == 0:
                await asyncio.sleep(0)

        self.store.add(peer_hash, _file_msg(f"[green]{path.name} enviado ✓[/green]"))

    def accept_file(self, peer_hash: str) -> None:
        offer = self._incoming_offers.get(peer_hash)
        if not offer:
            return
        try:
            offer.open_tmp()
        except OSError as e:
            self._incoming_offers.pop(peer_hash, None)
            self.store.add(peer_hash, _file_msg(
                f"[red]{offer.filename}: não foi possível criar arquivo temporário — {e}[/red]"
            ))
            return
        self._send(peer_hash, make_file_accept(offer.file_id))
        self.store.add(peer_hash, _file_msg(f"Recebendo [bold]{offer.filename}[/bold]…"))

    def reject_file(self, peer_hash: str) -> None:
        offer = self._incoming_offers.pop(peer_hash, None)
        if not offer:
            return
        offer.abort()
        self._send(peer_hash, make_file_reject(offer.file_id))
        self.store.add(peer_hash, _file_msg(f"[yellow]{offer.filename} recusado[/yellow]"))

    def send_ping(self, peer_hash: str) -> asyncio.Future:
        # Remove entradas sem resposta há mais de 30 s (evita acúmulo indefinido)
        now = time.time()
        stale = [k for k, (ts, _) in self._pending_pings.items() if now - ts > 30]
        for k in stale:
            self._pending_pings.pop(k)

        uid = _uuid.uuid4().hex[:12]
        fut = asyncio.get_running_loop().create_future()
        self._pending_pings[uid] = (now, fut)
        self._send(peer_hash, make_ping(uid))
        return fut

    # ------------------------------------------------------------------
    # PTT — push-to-talk
    # ------------------------------------------------------------------

    @property
    def ptt_active(self) -> bool:
        return self._ptt_conv is not None

    def start_ptt(self, conv_id: str) -> bool:
        """Inicia transmissão PTT. Retorna False se não for possível abrir o microfone."""
        if self._ptt_conv:
            return False
        try:
            from voice import PTTEngine
            if self._ptt_engine is None:
                self._ptt_engine = PTTEngine(self._on_ptt_frame)
            self._ptt_engine.start(asyncio.get_running_loop())
        except Exception:
            return False
        self._ptt_conv = conv_id
        self._send_voice_to_conv(conv_id, make_voice_start(conv_id, self.identity.pub_key_hash))
        self._emit("ptt_started", conv_id)
        return True

    def stop_ptt(self) -> None:
        conv_id = self._ptt_conv
        if not conv_id:
            return
        self._ptt_conv = None
        if self._ptt_engine:
            self._ptt_engine.stop()
        self._send_voice_to_conv(conv_id, make_voice_end(conv_id, self.identity.pub_key_hash))
        self._emit("ptt_stopped", conv_id)

    def _on_ptt_frame(self, b64: str) -> None:
        conv_id = self._ptt_conv
        if not conv_id:
            return
        self._send_voice_to_conv(
            conv_id, make_voice_frame(conv_id, self.identity.pub_key_hash, b64)
        )

    def _send_voice_to_conv(self, conv_id: str, payload: dict) -> None:
        """Fan-out para todos os membros de grupo ou envio direto para DM."""
        gs = self.groups.get(conv_id) if self.groups else None
        if gs:
            my_hex = self.identity.pub_key_bytes.hex()
            for member in gs.members:
                if member.pub_key_hex != my_hex:
                    self._send(self._hash_of(member.pub_key_hex), payload)
        else:
            self._send(conv_id, payload)

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
