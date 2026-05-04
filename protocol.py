"""
Protocolo de mensagens P2P do TeamFlow.

Todos os payloads são dicts JSON. O campo 'type' identifica o tipo.
A camada de transporte (peer_server/peer_client) cuida da criptografia — aqui
só definimos a estrutura e o dispatcher.

Tipos:
  chat          — DM entre dois peers
  group_msg     — mensagem de grupo (fan-out)
  group_state   — estado completo do grupo (sync de membros)
  invite        — convite para grupo
  join_request  — novo membro pedindo entrada após aceitar convite
  leave         — membro saindo de grupo
  dissolve      — admin apagando grupo
  ack           — confirmação de recebimento
"""

import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Any


# ---------------------------------------------------------------------------
# Construtores de payload
# ---------------------------------------------------------------------------

def make_chat(sender_hash: str, sender_name: str, text: str) -> dict:
    return {
        "type":        "chat",
        "uuid":        str(uuid.uuid4()),
        "sender_hash": sender_hash,
        "sender_name": sender_name,
        "text":        text,
        "ts":          time.time(),
    }


def make_group_msg(sender_hash: str, sender_name: str, group_id: str, text: str) -> dict:
    return {
        "type":        "group_msg",
        "uuid":        str(uuid.uuid4()),
        "sender_hash": sender_hash,
        "sender_name": sender_name,
        "group_id":    group_id,
        "text":        text,
        "ts":          time.time(),
    }


def make_ack(msg_uuid: str) -> dict:
    return {"type": "ack", "uuid": msg_uuid}


def make_group_state_payload(group_state_dict: dict) -> dict:
    return {"type": "group_state", "state": group_state_dict}


def make_join_request(group_id: str, pub_key_hex: str, username: str) -> dict:
    return {
        "type":        "join_request",
        "group_id":    group_id,
        "pub_key_hex": pub_key_hex,
        "username":    username,
    }


def make_leave(group_id: str, pub_key_hex: str) -> dict:
    return {"type": "leave", "group_id": group_id, "pub_key_hex": pub_key_hex}


def make_dissolve(group_id: str) -> dict:
    return {"type": "dissolve", "group_id": group_id}


def make_ping(uid: str) -> dict:
    return {"type": "ping", "uuid": uid, "ts": time.time()}


def make_pong(uid: str) -> dict:
    return {"type": "pong", "uuid": uid, "ts": time.time()}


def make_file_offer(file_id: str, sender_name: str, filename: str,
                    size: int, total_chunks: int) -> dict:
    return {
        "type":         "file_offer",
        "file_id":      file_id,
        "sender_name":  sender_name,
        "filename":     filename,
        "size":         size,
        "total_chunks": total_chunks,
    }


def make_file_chunk(file_id: str, index: int, total: int, data_b64: str) -> dict:
    return {
        "type":    "file_chunk",
        "file_id": file_id,
        "index":   index,
        "total":   total,
        "data":    data_b64,
    }


def make_file_accept(file_id: str) -> dict:
    return {"type": "file_accept", "file_id": file_id}


def make_file_reject(file_id: str) -> dict:
    return {"type": "file_reject", "file_id": file_id}


# ---------------------------------------------------------------------------
# Dispatcher — roteamento de mensagens recebidas
# ---------------------------------------------------------------------------

Handler = Callable[[dict, Any], None]  # (payload, session)


class Dispatcher:
    def __init__(self):
        self._handlers: dict[str, list[Handler]] = {}

    def register(self, msg_type: str, fn: Handler) -> None:
        self._handlers.setdefault(msg_type, []).append(fn)

    def dispatch(self, payload: dict, session: Any) -> None:
        msg_type = payload.get("type", "")
        for fn in self._handlers.get(msg_type, []):
            try:
                fn(payload, session)
            except Exception:
                pass
        for fn in self._handlers.get("*", []):
            try:
                fn(payload, session)
            except Exception:
                pass
