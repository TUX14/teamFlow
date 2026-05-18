"""
Lógica de grupos P2P.

GroupState é a fonte da verdade de um grupo. É assinado pelo admin com Ed25519.
Qualquer peer aceita um novo estado se version > atual E assinatura válida do admin.

Ao remover membro: group_key é rotacionada (forward secrecy).
Grupos sem membros são apagados do banco automaticamente.
"""

import hashlib
import json
import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from crypto import (
    sign,
    verify,
    public_key_from_bytes,
    public_key_to_bytes,
)
from db import save_group, load_all_groups, delete_group
from identity import LocalIdentity


@dataclass
class Member:
    pub_key_hex: str
    username:    str


@dataclass
class GroupState:
    group_id:         str
    name:             str
    admin_pub_key_hex: str
    members:          list[Member]
    group_key_hex:    str   # chave simétrica ChaCha20 para mensagens do grupo
    version:          int
    signature_hex:    str   # assinatura Ed25519 do admin sobre o canonical payload

    def to_dict(self) -> dict:
        return {
            "group_id":          self.group_id,
            "name":              self.name,
            "admin_pub_key_hex": self.admin_pub_key_hex,
            "members":           [{"pub_key_hex": m.pub_key_hex, "username": m.username} for m in self.members],
            "group_key_hex":     self.group_key_hex,
            "version":           self.version,
            "signature_hex":     self.signature_hex,
        }

    @staticmethod
    def from_dict(d: dict) -> "GroupState":
        return GroupState(
            group_id=d["group_id"],
            name=d["name"],
            admin_pub_key_hex=d["admin_pub_key_hex"],
            members=[Member(**m) for m in d["members"]],
            group_key_hex=d["group_key_hex"],
            version=d["version"],
            signature_hex=d["signature_hex"],
        )

    def canonical_bytes(self) -> bytes:
        """Payload determinístico usado para assinar/verificar."""
        payload = {
            "group_id":          self.group_id,
            "name":              self.name,
            "admin_pub_key_hex": self.admin_pub_key_hex,
            "members":           sorted(m.pub_key_hex for m in self.members),
            "group_key_hex":     self.group_key_hex,
            "version":           self.version,
        }
        return json.dumps(payload, sort_keys=True).encode()

    def is_valid_signature(self) -> bool:
        try:
            admin_pub = public_key_from_bytes(bytes.fromhex(self.admin_pub_key_hex))
            return verify(admin_pub, bytes.fromhex(self.signature_hex), self.canonical_bytes())
        except Exception:
            return False

    @property
    def member_hashes(self) -> set[str]:
        return {hashlib.sha256(bytes.fromhex(m.pub_key_hex)).hexdigest()[:32] for m in self.members}


def _sign_state(identity: LocalIdentity, state: GroupState) -> GroupState:
    sig = sign(identity.private_key, state.canonical_bytes())
    state.signature_hex = sig.hex()
    return state


class GroupManager:
    def __init__(self, identity: LocalIdentity, db_path: Path):
        self.identity = identity
        self._db_path = db_path
        self._groups: dict[str, GroupState] = {}
        self._on_update: list[Callable[[GroupState, str], None]] = []  # (state, event)

    def on_update(self, fn: Callable[[GroupState, str], None]) -> None:
        self._on_update.append(fn)

    def _notify(self, state: GroupState, event: str) -> None:
        for fn in self._on_update:
            try:
                fn(state, event)
            except Exception:
                pass

    def load_from_db(self) -> None:
        for d in load_all_groups(self.identity.db_key, self._db_path):
            state = GroupState.from_dict(d)
            self._groups[state.group_id] = state

    def _save(self, state: GroupState) -> None:
        save_group(self.identity.db_key, state.group_id, state.to_dict(), self._db_path)

    def _delete(self, group_id: str) -> None:
        self._groups.pop(group_id, None)
        delete_group(group_id, self._db_path)

    def remove_local(self, group_id: str) -> None:
        """Remove grupo do estado local e do banco (usado ao sair do grupo)."""
        self._delete(group_id)

    # ------------------------------------------------------------------
    # Criar grupo (apenas admin)
    # ------------------------------------------------------------------

    def create(self, name: str) -> GroupState:
        group_id  = str(uuid.uuid4())
        group_key = os.urandom(32).hex()
        me        = Member(pub_key_hex=self.identity.pub_key_bytes.hex(), username=self.identity.username)
        state = GroupState(
            group_id=group_id,
            name=name,
            admin_pub_key_hex=self.identity.pub_key_bytes.hex(),
            members=[me],
            group_key_hex=group_key,
            version=1,
            signature_hex="",
        )
        _sign_state(self.identity, state)
        self._groups[group_id] = state
        self._save(state)
        self._notify(state, "created")
        return state

    # ------------------------------------------------------------------
    # Aceitar GroupState recebido de outro peer (com validação)
    # ------------------------------------------------------------------

    def apply_state(self, new_state: GroupState) -> bool:
        """
        Aceita o novo estado se:
          1. Assinatura do admin é válida
          2. version > estado atual (ou grupo não existe ainda)
          3. Nosso pub_key está na lista de membros (ou estamos aceitando convite)
        Retorna True se aceito.
        """
        if not new_state.is_valid_signature():
            return False

        current = self._groups.get(new_state.group_id)
        if current and new_state.version <= current.version:
            return False

        my_hex = self.identity.pub_key_bytes.hex()
        if my_hex not in {m.pub_key_hex for m in new_state.members}:
            # fomos removidos — apagar grupo local
            self._delete(new_state.group_id)
            self._notify(new_state, "removed")
            return True

        self._groups[new_state.group_id] = new_state
        self._save(new_state)
        event = "joined" if current is None else "updated"
        self._notify(new_state, event)
        return True

    # ------------------------------------------------------------------
    # Convidar membro (qualquer membro pode convidar)
    # ------------------------------------------------------------------

    def create_invite(self, group_id: str, invitee_pub_key_hex: str, invitee_username: str) -> dict | None:
        """
        Retorna um InviteToken dict que deve ser enviado ao convidado via DM.
        O token contém o GroupState atual + info do convidado.
        Apenas o admin pode alterar o GroupState, então o convite só carrega
        o estado atual — o admin precisa depois emitir novo estado com o membro incluído.
        """
        state = self._groups.get(group_id)
        if state is None:
            return None
        my_hex = self.identity.pub_key_bytes.hex()
        if my_hex not in {m.pub_key_hex for m in state.members}:
            return None  # não sou membro
        return {
            "type":               "invite",
            "group_state":        state.to_dict(),
            "invitee_pub_key_hex": invitee_pub_key_hex,
            "invitee_username":   invitee_username,
            "inviter_pub_key_hex": my_hex,
        }

    def accept_invite(self, token: dict) -> GroupState | None:
        """
        Convidado aceita o convite: salva o estado atual do grupo localmente.
        O admin receberá JoinRequest e emitirá novo GroupState com o membro.
        """
        state = GroupState.from_dict(token["group_state"])
        if not state.is_valid_signature():
            return None
        self._groups[state.group_id] = state
        self._save(state)
        self._notify(state, "joined")
        return state

    # ------------------------------------------------------------------
    # Admin: adicionar membro após aceitar JoinRequest
    # ------------------------------------------------------------------

    def add_member(self, group_id: str, pub_key_hex: str, username: str) -> GroupState | None:
        state = self._groups.get(group_id)
        if state is None:
            return None
        if state.admin_pub_key_hex != self.identity.pub_key_bytes.hex():
            return None  # não sou admin
        if any(m.pub_key_hex == pub_key_hex for m in state.members):
            return state  # já é membro
        new_state = GroupState(
            group_id=state.group_id,
            name=state.name,
            admin_pub_key_hex=state.admin_pub_key_hex,
            members=state.members + [Member(pub_key_hex=pub_key_hex, username=username)],
            group_key_hex=state.group_key_hex,
            version=state.version + 1,
            signature_hex="",
        )
        _sign_state(self.identity, new_state)
        self._groups[group_id] = new_state
        self._save(new_state)
        self._notify(new_state, "updated")
        return new_state

    # ------------------------------------------------------------------
    # Admin: remover membro (rota chave)
    # ------------------------------------------------------------------

    def remove_member(self, group_id: str, pub_key_hex: str) -> GroupState | None:
        state = self._groups.get(group_id)
        if state is None:
            return None
        if state.admin_pub_key_hex != self.identity.pub_key_bytes.hex():
            return None
        new_members = [m for m in state.members if m.pub_key_hex != pub_key_hex]
        if not new_members:
            self._delete(group_id)
            return None
        new_state = GroupState(
            group_id=state.group_id,
            name=state.name,
            admin_pub_key_hex=state.admin_pub_key_hex,
            members=new_members,
            group_key_hex=os.urandom(32).hex(),  # rotação de chave
            version=state.version + 1,
            signature_hex="",
        )
        _sign_state(self.identity, new_state)
        self._groups[group_id] = new_state
        self._save(new_state)
        self._notify(new_state, "updated")
        return new_state

    # ------------------------------------------------------------------
    # Admin: apagar grupo
    # ------------------------------------------------------------------

    def delete_group(self, group_id: str) -> dict | None:
        """Retorna DissolveEvent para propagar."""
        state = self._groups.get(group_id)
        if state is None:
            return None
        if state.admin_pub_key_hex != self.identity.pub_key_bytes.hex():
            return None
        dissolve = {
            "type":     "dissolve",
            "group_id": group_id,
            "version":  state.version + 1,
        }
        sig = sign(self.identity.private_key, json.dumps(dissolve, sort_keys=True).encode())
        dissolve["signature_hex"] = sig.hex()
        dissolve["admin_pub_key_hex"] = state.admin_pub_key_hex
        self._delete(group_id)
        self._notify(state, "dissolved")
        return dissolve

    def apply_dissolve(self, event: dict) -> bool:
        state = self._groups.get(event.get("group_id"))
        if state is None:
            return False
        try:
            admin_pub = public_key_from_bytes(bytes.fromhex(event["admin_pub_key_hex"]))
            payload   = {k: v for k, v in event.items() if k != "signature_hex"}
            if not verify(admin_pub, bytes.fromhex(event["signature_hex"]),
                          json.dumps(payload, sort_keys=True).encode()):
                return False
        except Exception:
            return False
        self._delete(event["group_id"])
        self._notify(state, "dissolved")
        return True

    # ------------------------------------------------------------------
    # Getters
    # ------------------------------------------------------------------

    def get(self, group_id: str) -> GroupState | None:
        return self._groups.get(group_id)

    def all(self) -> list[GroupState]:
        return list(self._groups.values())

    def am_admin(self, group_id: str) -> bool:
        state = self._groups.get(group_id)
        if state is None:
            return False
        return state.admin_pub_key_hex == self.identity.pub_key_bytes.hex()
