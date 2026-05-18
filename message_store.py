"""
Store efêmero de mensagens — apenas em memória, zero disco.

Cada conversa (DM ou grupo) tem um deque com limite de tamanho.
Mensagens identificadas por UUID para deduplicação (fan-out pode causar duplicatas).
Tudo some ao fechar a aplicação.
"""

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable

MAX_MESSAGES_PER_CONV = 200  # limite por conversa em memória


@dataclass
class Message:
    uuid:        str
    sender_hash: str
    sender_name: str
    text:        str
    ts:          float = field(default_factory=time.time)
    is_mine:     bool  = False


class ConversationStore:
    """Store de uma única conversa (DM ou grupo)."""

    def __init__(self):
        self._messages: deque[Message] = deque(maxlen=MAX_MESSAGES_PER_CONV)
        # dict mantém ordem de inserção (Python 3.7+); serve como conjunto ordenado
        self._seen_uuids: dict[str, None] = {}
        self._callbacks: list[Callable[[Message], None]] = []

    def on_new_message(self, fn: Callable[[Message], None]) -> None:
        self._callbacks.append(fn)

    def add(self, msg: Message) -> bool:
        """Retorna True se adicionada, False se duplicata."""
        if msg.uuid in self._seen_uuids:
            return False
        self._seen_uuids[msg.uuid] = None
        # remove o mais antigo quando a janela de deduplicação dobra o limite
        if len(self._seen_uuids) > MAX_MESSAGES_PER_CONV * 2:
            self._seen_uuids.pop(next(iter(self._seen_uuids)))
        self._messages.append(msg)
        for fn in self._callbacks:
            try:
                fn(msg)
            except Exception:
                pass
        return True

    def all(self) -> list[Message]:
        return list(self._messages)

    def clear(self) -> None:
        self._messages.clear()
        self._seen_uuids.clear()  # dict.clear() funciona igual ao set.clear()


class MessageStore:
    """
    Store global — uma ConversationStore por conversa.

    Chave de conversa:
      DM    → pub_key_hash do peer remoto
      Grupo → group_id (UUID do grupo)
    """

    def __init__(self):
        self._convs: dict[str, ConversationStore] = {}

    def conversation(self, conv_id: str) -> ConversationStore:
        if conv_id not in self._convs:
            self._convs[conv_id] = ConversationStore()
        return self._convs[conv_id]

    def add(self, conv_id: str, msg: Message) -> bool:
        return self.conversation(conv_id).add(msg)

    def get(self, conv_id: str) -> list[Message]:
        return self.conversation(conv_id).all()

    def on_new_message(self, conv_id: str, fn: Callable[[Message], None]) -> None:
        self.conversation(conv_id).on_new_message(fn)

    def drop_conversation(self, conv_id: str) -> None:
        self._convs.pop(conv_id, None)
