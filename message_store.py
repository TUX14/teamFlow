"""
Store de mensagens em RAM — alocação dinâmica até MAX_BYTES (1 GB).

Estrutura: deque global de (conv_id, Message) em ordem de inserção.
Deduplicação por UUID. Evicção FIFO quando o orçamento de memória é atingido.
"""

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable

MAX_BYTES = 1 * 1024 ** 3  # 1 GB


@dataclass
class Message:
    uuid:        str
    sender_hash: str
    sender_name: str
    text:        str
    ts:          float = field(default_factory=time.time)
    is_mine:     bool  = False


class MessageStore:
    def __init__(self) -> None:
        self._msgs:      deque[tuple[str, Message]]              = deque()
        self._seen:      dict[str, None]                         = {}
        self._total:     int                                     = 0
        self._callbacks: dict[str, list[Callable[[Message], None]]] = {}

    @staticmethod
    def _size(msg: Message) -> int:
        return 64 + len(msg.uuid) + len(msg.sender_hash) + len(msg.sender_name) + len(msg.text.encode())

    def add(self, conv_id: str, msg: Message) -> bool:
        """Retorna True se adicionada, False se duplicata."""
        if msg.uuid in self._seen:
            return False
        self._seen[msg.uuid] = None
        self._msgs.append((conv_id, msg))
        self._total += self._size(msg)
        while self._total > MAX_BYTES:
            old_cid, old_msg = self._msgs.popleft()
            self._total -= self._size(old_msg)
            self._seen.pop(old_msg.uuid, None)
        for fn in self._callbacks.get(conv_id, ()):
            try:
                fn(msg)
            except Exception:
                pass
        return True

    def get(self, conv_id: str) -> list[Message]:
        return [m for cid, m in self._msgs if cid == conv_id]

    def on_new_message(self, conv_id: str, fn: Callable[[Message], None]) -> None:
        self._callbacks.setdefault(conv_id, []).append(fn)

    def clear_conversation(self, conv_id: str) -> None:
        """Libera todas as mensagens de uma conversa da RAM."""
        kept = deque()
        for cid, msg in self._msgs:
            if cid == conv_id:
                self._total -= self._size(msg)
                self._seen.pop(msg.uuid, None)
            else:
                kept.append((cid, msg))
        self._msgs = kept

    def drop_conversation(self, conv_id: str) -> None:
        """Libera mensagens e callbacks de uma conversa (usada ao sair)."""
        self.clear_conversation(conv_id)
        self._callbacks.pop(conv_id, None)
