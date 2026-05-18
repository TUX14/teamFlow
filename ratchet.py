"""
Symmetric Double Ratchet — per-message forward secrecy.

Each side maintains two KDF chains (send/recv). For every message the active
chain key advances and produces a fresh single-use message key:

    msg_key    = HKDF(chain_key, info=b"ratchet-msg-key")
    chain_key  = HKDF(chain_key, info=b"ratchet-chain-step")

The initiator's send chain equals the responder's recv chain and vice-versa,
so both sides stay in sync without extra negotiation.  Once a key is used it
is replaced immediately — past messages cannot be decrypted even if the current
chain state is later exposed.
"""

from crypto import hkdf_derive, encrypt, decrypt


def _step(chain_key: bytes) -> tuple[bytes, bytes]:
    """Returns (msg_key, next_chain_key)."""
    msg_key    = hkdf_derive(chain_key, info=b"ratchet-msg-key")
    next_chain = hkdf_derive(chain_key, info=b"ratchet-chain-step")
    return msg_key, next_chain


class RatchetState:
    """Symmetric ratchet for one P2P session (single-threaded asyncio use only)."""

    __slots__ = ("_send", "_recv")

    def __init__(self, send_chain: bytes, recv_chain: bytes) -> None:
        self._send = send_chain
        self._recv = recv_chain

    def encrypt(self, plaintext: bytes) -> bytes:
        msg_key, self._send = _step(self._send)
        return encrypt(msg_key, plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        msg_key, self._recv = _step(self._recv)
        return decrypt(msg_key, ciphertext)


def init_ratchet(session_key: bytes, is_initiator: bool) -> RatchetState:
    """
    Derives send/recv chains from the shared session_key.
    Initiator and responder swap assignments so their chains align.
    """
    chain_a = hkdf_derive(session_key, info=b"ratchet-chain-A")
    chain_b = hkdf_derive(session_key, info=b"ratchet-chain-B")
    if is_initiator:
        return RatchetState(send_chain=chain_a, recv_chain=chain_b)
    return RatchetState(send_chain=chain_b, recv_chain=chain_a)
