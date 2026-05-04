"""
Primitivas criptográficas do TeamFlow P2P.

  Ed25519  → identidade / assinatura
  X25519   → key exchange efêmero (ECDH)
  HKDF     → derivação de chaves
  ChaCha20-Poly1305 → criptografia autenticada de mensagens e células do banco
"""

import os
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, serialization


# ---------------------------------------------------------------------------
# Ed25519 — identidade e assinatura
# ---------------------------------------------------------------------------

def generate_identity_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    private = Ed25519PrivateKey.generate()
    return private, private.public_key()


def sign(private_key: Ed25519PrivateKey, data: bytes) -> bytes:
    return private_key.sign(data)


def verify(public_key: Ed25519PublicKey, signature: bytes, data: bytes) -> bool:
    try:
        public_key.verify(signature, data)
        return True
    except Exception:
        return False


def private_key_to_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def public_key_to_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def private_key_from_bytes(raw: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(raw)


def public_key_from_bytes(raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw)


# ---------------------------------------------------------------------------
# X25519 — key exchange efêmero por sessão
# ---------------------------------------------------------------------------

def generate_session_keypair() -> tuple[X25519PrivateKey, X25519PublicKey]:
    private = X25519PrivateKey.generate()
    return private, private.public_key()


def x25519_exchange(private: X25519PrivateKey, peer_public_raw: bytes) -> bytes:
    peer_pub = X25519PublicKey.from_public_bytes(peer_public_raw)
    return private.exchange(peer_pub)


def x25519_public_to_bytes(key: X25519PublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


# ---------------------------------------------------------------------------
# HKDF — derivação de chaves
# ---------------------------------------------------------------------------

def hkdf_derive(ikm: bytes, length: int = 32, info: bytes = b"teamflow", salt: bytes | None = None) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def derive_db_key(identity_private_raw: bytes) -> bytes:
    """Deriva a chave de criptografia do banco a partir da private key de identidade."""
    return hkdf_derive(identity_private_raw, info=b"teamflow-db-key")


# ---------------------------------------------------------------------------
# PBKDF2 — derivação de chave a partir de senha do usuário
# ---------------------------------------------------------------------------

PBKDF2_ITERATIONS = 600_000  # recomendação NIST 2024 para PBKDF2-SHA256


def derive_password_key(password: str, salt: bytes) -> bytes:
    """Deriva chave de 32 bytes a partir de senha + salt (PBKDF2-HMAC-SHA256)."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def new_password_salt() -> bytes:
    return os.urandom(32)


# ---------------------------------------------------------------------------
# ChaCha20-Poly1305 — criptografia autenticada
# ---------------------------------------------------------------------------

def encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> bytes:
    """Retorna nonce (12 bytes) + ciphertext+tag."""
    nonce = os.urandom(12)
    chacha = ChaCha20Poly1305(key)
    ct = chacha.encrypt(nonce, plaintext, aad)
    return nonce + ct


def decrypt(key: bytes, payload: bytes, aad: bytes | None = None) -> bytes:
    """Recebe nonce (12 bytes) + ciphertext+tag, retorna plaintext."""
    nonce, ct = payload[:12], payload[12:]
    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, ct, aad)


# ---------------------------------------------------------------------------
# Helpers para células do banco (encrypt/decrypt JSON)
# ---------------------------------------------------------------------------

def encrypt_cell(db_key: bytes, value: object) -> bytes:
    plaintext = json.dumps(value, ensure_ascii=False).encode()
    return encrypt(db_key, plaintext, aad=b"db-cell")


def decrypt_cell(db_key: bytes, blob: bytes) -> object:
    plaintext = decrypt(db_key, blob, aad=b"db-cell")
    return json.loads(plaintext.decode())


# ---------------------------------------------------------------------------
# Derivação de chave de sessão a partir do shared secret X25519
# ---------------------------------------------------------------------------

def derive_session_key(shared_secret: bytes, initiator_pub: bytes, responder_pub: bytes) -> bytes:
    """Garante que ambos os lados derivem a mesma chave independente da ordem."""
    salt = bytes(a ^ b for a, b in zip(initiator_pub[:32], responder_pub[:32]))
    return hkdf_derive(shared_secret, info=b"teamflow-session", salt=salt)
