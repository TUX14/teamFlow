"""
Identidade local — keypair Ed25519 persistido em disco.

    data/identity.key   — 32 bytes raw Ed25519 private key  (chmod 600)
    data/identity.name  — username em texto plano

Sem banco, sem senha, sem sessão.
A segurança é garantida pelas permissões do sistema de arquivos.
"""

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from crypto import (
    generate_identity_keypair,
    private_key_to_bytes,
    public_key_to_bytes,
    private_key_from_bytes,
    derive_db_key,
)

DATA_DIR  = Path(__file__).parent / "data"
KEY_FILE  = DATA_DIR / "identity.key"
NAME_FILE = DATA_DIR / "identity.name"


@dataclass
class LocalIdentity:
    private_key:   object          # Ed25519PrivateKey
    public_key:    object          # Ed25519PublicKey
    pub_key_bytes: bytes
    pub_key_hash:  str
    username:      str
    db_key:        bytes
    _db_path:      Path = field(default=None, repr=False)


def load_or_create() -> LocalIdentity:
    """
    Carrega identidade do disco ou gera um novo keypair.
    username fica vazio ('') se ainda não foi definido — a TUI mostra a
    tela de setup nesse caso.
    """
    DATA_DIR.mkdir(exist_ok=True)

    if KEY_FILE.exists():
        priv_raw = KEY_FILE.read_bytes()
        priv = private_key_from_bytes(priv_raw)
    else:
        priv, _ = generate_identity_keypair()
        priv_raw = private_key_to_bytes(priv)
        KEY_FILE.write_bytes(priv_raw)
        try:
            KEY_FILE.chmod(0o600)
        except Exception:
            pass

    pub       = priv.public_key()
    pub_bytes = public_key_to_bytes(pub)
    pub_hash  = hashlib.sha256(pub_bytes).hexdigest()[:32]
    db_key    = derive_db_key(priv_raw)
    username  = NAME_FILE.read_text(encoding="utf-8").strip() if NAME_FILE.exists() else ""

    return LocalIdentity(
        private_key=priv,
        public_key=pub,
        pub_key_bytes=pub_bytes,
        pub_key_hash=pub_hash,
        username=username,
        db_key=db_key,
    )


def save_username(username: str) -> None:
    DATA_DIR.mkdir(exist_ok=True)
    NAME_FILE.write_text(username.strip(), encoding="utf-8")
