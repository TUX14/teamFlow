"""
Identidade local — keypair Ed25519.

Formatos de data/identity.key:
  Novo  (92 bytes): salt(32) + nonce(12) + ciphertext(32) + tag(16)
                    Chave cifrada com PBKDF2-HMAC-SHA256 (600 000 iter.) + ChaCha20-Poly1305.
  Legado (32 bytes): raw Ed25519 private key sem senha.
                    Protegido apenas por permissões do SO (chmod 600).

data/identity.name — username em texto plano.

API pública:
  key_status()          → 'none' | 'encrypted' | 'legacy'
  create(username, pw)  → LocalIdentity   (novo usuário)
  load_encrypted(pw)    → LocalIdentity   (levanta ValueError se senha errada)
  load_legacy()         → LocalIdentity   (formato antigo, sem senha)
  save_username(name)   → None
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
    derive_password_key,
    new_password_salt,
    encrypt,
    decrypt,
)

DATA_DIR  = Path(__file__).parent / "data"
KEY_FILE  = DATA_DIR / "identity.key"
NAME_FILE = DATA_DIR / "identity.name"

_ENCRYPTED_SIZE = 92   # salt(32) + nonce(12) + raw_key(32) + tag(16)


@dataclass
class LocalIdentity:
    private_key:   object          # Ed25519PrivateKey
    public_key:    object          # Ed25519PublicKey
    pub_key_bytes: bytes
    pub_key_hash:  str
    username:      str
    db_key:        bytes
    _db_path:      Path = field(default=None, repr=False)


def key_status() -> str:
    """
    Retorna o estado do arquivo de chave em disco:
      'none'      — nenhuma chave (primeiro acesso)
      'encrypted' — 92 bytes; cifrada com PBKDF2 + ChaCha20-Poly1305
      'legacy'    — 32 bytes raw; protegida apenas por chmod 600
    """
    if not KEY_FILE.exists():
        return "none"
    return "encrypted" if KEY_FILE.stat().st_size == _ENCRYPTED_SIZE else "legacy"


def _build(priv_raw: bytes, username: str) -> LocalIdentity:
    priv      = private_key_from_bytes(priv_raw)
    pub       = priv.public_key()
    pub_bytes = public_key_to_bytes(pub)
    return LocalIdentity(
        private_key   = priv,
        public_key    = pub,
        pub_key_bytes = pub_bytes,
        pub_key_hash  = hashlib.sha256(pub_bytes).hexdigest()[:32],
        username      = username,
        db_key        = derive_db_key(priv_raw),
    )


def create(username: str, password: str) -> LocalIdentity:
    """
    Gera novo keypair Ed25519, cifra com senha e salva em disco.
    Levanta RuntimeError se identity.key já existe.
    """
    DATA_DIR.mkdir(exist_ok=True)
    if KEY_FILE.exists():
        raise RuntimeError("Chave já existe. Apague data/identity.key para recriar.")
    priv, _ = generate_identity_keypair()
    priv_raw = private_key_to_bytes(priv)
    salt     = new_password_salt()                               # 32 bytes
    pw_key   = derive_password_key(password, salt)
    blob     = encrypt(pw_key, priv_raw, aad=b"identity-key")   # nonce(12)+ct(32)+tag(16) = 60 bytes
    KEY_FILE.write_bytes(salt + blob)                            # 92 bytes total
    try:
        KEY_FILE.chmod(0o600)
    except Exception:
        pass
    NAME_FILE.write_text(username.strip(), encoding="utf-8")
    return _build(priv_raw, username)


def load_encrypted(password: str) -> LocalIdentity:
    """
    Carrega e decifra identidade protegida por senha.
    Levanta ValueError se a senha estiver incorreta.
    """
    data   = KEY_FILE.read_bytes()
    salt   = data[:32]
    blob   = data[32:]
    pw_key = derive_password_key(password, salt)
    try:
        priv_raw = decrypt(pw_key, blob, aad=b"identity-key")
    except Exception:
        raise ValueError("Senha incorreta.")
    username = NAME_FILE.read_text(encoding="utf-8").strip() if NAME_FILE.exists() else ""
    return _build(priv_raw, username)


def load_legacy() -> LocalIdentity:
    """Carrega chave em formato legado (32 bytes raw, sem senha)."""
    priv_raw = KEY_FILE.read_bytes()
    username = NAME_FILE.read_text(encoding="utf-8").strip() if NAME_FILE.exists() else ""
    return _build(priv_raw, username)


def save_username(username: str) -> None:
    DATA_DIR.mkdir(exist_ok=True)
    NAME_FILE.write_text(username.strip(), encoding="utf-8")
