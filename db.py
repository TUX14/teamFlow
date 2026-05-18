"""
Banco mínimo — sqlite3 puro, células sensíveis criptografadas.

Tabelas (banco pessoal por usuário, em data/<username>.db):
  groups            — grupos dos quais este peer é membro (células cifradas com db_key)
  trusted_keys      — registro TOFU: pub_key_hash → pub_key_hex + username
  username_registry — mapeamento username_lower → pub_key_hash para detectar roubo de nick

Peers são mantidos SOMENTE em RAM via PeerRegistry (discovery.py).
Mensagens são efêmeras em RAM (message_store.py).
A identidade (keypair) vive em data/identity.key — ver identity.py.
"""

import sqlite3
from pathlib import Path
from crypto import encrypt_cell, decrypt_cell

DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(exist_ok=True)


def _conn(path: Path) -> sqlite3.Connection:
    c = sqlite3.connect(path)
    c.row_factory = sqlite3.Row
    return c


def user_db_path(username: str) -> Path:
    """Caminho do banco pessoal do usuário."""
    return DATA_DIR / f"{username}.db"


def init_db(path: Path) -> None:
    """Cria tabelas se não existirem."""
    with _conn(path) as c:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS groups (
                group_id    TEXT PRIMARY KEY,
                data        BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS trusted_keys (
                pub_key_hash    TEXT PRIMARY KEY,
                public_key_hex  TEXT NOT NULL,
                username        TEXT NOT NULL,
                first_seen      REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS username_registry (
                username_lower  TEXT PRIMARY KEY,
                username        TEXT NOT NULL,
                pub_key_hash    TEXT NOT NULL,
                first_seen      REAL NOT NULL
            );
        """)


# ---------------------------------------------------------------------------
# trusted_keys + username_registry — TOFU e detecção de roubo de nick
# ---------------------------------------------------------------------------

def get_trusted_key_hex(pub_key_hash: str, path: Path) -> str | None:
    """Retorna public_key_hex armazenado para um pub_key_hash, ou None."""
    with _conn(path) as c:
        row = c.execute(
            "SELECT public_key_hex FROM trusted_keys WHERE pub_key_hash=?",
            (pub_key_hash,)
        ).fetchone()
    return row["public_key_hex"] if row else None


def tofu_check(pub_key_hash: str, public_key_hex: str, username: str,
               path: Path) -> tuple[str, dict]:
    """
    Verifica segurança TOFU. Retorna (status, detalhes):
      ('new',      {})                        — primeiro contato, chave e nick salvos
      ('ok',       {})                        — chave e nick batem com registro anterior
      ('renamed',  {old_username, new_username}) — mesma chave, nick diferente (renomear legítimo)
      ('hijacked', {username, known_hash, known_key_hex}) — nick em uso por chave diferente
    """
    import time
    username_lower = username.lower()

    with _conn(path) as c:
        key_row = c.execute(
            "SELECT public_key_hex, username FROM trusted_keys WHERE pub_key_hash=?",
            (pub_key_hash,)
        ).fetchone()
        nick_row = c.execute(
            "SELECT pub_key_hash, username FROM username_registry WHERE username_lower=?",
            (username_lower,)
        ).fetchone()

    if key_row is None:
        # Chave nunca vista — verifica se o nick já está associado a outra chave.
        if nick_row is not None and nick_row["pub_key_hash"] != pub_key_hash:
            known_key_hex = get_trusted_key_hex(nick_row["pub_key_hash"], path) or ""
            return ("hijacked", {
                "username":      username,
                "known_hash":    nick_row["pub_key_hash"],
                "known_key_hex": known_key_hex,
            })
        # Genuinamente novo — salva em ambas as tabelas.
        now = time.time()
        with _conn(path) as c:
            c.execute(
                "INSERT INTO trusted_keys (pub_key_hash, public_key_hex, username, first_seen)"
                " VALUES (?, ?, ?, ?)",
                (pub_key_hash, public_key_hex, username, now),
            )
            c.execute(
                "INSERT OR IGNORE INTO username_registry"
                " (username_lower, username, pub_key_hash, first_seen)"
                " VALUES (?, ?, ?, ?)",
                (username_lower, username, pub_key_hash, now),
            )
        return ("new", {})

    # Chave conhecida — verifica se o nick mudou.
    stored_username = key_row["username"]
    if stored_username.lower() == username_lower:
        return ("ok", {})

    # Mesmo keypair, nick diferente — renomeação legítima.
    return ("renamed", {
        "old_username": stored_username,
        "new_username": username,
    })


def tofu_update(pub_key_hash: str, public_key_hex: str, username: str,
                path: Path) -> None:
    """Atualiza registro de confiança após confirmação explícita do usuário."""
    import time
    username_lower = username.lower()
    now = time.time()
    with _conn(path) as c:
        c.execute(
            "INSERT INTO trusted_keys (pub_key_hash, public_key_hex, username, first_seen)"
            " VALUES (?, ?, ?, ?) ON CONFLICT(pub_key_hash) DO UPDATE"
            " SET public_key_hex=excluded.public_key_hex, username=excluded.username",
            (pub_key_hash, public_key_hex, username, now),
        )
        c.execute(
            "INSERT INTO username_registry"
            " (username_lower, username, pub_key_hash, first_seen)"
            " VALUES (?, ?, ?, ?)"
            " ON CONFLICT(username_lower) DO UPDATE"
            " SET pub_key_hash=excluded.pub_key_hash, username=excluded.username",
            (username_lower, username, pub_key_hash, now),
        )


# ---------------------------------------------------------------------------
# groups — estado de grupo cifrado célula a célula
# ---------------------------------------------------------------------------

def save_group(db_key: bytes, group_id: str, group_data: dict, path: Path) -> None:
    blob = encrypt_cell(db_key, group_data)
    with _conn(path) as c:
        c.execute(
            "INSERT INTO groups (group_id, data) VALUES (?, ?) "
            "ON CONFLICT(group_id) DO UPDATE SET data=excluded.data",
            (group_id, blob),
        )


def load_all_groups(db_key: bytes, path: Path) -> list[dict]:
    if not path.exists():
        return []
    with _conn(path) as c:
        rows = c.execute("SELECT group_id, data FROM groups").fetchall()
    result = []
    for row in rows:
        try:
            d = decrypt_cell(db_key, bytes(row["data"]))
            d["group_id"] = row["group_id"]
            result.append(d)
        except Exception:
            pass
    return result


def delete_group(group_id: str, path: Path) -> None:
    with _conn(path) as c:
        c.execute("DELETE FROM groups WHERE group_id=?", (group_id,))
