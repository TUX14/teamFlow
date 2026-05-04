"""
Banco mínimo — sqlite3 puro, células sensíveis criptografadas.

Tabelas:
  users   — credenciais: username (plaintext para lookup) + salt + private_key cifrada com senha
  groups  — grupos dos quais este peer é membro (células cifradas com db_key)

Peers são descobertos via UDP broadcast e mantidos SOMENTE em RAM — zero
metadados de rede persistidos em disco.  Mensagens também nunca vão ao banco.
"""

import sqlite3
from pathlib import Path
from crypto import encrypt_cell, decrypt_cell, encrypt, decrypt, derive_password_key, new_password_salt

DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(exist_ok=True)

# banco compartilhado só para autenticação (mapeamento username → DB file)
AUTH_DB = DATA_DIR / "_auth.db"


def _conn(path: Path) -> sqlite3.Connection:
    c = sqlite3.connect(path)
    c.row_factory = sqlite3.Row
    return c


# ---------------------------------------------------------------------------
# Auth DB — lookup de usuários (username é plaintext, chave cifrada com senha)
# ---------------------------------------------------------------------------

def _init_auth_db() -> None:
    with _conn(AUTH_DB) as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                username        TEXT UNIQUE NOT NULL,
                salt            BLOB NOT NULL,
                encrypted_key   BLOB NOT NULL,
                public_key_hex  TEXT NOT NULL,
                created_at      REAL NOT NULL DEFAULT (unixepoch())
            )
        """)


def user_db_path(username: str) -> Path:
    """Caminho do banco de dados pessoal do usuário."""
    return DATA_DIR / f"{username}.db"


def user_exists(username: str) -> bool:
    _init_auth_db()
    with _conn(AUTH_DB) as c:
        row = c.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
    return row is not None


def register_user(username: str, password: str) -> tuple[bytes, bytes]:
    """
    Cria novo usuário. Retorna (private_key_bytes, public_key_bytes).
    Lança ValueError se username já existe.
    """
    from crypto import generate_identity_keypair, private_key_to_bytes, public_key_to_bytes
    _init_auth_db()
    if user_exists(username):
        raise ValueError(f"Usuário '{username}' já existe.")

    priv, pub = generate_identity_keypair()
    priv_raw  = private_key_to_bytes(priv)
    pub_raw   = public_key_to_bytes(pub)
    salt      = new_password_salt()
    pw_key    = derive_password_key(password, salt)
    enc_key   = encrypt(pw_key, priv_raw, aad=b"auth-private-key")

    with _conn(AUTH_DB) as c:
        c.execute(
            "INSERT INTO users (username, salt, encrypted_key, public_key_hex) VALUES (?,?,?,?)",
            (username, salt, enc_key, pub_raw.hex()),
        )

    init_user_db(username)
    return priv_raw, pub_raw


def login_user(username: str, password: str) -> tuple[bytes, bytes] | None:
    """
    Verifica credenciais. Retorna (private_key_bytes, public_key_bytes) se ok, None se falhou.
    """
    _init_auth_db()
    with _conn(AUTH_DB) as c:
        row = c.execute(
            "SELECT salt, encrypted_key, public_key_hex FROM users WHERE username=?", (username,)
        ).fetchone()
    if row is None:
        return None
    try:
        pw_key  = derive_password_key(password, bytes(row["salt"]))
        priv_raw = decrypt(pw_key, bytes(row["encrypted_key"]), aad=b"auth-private-key")
        pub_raw  = bytes.fromhex(row["public_key_hex"])
        return priv_raw, pub_raw
    except Exception:
        return None  # senha errada


def change_password(username: str, old_password: str, new_password: str) -> bool:
    """Troca a senha. Retorna True se ok."""
    result = login_user(username, old_password)
    if result is None:
        return False
    priv_raw, _ = result
    salt   = new_password_salt()
    pw_key = derive_password_key(new_password, salt)
    enc    = encrypt(pw_key, priv_raw, aad=b"auth-private-key")
    with _conn(AUTH_DB) as c:
        c.execute(
            "UPDATE users SET salt=?, encrypted_key=? WHERE username=?",
            (salt, enc, username),
        )
    return True


# ---------------------------------------------------------------------------
# Banco pessoal do usuário (known_peers + groups)
# ---------------------------------------------------------------------------

def init_user_db(username: str) -> Path:
    path = user_db_path(username)
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
        """)
    return path


def init_db(path: Path | None = None) -> None:
    if path:
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
            """)


# ---------------------------------------------------------------------------
# trusted_keys — TOFU (Trust On First Use)
# ---------------------------------------------------------------------------

def tofu_check(pub_key_hash: str, public_key_hex: str, username: str,
               path: Path) -> str:
    """
    Verifica confiança TOFU. Retorna:
      'new'     — primeiro contato, chave salva agora
      'trusted' — chave bate com o registro anterior
      'changed' — ALERTA: chave diferente da registrada
    """
    import time
    with _conn(path) as c:
        row = c.execute(
            "SELECT public_key_hex FROM trusted_keys WHERE pub_key_hash=?",
            (pub_key_hash,)
        ).fetchone()

    if row is None:
        with _conn(path) as c:
            c.execute(
                "INSERT INTO trusted_keys (pub_key_hash, public_key_hex, username, first_seen)"
                " VALUES (?, ?, ?, ?)",
                (pub_key_hash, public_key_hex, username, time.time()),
            )
        return "new"

    return "trusted" if row["public_key_hex"] == public_key_hex else "changed"


def tofu_update(pub_key_hash: str, public_key_hex: str, username: str,
                path: Path) -> None:
    """Atualiza registro de confiança após confirmação explícita do usuário."""
    import time
    with _conn(path) as c:
        c.execute(
            "INSERT INTO trusted_keys (pub_key_hash, public_key_hex, username, first_seen)"
            " VALUES (?, ?, ?, ?) ON CONFLICT(pub_key_hash) DO UPDATE"
            " SET public_key_hex=excluded.public_key_hex, username=excluded.username",
            (pub_key_hash, public_key_hex, username, time.time()),
        )


# ---------------------------------------------------------------------------
# groups
# ---------------------------------------------------------------------------

def save_group(db_key: bytes, group_id: str, group_data: dict, path: Path | None = None) -> None:
    path = path or DATA_DIR / "default.db"
    blob = encrypt_cell(db_key, group_data)
    with _conn(path) as c:
        c.execute(
            "INSERT INTO groups (group_id, data) VALUES (?, ?) "
            "ON CONFLICT(group_id) DO UPDATE SET data=excluded.data",
            (group_id, blob),
        )


def load_group(db_key: bytes, group_id: str, path: Path | None = None) -> dict | None:
    path = path or DATA_DIR / "default.db"
    if not path.exists():
        return None
    with _conn(path) as c:
        row = c.execute("SELECT data FROM groups WHERE group_id=?", (group_id,)).fetchone()
    if row is None:
        return None
    return decrypt_cell(db_key, bytes(row["data"]))


def load_all_groups(db_key: bytes, path: Path | None = None) -> list[dict]:
    path = path or DATA_DIR / "default.db"
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


def delete_group(group_id: str, path: Path | None = None) -> None:
    path = path or DATA_DIR / "default.db"
    with _conn(path) as c:
        c.execute("DELETE FROM groups WHERE group_id=?", (group_id,))


# mantém compatibilidade antiga
def save_identity(db_key: bytes, identity: dict, path: Path | None = None) -> None:
    pass  # identidade agora vive no auth.db via register_user/login_user


def load_identity(db_key: bytes, path: Path | None = None) -> dict | None:
    return None  # use login_user() em vez disso
