# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Run
python run.py

# Lint (ruff, if available)
ruff check .

# Type check (mypy, if available)
mypy .
```

There is no test suite. The app requires a real LAN environment; all P2P behaviour can only be verified by running two instances on the same network.

## Architecture

TeamFlow is a serverless P2P LAN messenger. Every peer is simultaneously a WebSocket server (port 47778) and a WebSocket client. Peer discovery is via UDP broadcast (port 47777).

### Startup flow

```
run.py → Node() [no identity yet]
       → TeamFlowApp(node).run()
           on_mount() → key_status()
             "none"      → SetupModal  → identity.create()     → node.set_identity()
             "encrypted" → LoginModal  → identity.load_encrypted() → node.set_identity()
             "legacy"    → load_legacy()                        → node.set_identity()
           _after_auth() → node.start()
             init_db / GroupManager / Discovery / PeerServer
           → push_screen(HomeScreen)
```

`node.set_identity()` must be called before `node.start()`. This separation lets the TUI own the authentication flow before any network socket is opened.

### Message routing

`node.py` is the sole dispatcher. `PeerServer` and `PeerClient` both wire their `on_message` callbacks to `node._handle()`. All branching on `payload["type"]` lives there — there is no separate Router or Dispatcher class. `protocol.py` only constructs payloads; it never touches sockets.

### Encryption layers

Every connection uses two independent encryption layers:

1. **Session layer (ratchet):** after the X25519 handshake, each WebSocket frame is encrypted with `RatchetState.encrypt/decrypt` (symmetric double ratchet, ChaCha20-Poly1305, per-message keys). This gives per-message forward secrecy for all traffic including group messages.

2. **Group layer:** the `text` field of a `group_msg` payload is additionally encrypted with the shared `group_key` (`ChaCha20-Poly1305`, `aad=b"group-msg"`). This means even if a session key leaks, past group messages require the group key. Key rotation on kick/leave is handled by `GroupManager.remove_member`.

The `crypto.py` module is the only place that imports from `cryptography`. All primitives (Ed25519, X25519, HKDF, PBKDF2, ChaCha20-Poly1305) are in that file.

### Handshake sequence

```
Server                          Client
  HELLO (x25519_pub + ed25519_pub + username) →
                           ← HELLO (x25519_pub + ed25519_pub + username)
  ← CHALLENGE (nonce 32 bytes)
  → RESPONSE (Ed25519 sig of nonce)
  OK →
```

Both sides derive `session_key = HKDF(x25519_shared, info="teamflow-session", salt=xor(pub_a, pub_b))`. The ratchet is then initialised: server is `is_initiator=True`, client is `is_initiator=False`.

### Persistence model

Only two things survive a restart:
- `data/identity.key` — Ed25519 private key (92-byte encrypted format or 32-byte legacy)
- `data/<username>.db` — SQLite: `groups` (cells encrypted with `db_key` derived from private key) and TOFU tables (`trusted_keys`, `username_registry`)

Messages and peer state are purely in RAM. `MessageStore` is a global deque bounded at 1 GB; `PeerRegistry` is rebuilt from UDP beacons every session.

### Groups

`GroupState` is the source of truth and must always carry a valid Ed25519 signature from the admin. `GroupManager.apply_state` rejects any incoming state where `version ≤ current` or the signature fails. The `canonical_bytes()` method (sorted member keys, `sort_keys=True` JSON) defines what is signed — any change to this must be reflected in both signing and verification.

`group_key` rotation happens on every `remove_member` call; the new random key is included in the re-signed `GroupState` broadcast to remaining members.

## Critical security invariants

- **Never trust `sender_hash`/`sender_name` from the payload.** Always use `session.pub_key_hash` and `session.username` (set during handshake). See `node._handle` for the existing pattern.
- **Validate `pub_key_hex` against the session when acting on it.** In `join_request`, the `pub_key_hex` field must equal `session.public_key_hex`; otherwise a peer could add arbitrary members.
- **For `leave`, ignore `pub_key_hex` from the payload entirely.** Use `session.public_key_hex` to identify who is leaving (a peer should not be able to remove others by forging this field).
- **`GroupState` changes must be signed.** Never call `_sign_state` with an identity that isn't the admin, and never skip signature verification in `apply_state` or `apply_dissolve`.
- **Messages must not be written to disk.** `MessageStore` is RAM-only. If you add any persistence, the README security table must be updated.

## Ports

| Port  | Protocol | Purpose                  |
|-------|----------|--------------------------|
| 47777 | UDP      | Peer discovery (broadcast) |
| 47778 | TCP/WS   | P2P WebSocket transport  |
