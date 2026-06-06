# TeamFlow

![Python](https://img.shields.io/badge/python-3.13%2B-blue?style=flat-square)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey?style=flat-square)
![UI](https://img.shields.io/badge/ui-textual%20TUI-blueviolet?style=flat-square)
![Crypto](https://img.shields.io/badge/crypto-Ed25519%20%7C%20X25519%20%7C%20ChaCha20--Poly1305-green?style=flat-square)
![Network](https://img.shields.io/badge/network-P2P%20LAN-orange?style=flat-square)
![Storage](https://img.shields.io/badge/messages-ephemeral%20(RAM%20only)-red?style=flat-square)

Mensageiro P2P criptografado para redes locais. Sem servidor central, sem conta, sem nuvem. Peers se descobrem automaticamente via UDP broadcast e se comunicam diretamente por WebSocket com criptografia de ponta a ponta.

---

## Sumario

- [Funcionalidades](#funcionalidades)
- [Seguranca](#seguranca)
- [Instalacao](#instalacao)
- [Uso](#uso)
- [Comandos](#comandos)
- [Arquitetura](#arquitetura)
- [Estrutura do projeto](#estrutura-do-projeto)

---

## Funcionalidades

- Descoberta automatica de peers na LAN via UDP broadcast
- Mensagens diretas (DM) entre dois peers
- Grupos com controle de membros pelo admin
- **Push-to-talk** estilo walkie-talkie em DMs e grupos (Ctrl+T)
- Transferencia de arquivos em DMs (streaming em chunks de 64 KB)
- Fingerprint mnemonica em portugues para verificacao de identidade
- Alerta TOFU (Trust On First Use) quando a chave de um peer muda
- Identicons pixel-art gerados a partir da chave publica
- Interface TUI no terminal (Textual)

---

## Seguranca

| Primitiva | Uso |
|---|---|
| Ed25519 | Identidade permanente e assinatura de estados de grupo |
| X25519 (ECDH) | Troca de chave de sessao efemera por conexao |
| HKDF-SHA256 | Derivacao de chaves de sessao e do banco |
| ChaCha20-Poly1305 | Criptografia autenticada: sessao, banco e mensagens de grupo |
| PBKDF2-HMAC-SHA256 (600 000 iteracoes) | Protecao da private key em disco (formato novo) |
| Symmetric Double Ratchet | Forward secrecy por mensagem nas sessoes individuais |

**Propriedades garantidas:**

- Mensagens e audio nunca sao gravados em disco (apenas em RAM, ate fechar o app)
- A private key e cifrada com PBKDF2 + ChaCha20-Poly1305 (novos usuarios)
- Identidades no formato legado (32 bytes raw) sao protegidas apenas por chmod 600
- Session keys sao efemeras: cada conexao usa um par X25519 diferente
- Mensagens e frames de voz PTT trafegam cifrados pelo ratchet de sessao (ChaCha20-Poly1305, forward secrecy por frame)
- Mensagens de grupo tem dupla camada de cifra: ratchet de sessao + group_key
- Remocao de membro rotaciona a group_key (mensagens futuras ilegíveis para o removido)
- Estados de grupo sao assinados pelo admin com Ed25519 e versionados

> **Aviso:** o transporte WebSocket e em texto claro (`ws://`). A criptografia e feita inteiramente na camada de aplicacao. Para uso em redes nao confiaveis, considere adicionar TLS.

---

## Instalacao

**Requisitos:** Python 3.13 ou superior.

```bash
git clone <repo>
cd teamFlow
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

`requirements.txt`:
```
textual>=0.70.0
websockets>=12.0
cryptography>=43.0.0
sounddevice>=0.4.6
numpy>=1.24.0
```

> `sounddevice` e `numpy` sao necessarios apenas para o push-to-talk. O app funciona normalmente sem eles; o PTT fica desabilitado com uma notificacao se os pacotes nao estiverem instalados ou se nao houver dispositivo de audio.

---

## Uso

```bash
python run.py
```

No primeiro acesso, o app solicita nome de usuario (minimo 2 caracteres) e uma senha (minimo 4 caracteres). O keypair Ed25519 e gerado e salvo cifrado em `data/identity.key`.

Cada instancia precisa estar **na mesma rede local**. Peers aparecem automaticamente na tela inicial assim que enviam o primeiro beacon UDP.

---

## Comandos

### Em qualquer tela

| Comando | Descricao |
|---|---|
| `/help` | Exibe a referencia de comandos |
| `/quit` | Encerra o TeamFlow |
| `/me` | Exibe sua identidade e fingerprint |
| `/peers` | Lista peers online |
| `/groups` | Lista seus grupos |
| `/status` | Estado geral da rede (peers, grupos, uptime) |
| `/rename <nome>` | Altera seu nome na rede |
| `/clock` | Exibe data e hora atuais |

### Tela inicial

| Comando | Descricao |
|---|---|
| `/newgroup <nome>` | Cria um novo grupo |

### No chat

| Comando | Descricao |
|---|---|
| `/back` | Volta para a lista |
| `/whois` | Exibe fingerprint do peer ativo |
| `/clear` | Limpa o historico de mensagens |
| `/ping [nome]` | Mede a latencia do peer (padrao: peer atual) |
| `/invite <nome>` | Convida peer conectado para o grupo |
| `/kick <nome>` | Remove membro do grupo (somente admin) |
| `/leave` | Sai do grupo |
| `/dissolve` | Dissolve o grupo (somente admin) |
| `/send <caminho>` | Envia arquivo ao peer (somente DMs, sem espacos no caminho) |
| `/accept` | Aceita arquivo recebido |
| `/reject` | Recusa arquivo recebido |
| `Ctrl+T` | Ativa/desativa push-to-talk (microfone) |

---

## Arquitetura

```
run.py
  └── node.py          Node() sem identidade; TUI chama set_identity() apos autenticacao
        ├── identity.py        keypair Ed25519 em disco (cifrado com PBKDF2)
        ├── discovery.py       UDP broadcast (porta 47777)
        ├── peer_server.py     WebSocket server (porta 47778)
        ├── peer_client.py     WebSocket client (saida)
        │     └── ratchet.py   symmetric double ratchet por sessao
        ├── groups.py          estados de grupo assinados + group_key
        ├── message_store.py   store efemero em RAM
        ├── file_transfer.py   transferencia por chunks (streaming)
        ├── voice.py           PTTEngine (captura mic) + _Player (reproducao com jitter buffer)
        └── db.py              SQLite (grupos cifrados + TOFU)
  └── tui.py           interface Textual
        ├── SetupModal   primeiro acesso (username + senha)
        ├── LoginModal   autenticacao em acessos subsequentes
        ├── HomeScreen   peers + grupos
        └── ChatScreen   chat + PTT + comandos
```

### Handshake de sessao

```
Peer A (server)                    Peer B (client)
      |                                  |
      |<-- WebSocket connect ------------|
      |                                  |
      |--- HELLO (X25519_pub + Ed25519_pub + username_utf8) -->|
      |<-- HELLO (X25519_pub + Ed25519_pub + username_utf8) ---|
      |                                  |
      |  ambos derivam session_key via ECDH + HKDF             |
      |                                  |
      |--- CHALLENGE (nonce 32 bytes) -->|
      |<-- RESPONSE (sign(nonce)) -------|
      |--- OK --------------------------->|
      |                                  |
      |  ratchet inicializado com session_key                  |
      |  mensagens: ratchet.encrypt(json_payload)              |
```

O campo `username` no HELLO e UTF-8 de comprimento variavel (bytes 64 ate o fim do frame).

### Push-to-talk

O PTT transmite audio PCM (16 kHz, mono, int16) em chunks de 20 ms codificados em base64, enviados como payloads JSON comuns sobre o WebSocket ja cifrado pelo ratchet de sessao. Cada frame de voz tem forward secrecy individual — um sniffer na LAN ve apenas bytes cifrados.

```
Microfone → PTTEngine (chunks de 20 ms)
  → base64 PCM → make_voice_frame() → ratchet.encrypt() → WebSocket
  → ratchet.decrypt() → _Player.feed() → saida de audio (jitter buffer por peer)
```

Para grupos, os frames sao enviados individualmente a cada membro via seu canal ratchet dedicado (fan-out identico ao de mensagens de grupo, sem a camada extra de `group_key`). A barra de status no chat exibe `● TX` ao transmitir e `🔊 nome` ao receber.

### Criptografia de mensagens de grupo

Mensagens de grupo tem dupla camada de cifra:

1. **Outer (sessao):** `ratchet.encrypt(payload_json)` — forward secrecy por mensagem, protege o canal DM individual de cada membro
2. **Inner (grupo):** `ChaCha20-Poly1305(group_key, text, aad=b"group-msg")` — o campo `text` do payload JSON e o ciphertext hex desta camada

A `group_key` e um segredo compartilhado entre todos os membros, distribuido pelo admin via `GroupState`. Ao remover um membro, o admin gera uma nova `group_key` aleatoria, incrementa a versao e transmite o novo `GroupState` assinado. Mensagens enviadas apos a rotacao nao podem ser decifradas pelo membro removido, mesmo que este tenha capturado o trafego.

### Fluxo de grupo

1. Admin cria grupo: gera `group_id`, `group_key` (32 bytes aleatorios), assina `GroupState` com Ed25519
2. Membro convida peer: envia `invite` com o `GroupState` atual via DM criptografado
3. Convidado envia `join_request` ao admin
4. Admin adiciona membro, incrementa versao, re-assina e faz broadcast do novo `GroupState`
5. Kick/leave: admin rotaciona `group_key`, incrementa versao, re-assina e faz broadcast

---

## Estrutura do projeto

```
teamFlow/
├── run.py              entry point — cria Node(), inicia TUI
├── identity.py         keypair Ed25519; API: key_status/create/load_encrypted/load_legacy
├── crypto.py           primitivas: Ed25519, X25519, HKDF, ChaCha20-Poly1305, PBKDF2
├── ratchet.py          symmetric double ratchet (forward secrecy por mensagem)
├── discovery.py        descoberta UDP na LAN (porta 47777)
├── peer_server.py      servidor WebSocket P2P (porta 47778)
├── peer_client.py      cliente WebSocket P2P com reconexao exponencial
├── protocol.py         construtores de payloads JSON (sem Dispatcher — despacho em node.py)
├── node.py             orquestrador central; set_identity() → start() → stop()
├── groups.py           logica de grupos: GroupState, GroupManager
├── message_store.py    store efemero de mensagens em RAM (ate 1 GB, evicao FIFO)
├── db.py               SQLite: grupos cifrados (db_key) + TOFU (trusted_keys)
├── file_transfer.py    transferencia de arquivos em chunks de 64 KB (streaming)
├── voice.py            PTTEngine (captura mic, 20 ms) + _Player (jitter buffer + mix)
├── tui.py              interface Textual: SetupModal, LoginModal, HomeScreen, ChatScreen
├── avatar.py           identicons pixel-art para o terminal
├── wordlist.py         fingerprint mnemonica (256 palavras PT, 5 palavras = 40 bits)
├── requirements.txt
└── data/               gerado em runtime (ignorado pelo git)
    ├── identity.key    private key — 92 bytes (cifrada) ou 32 bytes (legado)
    ├── identity.name   username em texto plano
    └── <usuario>.db    banco pessoal (grupos + trusted_keys)
```

### Limitacoes conhecidas

- Transporte WebSocket sem TLS (`ws://`); cifra e feita na camada de aplicacao
- Sem re-entrega garantida de mensagens (best-effort via WebSocket)
- Sem suporte a multiplas instancias do mesmo usuario na rede
- Historico de mensagens efemero (RAM); perdido ao fechar o app
