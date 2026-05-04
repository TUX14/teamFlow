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
- Transferencia de arquivos em DMs (chunks de 64 KB)
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
| ChaCha20-Poly1305 | Criptografia autenticada de mensagens e celulas do banco |
| PBKDF2-HMAC-SHA256 (600 000 iteracoes) | Protecao da private key em disco |
| Symmetric Double Ratchet | Forward secrecy por mensagem |

**Propriedades garantidas:**

- Mensagens nunca sao gravadas em disco (apenas em RAM, ate fechar o app)
- A private key fica em `data/identity.key` com permissao `600`
- Session keys sao efemeras: cada conexao usa um par X25519 diferente
- Compromisso de uma chave de sessao nao expoe mensagens anteriores nem futuras
- Estados de grupo sao assinados pelo admin com Ed25519 e versionados
- Remocao de membro rotaciona a chave simetrica do grupo (forward secrecy no grupo)

> **Aviso:** o transporte WebSocket e em texto claro (`ws://`). A criptografia e feita inteiramente na camada de aplicacao pelo ratchet. Para uso em redes nao confiaveis, considere adicionar TLS.

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
```

---

## Uso

```bash
python run.py
```

No primeiro acesso, o app solicita um nome de usuario (minimo 2 caracteres). O keypair Ed25519 e gerado e salvo automaticamente em `data/identity.key`.

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

---

## Arquitetura

```
run.py
  └── identity.py      keypair Ed25519 em disco
  └── node.py          orquestrador central
        ├── discovery.py       UDP broadcast (porta 47777)
        ├── peer_server.py     WebSocket server (porta 47778)
        ├── peer_client.py     WebSocket client (saida)
        │     └── ratchet.py   symmetric double ratchet
        ├── groups.py          estados de grupo assinados
        ├── message_store.py   store efemero em RAM
        ├── file_transfer.py   transferencia por chunks
        └── db.py              SQLite (grupos + TOFU)
  └── tui.py           interface Textual
        ├── HomeScreen   peers + grupos
        └── ChatScreen   chat + comandos
```

### Handshake de sessao

```
Peer A (server)                    Peer B (client)
      |                                  |
      |<-- WebSocket connect ------------|
      |                                  |
      |--- HELLO (X25519_pub + Ed25519_pub + username) -->|
      |<-- HELLO (X25519_pub + Ed25519_pub + username) ---|
      |                                  |
      |  ambos derivam session_key via ECDH + HKDF        |
      |                                  |
      |--- CHALLENGE (nonce 32 bytes) -->|
      |<-- RESPONSE (sign(nonce)) -------|
      |--- OK --------------------------->|
      |                                  |
      |  ratchet inicializado com session_key             |
      |  todas as mensagens: ratchet.encrypt(json)        |
```

### Fluxo de grupo

1. Admin cria grupo: gera `group_id`, `group_key`, assina `GroupState` com Ed25519
2. Membro convida peer: envia `invite` com o `GroupState` atual via DM
3. Convidado envia `join_request` ao admin
4. Admin adiciona membro, incrementa versao, re-assina e faz broadcast do novo `GroupState`
5. Kick/leave: admin rotaciona `group_key`, incrementa versao, re-assina e faz broadcast

---

## Estrutura do projeto

```
teamFlow/
├── run.py              entry point
├── identity.py         identidade local (keypair Ed25519)
├── crypto.py           primitivas criptograficas
├── ratchet.py          symmetric double ratchet
├── discovery.py        descoberta UDP na LAN
├── peer_server.py      servidor WebSocket P2P
├── peer_client.py      cliente WebSocket P2P
├── protocol.py         payloads e dispatcher de mensagens
├── node.py             orquestrador central
├── groups.py           logica de grupos
├── message_store.py    store efemero de mensagens
├── db.py               persistencia SQLite
├── file_transfer.py    transferencia de arquivos
├── tui.py              interface TUI (Textual)
├── avatar.py           identicons para o terminal
├── wordlist.py         fingerprint mnemonica
├── requirements.txt
└── data/               gerado em runtime (ignorado pelo git)
    ├── identity.key    private key (chmod 600)
    ├── identity.name   username
    └── <usuario>.db    banco pessoal
```
