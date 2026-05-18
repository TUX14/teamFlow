"""Interface TUI do TeamFlow — Textual."""

from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
import sys
from typing import TYPE_CHECKING

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button, Collapsible, DataTable, Input,
    Label, ListItem, ListView, RichLog, Static,
)

if TYPE_CHECKING:
    from node import Node


# ── Modais ────────────────────────────────────────────────────────────────────

class SetupModal(ModalScreen[bool]):
    """
    Primeiro acesso — cria nova identidade.
    Solicita username e senha; chama identity.create() e node.set_identity().
    """

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("[bold]TeamFlow — primeiro acesso[/bold]")
            yield Label("Como você quer ser conhecido na rede?")
            yield Input(placeholder="nome (mín. 2 caracteres)", id="name-input")
            yield Label("Crie uma senha para proteger sua chave privada:")
            yield Input(placeholder="senha (mín. 4 caracteres)", id="pw-input",  password=True)
            yield Input(placeholder="confirme a senha",          id="pw2-input", password=True)
            yield Button("Criar identidade", variant="primary", id="confirm")

    def on_mount(self) -> None:
        v = self.query_one(Vertical)
        v.styles.width            = "100%"
        v.styles.height           = "100%"
        v.styles.padding          = (4, 8)
        v.styles.align_horizontal = "center"
        v.styles.align_vertical   = "middle"
        self.query_one("#name-input").focus()

    def on_input_submitted(self, _: Input.Submitted) -> None:
        self._save()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "confirm":
            self._save()

    def _save(self) -> None:
        from identity import create as identity_create
        name = self.query_one("#name-input",  Input).value.strip()
        pw   = self.query_one("#pw-input",    Input).value
        pw2  = self.query_one("#pw2-input",   Input).value
        if len(name) < 2:
            self.query_one("#name-input", Input).placeholder = "mínimo 2 caracteres!"
            return
        if len(pw) < 4:
            self.notify("Senha precisa ter no mínimo 4 caracteres.", severity="error")
            return
        if pw != pw2:
            self.notify("As senhas não coincidem.", severity="error")
            return
        identity = identity_create(name, pw)
        self.app.node.set_identity(identity)  # type: ignore[attr-defined]
        self.dismiss(True)


class LoginModal(ModalScreen[bool]):
    """
    Autenticação com senha para identidade já existente (formato cifrado).
    Chama identity.load_encrypted() e node.set_identity().
    Exibe erro inline se a senha estiver incorreta — não fecha o modal.
    """

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("[bold]TeamFlow — autenticação[/bold]")
            yield Label("Digite sua senha para desbloquear a identidade:")
            yield Input(placeholder="senha", id="pw-input", password=True)
            yield Button("Entrar", variant="primary", id="confirm")

    def on_mount(self) -> None:
        v = self.query_one(Vertical)
        v.styles.width            = "100%"
        v.styles.height           = "100%"
        v.styles.padding          = (4, 8)
        v.styles.align_horizontal = "center"
        v.styles.align_vertical   = "middle"
        self.query_one(Input).focus()

    def on_input_submitted(self, _: Input.Submitted) -> None:
        self._login()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "confirm":
            self._login()

    def _login(self) -> None:
        from identity import load_encrypted
        pw = self.query_one(Input).value
        try:
            identity = load_encrypted(pw)
            self.app.node.set_identity(identity)  # type: ignore[attr-defined]
            self.dismiss(True)
        except ValueError:
            self.notify("Senha incorreta. Tente novamente.", severity="error")
            self.query_one(Input).clear()
            self.query_one(Input).focus()


class _UsernameModal(ModalScreen[bool]):
    """
    Define username para identidade legada que não tem nome gravado.
    Não cria nova chave — apenas salva o username.
    """

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("[bold]TeamFlow — defina seu nome[/bold]")
            yield Input(placeholder="nome (mín. 2 caracteres)", id="name-input")
            yield Button("Confirmar", variant="primary", id="confirm")

    def on_mount(self) -> None:
        v = self.query_one(Vertical)
        v.styles.width            = "100%"
        v.styles.height           = "100%"
        v.styles.padding          = (4, 8)
        v.styles.align_horizontal = "center"
        v.styles.align_vertical   = "middle"
        self.query_one(Input).focus()

    def on_input_submitted(self, _: Input.Submitted) -> None:
        self._save()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "confirm":
            self._save()

    def _save(self) -> None:
        from identity import save_username
        name = self.query_one(Input).value.strip()
        if len(name) < 2:
            self.query_one(Input).placeholder = "mínimo 2 caracteres!"
            return
        save_username(name)
        self.app.node.identity.username = name  # type: ignore[attr-defined]
        self.dismiss(True)


class TofuModal(ModalScreen[bool]):
    """Alerta de segurança TOFU — personificação ou mudança de chave."""

    def __init__(self, pub_key_hash: str, alert: dict) -> None:
        super().__init__()
        self._hash  = pub_key_hash
        self._alert = alert

    def compose(self) -> ComposeResult:
        name  = self._alert["username"]
        words = self._alert["words"]
        with Vertical():
            yield Label("[bold red]⚠  ALERTA DE SEGURANÇA[/bold red]")
            known_words = self._alert.get("known_words", "desconhecida")
            yield Label(
                f'[bold]{name}[/bold] está usando uma chave '
                f'[bold red]diferente[/bold red] da registrada.'
            )
            yield Label("Pode ser tentativa de personificação.")
            yield Label("")
            yield Label("Chave registrada (verificada anteriormente):")
            yield Label(f"[bold green]{known_words}[/bold green]")
            yield Label("Chave atual (não verificada):")
            yield Label(f"[bold yellow]{words}[/bold yellow]")
            yield Label("")
            yield Label("Confirme a identidade por outro canal antes de aceitar.")
            with Horizontal():
                yield Button("Aceitar nova chave", variant="warning", id="accept")
                yield Button("Rejeitar",           variant="error",   id="reject")

    def on_mount(self) -> None:
        v = self.query_one(Vertical)
        v.styles.width            = "100%"
        v.styles.height           = "100%"
        v.styles.padding          = (4, 8)
        v.styles.align_horizontal = "center"
        v.styles.align_vertical   = "middle"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        accepted = event.button.id == "accept"
        if accepted:
            self.app.node.dismiss_tofu(self._hash)  # type: ignore[attr-defined]
        # Remove do conjunto para que futuros alertas do mesmo peer sejam exibidos.
        self.app._shown_tofu.discard(self._hash)  # type: ignore[attr-defined]
        self.dismiss(accepted)


class HelpModal(ModalScreen[None]):
    """Referência de todos os comandos."""

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("[bold]Comandos disponíveis[/bold]")
            yield Label("")
            yield Label("[bold cyan]Em qualquer tela:[/bold cyan]")
            yield Label("  /help                esta ajuda")
            yield Label("  /quit                sai do TeamFlow")
            yield Label("  /me                  sua identidade e fingerprint")
            yield Label("  /peers               lista peers online")
            yield Label("  /groups              lista seus grupos")
            yield Label("  /status              estado geral da rede")
            yield Label("  /rename <nome>       muda seu nome na rede")
            yield Label("  /clock               mostra data e hora atual")
            yield Label("")
            yield Label("[bold cyan]Tela inicial:[/bold cyan]")
            yield Label("  /newgroup <nome>     cria um novo grupo")
            yield Label("")
            yield Label("[bold cyan]No chat:[/bold cyan]")
            yield Label("  /back                volta para a lista")
            yield Label("  /whois               fingerprint do peer ativo")
            yield Label("  /clear               limpa o log")
            yield Label("  /ping [nome]         latência do peer (padrão: atual)")
            yield Label("  /invite <nome>       convida peer para o grupo")
            yield Label("  /kick <nome>         remove membro do grupo (admin)")
            yield Label("  /leave               sai do grupo")
            yield Label("  /dissolve            dissolve o grupo (somente admin)")
            yield Label("  /send <caminho>      envia arquivo (sem espaços no caminho)")
            yield Label("  /accept              aceita arquivo recebido")
            yield Label("  /reject              recusa arquivo recebido")
            yield Label("")
            yield Button("Fechar", variant="primary", id="close")

    def on_mount(self) -> None:
        v = self.query_one(Vertical)
        v.styles.width            = "100%"
        v.styles.height           = "100%"
        v.styles.padding          = (4, 8)
        v.styles.align_horizontal = "center"
        v.styles.align_vertical   = "middle"
        self.query_one(Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close":
            self.dismiss()


class OutputModal(ModalScreen[None]):
    """Exibe saída de comandos informativos."""

    def __init__(self, title: str, lines: list[str]) -> None:
        super().__init__()
        self._title = title
        self._lines = lines

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(f"[bold]{self._title}[/bold]")
            yield Label("")
            yield RichLog(id="out", highlight=True, markup=True)
            yield Button("Fechar", variant="primary", id="close")

    def on_mount(self) -> None:
        v = self.query_one(Vertical)
        v.styles.width            = "100%"
        v.styles.height           = "100%"
        v.styles.padding          = (4, 8)
        v.styles.align_horizontal = "center"
        log = self.query_one(RichLog)
        log.styles.height = "1fr"
        for line in self._lines:
            log.write(line)
        self.query_one(Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close":
            self.dismiss()


# ── Base com comandos compartilhados ──────────────────────────────────────────

class _BaseScreen(Screen):
    BINDINGS = []

    def _output(self, title: str, lines: list[str]) -> None:
        self.app.push_screen(OutputModal(title, lines))

    def _shared_command(self, verb: str, arg: str) -> bool:
        """Retorna True se o comando foi tratado aqui."""
        if verb == "help":
            self.app.push_screen(HelpModal())
        elif verb == "quit":
            self.app.call_after_refresh(self.app.action_quit)  # type: ignore[attr-defined]
        elif verb == "me":
            self._cmd_me()
        elif verb == "peers":
            self._cmd_peers()
        elif verb == "groups":
            self._cmd_groups()
        elif verb == "status":
            self._cmd_status()
        elif verb == "rename":
            self._cmd_rename(arg)
        elif verb == "clock":
            self._cmd_clock()
        else:
            return False
        return True

    def _cmd_me(self) -> None:
        from wordlist import pub_to_words
        node  = self.app.node  # type: ignore[attr-defined]
        words = pub_to_words(node.identity.pub_key_bytes.hex())
        key   = node.identity.pub_key_bytes.hex()
        self._output("Identidade", [
            f"Nome         : [bold]{node.identity.username}[/bold]",
            f"Fingerprint  : [yellow]{words}[/yellow]",
            f"Chave pública: [dim]{key[:48]}…[/dim]",
        ])

    def _cmd_peers(self) -> None:
        from wordlist import pub_to_words
        node  = self.app.node  # type: ignore[attr-defined]
        peers = node.registry.all_online()
        if not peers:
            self.notify("Nenhum peer online no momento.", severity="warning")
            return
        lines = [f"Peers online ({len(peers)}):"]
        for p in peers:
            dot = "[green]●[/green]" if p.connected else "[dim]○[/dim]"
            lines.append(f"  {dot} [bold]{p.username}[/bold]  [dim]{pub_to_words(p.public_key_hex)}[/dim]")
        self._output("Peers", lines)

    def _cmd_groups(self) -> None:
        node   = self.app.node  # type: ignore[attr-defined]
        groups = node.groups.all() if node.groups else []
        if not groups:
            self.notify("Você não participa de nenhum grupo.", severity="warning")
            return
        my_hex = node.identity.pub_key_bytes.hex()
        lines  = [f"Grupos ({len(groups)}):"]
        for gs in groups:
            role = "[bold cyan][admin][/bold cyan]" if gs.admin_pub_key_hex == my_hex else ""
            lines.append(f"  [cyan]#[/cyan] [bold]{gs.name}[/bold]  {role}  {len(gs.members)} membros")
        self._output("Grupos", lines)

    def _cmd_status(self) -> None:
        import time
        from node import WS_PORT
        node    = self.app.node  # type: ignore[attr-defined]
        peers   = node.registry.all_online()
        conn    = sum(1 for p in peers if p.connected)
        groups  = node.groups.all() if node.groups else []
        elapsed = int(time.time() - node._start_time)
        h, rem  = divmod(elapsed, 3600)
        m, s    = divmod(rem, 60)
        self._output("Status", [
            f"Usuário     : [bold]{node.identity.username}[/bold]",
            f"Peers online: {len(peers)}  ({conn} conectados)",
            f"Grupos      : {len(groups)}",
            f"Porta WS    : {WS_PORT}",
            f"Uptime      : {h:02d}:{m:02d}:{s:02d}",
        ])

    def _cmd_clock(self) -> None:
        from datetime import datetime
        now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        self.notify(now, title="Hora")

    def _cmd_rename(self, name: str) -> None:
        if not name:
            self.notify("Uso: /rename <novo nome>", severity="warning")
            return
        if len(name) < 2:
            self.notify("Nome precisa ter no mínimo 2 caracteres.", severity="warning")
            return
        from identity import save_username
        node = self.app.node  # type: ignore[attr-defined]
        save_username(name)
        node.identity.username = name
        self.notify(f"Nome alterado para {name}.")


# ── Tela inicial — lista de peers e grupos ────────────────────────────────────

class _GroupItem(ListItem):
    def __init__(self, group_id: str, name: str, admin_pub_key_hex: str) -> None:
        import hashlib
        from avatar import make_chip
        admin_hash = hashlib.sha256(bytes.fromhex(admin_pub_key_hex)).hexdigest()[:32]
        super().__init__(Label(f"{make_chip(admin_hash)} [cyan]#[/cyan] {name}"))
        self.group_id = group_id


class HomeScreen(_BaseScreen):
    _peer_state:  tuple = ()
    _group_state: tuple = ()

    def compose(self) -> ComposeResult:
        with Horizontal(id="self-card"):
            yield Static("", id="self-avatar")
            with Vertical(id="self-info"):
                yield Static("", id="self-name")
                yield Static("", id="self-fp")
        with VerticalScroll(id="list-area"):
            with Collapsible(title="Peers", collapsed=False):
                yield DataTable(id="peer-table", cursor_type="row", show_header=False)
            with Collapsible(title="Grupos", collapsed=False):
                yield ListView(id="group-list")
        yield Input(placeholder="> comando  (/help para ajuda)", id="cmd-input")

    def on_mount(self) -> None:
        card = self.query_one("#self-card")
        card.styles.height  = 4
        card.styles.padding = (0, 2)
        self.query_one("#self-info").styles.padding = (0, 2)
        self.query_one("#list-area").styles.height = "1fr"
        t = self.query_one(DataTable)
        t.add_column("av",   width=5,  key="av")
        t.add_column("s",    width=2,  key="dot")
        t.add_column("nome", width=20, key="nome")
        t.add_column("fp",   width=28, key="fp")
        self._refresh_self_card()
        self.set_interval(0.5, self._poll)
        self.query_one(Input).focus()

    def _refresh_self_card(self) -> None:
        from avatar import make_avatar
        from wordlist import pub_to_words
        node  = self.app.node  # type: ignore[attr-defined]
        words = pub_to_words(node.identity.pub_key_bytes.hex())
        self.query_one("#self-avatar", Static).update(make_avatar(node.identity.pub_key_hash))
        self.query_one("#self-name",   Static).update(f"[bold]{node.identity.username}[/bold]")
        self.query_one("#self-fp",     Static).update(f"[dim]{words}[/dim]")

    def _poll(self) -> None:
        from avatar import make_chip
        from wordlist import pub_to_words
        node = self.app.node  # type: ignore[attr-defined]

        peers     = node.registry.all_online()
        new_peers = tuple((p.pub_key_hash, p.connected) for p in peers)
        if new_peers != self._peer_state:
            self._peer_state = new_peers
            table = self.query_one(DataTable)
            table.clear()
            for peer in peers:
                chip = make_chip(peer.pub_key_hash)
                dot  = "[green]●[/green]" if peer.connected else "[dim]○[/dim]"
                table.add_row(chip, dot, peer.username, pub_to_words(peer.public_key_hex),
                              key=peer.pub_key_hash)

        groups     = node.groups.all() if node.groups else []
        new_groups = tuple(gs.group_id for gs in groups)
        if new_groups != self._group_state:
            self._group_state = new_groups
            lv = self.query_one(ListView)
            lv.clear()
            for gs in groups:
                lv.append(_GroupItem(gs.group_id, gs.name, gs.admin_pub_key_hex))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        peer_hash = event.row_key.value
        if not peer_hash:
            return
        peer = self.app.node.registry.get(peer_hash)  # type: ignore[attr-defined]
        self.app.push_screen(ChatScreen(peer_hash, peer.username if peer else peer_hash[:8]))

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        item = event.item
        if not isinstance(item, _GroupItem):
            return
        node = self.app.node  # type: ignore[attr-defined]
        gs   = node.groups.get(item.group_id) if node.groups else None
        self.app.push_screen(ChatScreen(item.group_id, f"# {gs.name}" if gs else item.group_id[:8]))

    def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        event.input.clear()
        if not text:
            return
        if text.startswith("/"):
            self._command(text[1:])
        else:
            self.notify("Digite um comando. /help para ver a lista.", severity="warning")

    def _command(self, raw: str) -> None:
        parts = raw.strip().split(maxsplit=1)
        verb  = parts[0].lower() if parts else ""
        arg   = parts[1].strip() if len(parts) > 1 else ""
        if self._shared_command(verb, arg):
            return
        if verb == "newgroup":
            if not arg:
                self.notify("Uso: /newgroup <nome>", severity="warning")
                return
            node = self.app.node  # type: ignore[attr-defined]
            if node.groups:
                gs = node.groups.create(arg)
                self.app.push_screen(ChatScreen(gs.group_id, f"# {gs.name}"))
        else:
            self.notify(f"Comando desconhecido: /{verb}  (/help para ver a lista)",
                        severity="error")


# ── Tela de chat ──────────────────────────────────────────────────────────────

class ChatScreen(_BaseScreen):
    def __init__(self, chat_id: str, title: str) -> None:
        super().__init__()
        self.chat_id     = chat_id
        self._title      = title
        self._last_count = -1

    def compose(self) -> ComposeResult:
        with Horizontal(id="peer-header"):
            yield Static("", id="peer-avatar")
            yield Label(self._title, id="chat-title")
        yield RichLog(id="messages", highlight=True, markup=True, wrap=True)
        yield Input(placeholder="> mensagem ou /comando  (/help para ajuda)", id="msg-input")

    def on_mount(self) -> None:
        header = self.query_one("#peer-header")
        header.styles.height         = 4
        header.styles.padding        = (0, 2)
        header.styles.align_vertical = "middle"
        self.query_one("#chat-title").styles.padding = (0, 2)
        self.query_one("#messages").styles.height = "1fr"
        self._refresh_peer_avatar()
        self.query_one(Input).focus()
        self.set_interval(0.5, self._poll)

    def _refresh_peer_avatar(self) -> None:
        import hashlib
        from avatar import make_avatar
        node = self.app.node  # type: ignore[attr-defined]
        peer = node.registry.get(self.chat_id)
        if peer:
            seed = peer.pub_key_hash
        else:
            gs   = node.groups.get(self.chat_id) if node.groups else None
            seed = hashlib.sha256(bytes.fromhex(gs.admin_pub_key_hex)).hexdigest()[:32] if gs else self.chat_id
        self.query_one("#peer-avatar", Static).update(make_avatar(seed))

    def _poll(self) -> None:
        count = len(self.app.node.store.get(self.chat_id))  # type: ignore[attr-defined]
        if count != self._last_count:
            self._last_count = count
            self._render_messages()

    def _render_messages(self) -> None:
        from avatar import make_chip
        node = self.app.node  # type: ignore[attr-defined]
        log  = self.query_one("#messages", RichLog)
        log.clear()
        my_chip = make_chip(node.identity.pub_key_hash)
        for m in node.store.get(self.chat_id):
            ts = datetime.fromtimestamp(m.ts).strftime("%H:%M")
            if m.sender_name == "📎":
                log.write(f"[dim]{ts}[/dim] 📎 {m.text}")
            elif m.is_mine:
                log.write(f"[dim]{ts}[/dim] {my_chip} [bold cyan]você[/bold cyan]: {m.text}")
            else:
                chip = make_chip(m.sender_hash) if m.sender_hash else ""
                log.write(f"[dim]{ts}[/dim] {chip} [bold]{m.sender_name}[/bold]: {m.text}")
        log.scroll_end(animate=False)

    def _sys(self, text: str) -> None:
        self.query_one("#messages", RichLog).write(f"[dim italic]{text}[/dim italic]")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        event.input.clear()
        if not text:
            return
        if text.startswith("/"):
            self._command(text[1:])
        else:
            self._send(text)

    def _send(self, text: str) -> None:
        node = self.app.node  # type: ignore[attr-defined]
        if node.groups and node.groups.get(self.chat_id):
            node.send_group_msg(self.chat_id, text)
        else:
            node.send_dm(self.chat_id, text)
        self._render_messages()

    def _command(self, raw: str) -> None:
        parts = raw.strip().split(maxsplit=1)
        verb  = parts[0].lower() if parts else ""
        arg   = parts[1].strip() if len(parts) > 1 else ""
        if self._shared_command(verb, arg):
            return
        dispatch = {
            "back":     lambda _: self.app.pop_screen(),
            "clear":    lambda _: self.query_one("#messages", RichLog).clear(),
            "whois":    self._cmd_whois,
            "ping":     self._cmd_ping,
            "invite":   self._cmd_invite,
            "kick":     self._cmd_kick,
            "leave":    lambda _: self._cmd_leave(),
            "dissolve": lambda _: self._cmd_dissolve(),
            "send":     self._cmd_send,
            "accept":   lambda _: self._cmd_accept(),
            "reject":   lambda _: self._cmd_reject(),
        }
        fn = dispatch.get(verb)
        if fn:
            fn(arg)
        else:
            self.notify(f"Comando desconhecido: /{verb}  (/help para ver a lista)",
                        severity="error")

    def _cmd_whois(self, _: str) -> None:
        from wordlist import pub_to_words
        peer = self.app.node.registry.get(self.chat_id)  # type: ignore[attr-defined]
        if peer:
            status = "[green]●[/green] conectado" if peer.connected else "[dim]○[/dim] offline"
            self._sys(
                f"[bold]{peer.username}[/bold]  {status}\n"
                f"fingerprint : [yellow]{pub_to_words(peer.public_key_hex)}[/yellow]\n"
                f"chave pública: [dim]{peer.public_key_hex[:48]}…[/dim]"
            )
        else:
            self.notify("Peer não está no registry.", severity="warning")

    def _cmd_ping(self, arg: str) -> None:
        node = self.app.node  # type: ignore[attr-defined]
        if arg:
            peer = next(
                (p for p in node.registry.all_connected() if p.username.lower() == arg.lower()),
                None,
            )
        else:
            peer = node.registry.get(self.chat_id)
        if peer is None:
            self.notify("Peer não encontrado ou não conectado.", severity="error")
            return
        self._sys(f"Pingando [bold]{peer.username}[/bold]…")

        async def _do_ping() -> None:
            try:
                latency = await asyncio.wait_for(
                    asyncio.shield(node.send_ping(peer.pub_key_hash)), timeout=5.0
                )
                self._sys(f"Pong de [bold]{peer.username}[/bold]: [green]{latency:.1f} ms[/green]")
            except asyncio.TimeoutError:
                self._sys(f"[red]Timeout[/red]: {peer.username} não respondeu em 5s.")

        self.run_worker(_do_ping())

    def _cmd_invite(self, name: str) -> None:
        if not name:
            self.notify("Uso: /invite <nome>", severity="warning")
            return
        node = self.app.node  # type: ignore[attr-defined]
        if not (node.groups and node.groups.get(self.chat_id)):
            self.notify("Abra um grupo primeiro.", severity="warning")
            return
        target = next(
            (p for p in node.registry.all_connected() if p.username.lower() == name.lower()),
            None,
        )
        if target is None:
            self.notify(f"Peer '{name}' não está conectado.", severity="error")
            return
        node.send_invite(self.chat_id, target.pub_key_hash)
        self.notify(f"Convite enviado para {target.username}.")

    def _cmd_kick(self, name: str) -> None:
        if not name:
            self.notify("Uso: /kick <nome>", severity="warning")
            return
        node = self.app.node  # type: ignore[attr-defined]
        if not node.kick_member(self.chat_id, name):
            self.notify(f"Não foi possível remover '{name}'. Verifique se você é admin e o nome está correto.",
                        severity="error")
            return
        self.notify(f"{name} removido do grupo.")

    def _cmd_leave(self) -> None:
        node = self.app.node  # type: ignore[attr-defined]
        if not (node.groups and node.groups.get(self.chat_id)):
            self.notify("Chat atual não é um grupo.", severity="warning")
            return
        node.leave_group(self.chat_id)
        self.notify("Saiu do grupo.")
        self.app.pop_screen()

    def _cmd_send(self, arg: str) -> None:
        if not arg:
            self.notify("Uso: /send <caminho>  (sem espaços)", severity="warning")
            return
        if " " in arg:
            self.notify("Caminho não pode ter espaços. Renomeie o arquivo.", severity="error")
            return
        node = self.app.node  # type: ignore[attr-defined]
        if node.groups and node.groups.get(self.chat_id):
            self.notify("Envio de arquivos disponível apenas em DMs.", severity="warning")
            return
        path = Path(arg).expanduser().resolve()
        if not path.is_file():
            self.notify("Arquivo não encontrado.", severity="error")
            return
        self.run_worker(node.send_file(self.chat_id, path))

    def _cmd_accept(self) -> None:
        node = self.app.node  # type: ignore[attr-defined]
        if self.chat_id not in node._incoming_offers:
            self.notify("Nenhuma oferta pendente.", severity="warning")
            return
        node.accept_file(self.chat_id)

    def _cmd_reject(self) -> None:
        node = self.app.node  # type: ignore[attr-defined]
        if self.chat_id not in node._incoming_offers:
            self.notify("Nenhuma oferta pendente.", severity="warning")
            return
        node.reject_file(self.chat_id)

    def _cmd_dissolve(self) -> None:
        node = self.app.node  # type: ignore[attr-defined]
        if not (node.groups and node.groups.am_admin(self.chat_id)):
            self.notify("Você não é admin deste grupo.", severity="error")
            return
        node.dissolve_group(self.chat_id)
        self.notify("Grupo dissolvido.")
        self.app.pop_screen()


# ── App ───────────────────────────────────────────────────────────────────────

class TeamFlowApp(App):
    TITLE                   = "TeamFlow"
    BINDINGS                = []
    COMMANDS                = set()
    COMMAND_PALETTE_BINDING = ""
    ENABLE_COMMAND_PALETTE  = False

    def __init__(self, node: Node) -> None:
        super().__init__()
        self.node = node
        self._shown_tofu: set[str] = set()

    async def on_mount(self) -> None:
        from identity import key_status, load_legacy
        status = key_status()

        if status == "none":
            # Primeiro acesso: cria identidade com senha
            await self.push_screen(SetupModal(), self._after_auth)

        elif status == "encrypted":
            # Identidade existente protegida por senha
            await self.push_screen(LoginModal(), self._after_auth)

        else:
            # Formato legado (32 bytes raw) — carrega sem senha
            identity = load_legacy()
            self.node.set_identity(identity)
            if not identity.username:
                # Edge case: chave existe mas username não foi salvo
                await self.push_screen(_UsernameModal(), self._after_auth)
            else:
                self.notify(
                    "Identidade legada (sem proteção por senha). "
                    "Apague data/identity.key e reinicie para criar com senha.",
                    severity="warning", timeout=10,
                )
                await self._start()

    async def _after_auth(self, result: bool | None) -> None:
        if result:
            await self._start()

    async def _start(self) -> None:
        await self.node.start()
        self.node.on_event(self._on_node_event)
        self.set_interval(1.0, self._check_tofu)
        await self.push_screen(HomeScreen())

    def _on_node_event(self, event: str, data) -> None:
        if event == "message":
            # Toca bell do terminal apenas se o usuário não estiver nessa conversa.
            current = self.screen
            if not (hasattr(current, "chat_id") and current.chat_id == data):
                sys.stdout.write("\a")
                sys.stdout.flush()
        elif event == "file_offer":
            from file_transfer import human_size
            self.notify(
                f"📎 {data.sender_name}: {data.filename} ({human_size(data.size)})"
                f" — abra o chat e /accept",
                timeout=15,
            )
        elif event == "peer_renamed":
            old = data["old_username"]
            new = data["new_username"]
            self.notify(f"{old} alterou o nome para {new}.", title="Rename", timeout=8)

    def _check_tofu(self) -> None:
        for h, alert in list(self.node.tofu_alerts.items()):
            if h not in self._shown_tofu:
                self._shown_tofu.add(h)
                self.push_screen(TofuModal(h, alert))

    async def action_quit(self) -> None:
        await self.node.stop()
        self.exit()
