"""
Avatares pixel-art coloridos para o terminal.

Técnica: caractere ▀ (half-block) com cores RGB no foreground (pixel topo)
e background (pixel base) — cada char = 2 pixels, corrigindo o aspecto 2:1
do terminal e produzindo um bloco visualmente quadrado.

Simetria horizontal (estilo identicon) para visual reconhecível.
Aceita qualquer string como seed: pub_key_hash, group_id, etc.
"""

import hashlib


def _palette(identifier: str):
    """Deriva paleta de 4 cores a partir do identificador."""
    seed = hashlib.sha256(identifier.encode()).digest()
    data = bytearray()
    chunk = seed
    while len(data) < 32:
        data.extend(chunk)
        chunk = hashlib.sha256(chunk).digest()

    def rgb(off):
        return (data[off % 32], data[(off + 1) % 32], data[(off + 2) % 32])

    dark   = tuple(max(c - 180, 10) for c in rgb(0))
    light1 = rgb(3)
    light2 = rgb(6)
    return (dark, light1, light2, light1), data


def make_avatar(identifier: str, size: int = 4) -> str:
    """
    Avatar mini: `size`×`size` px, renderizado em `size` colunas × `size//2` linhas.
    Padrão size=4 → 4 chars largura × 2 chars altura.
    """
    palette, data = _palette(identifier)
    half = size // 2
    pixels: list[list[tuple]] = []
    for row in range(size):
        row_half = []
        for col in range(half):
            i = (row * half + col + 9) % len(data)
            b = data[i]
            idx = (b >> ((col % 4) * 2)) & 0x3
            row_half.append(palette[idx])
        pixels.append(row_half + row_half[::-1])

    lines = []
    for row in range(0, size, 2):
        line = ""
        for col in range(size):
            top = pixels[row][col]
            bot = pixels[row + 1][col] if row + 1 < size else (0, 0, 0)
            line += (
                f"[rgb({top[0]},{top[1]},{top[2]})"
                f" on rgb({bot[0]},{bot[1]},{bot[2]})]▀[/]"
            )
        lines.append(line)

    return "\n".join(lines)


def make_chip(identifier: str) -> str:
    """
    Primeira linha do avatar size=4 — 4 chars × 1 linha com padrão de pixels.
    Usável inline em tabelas e mensagens.
    """
    return make_avatar(identifier, size=4).split("\n")[0]
