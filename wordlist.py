"""
Fingerprint mnemônica — converte chave pública em palavras portuguesas.

Cada byte dos primeiros N bytes do pub_key_hex mapeia para uma palavra da
lista de 256 entradas.  5 palavras = 40 bits = ~1 trilhão de combinações,
suficiente para identificação humana sem ambiguidade.

Uso:
    from wordlist import pub_to_words
    print(pub_to_words("a3f8c2d1..."))  # "corvo · pedra · delta · nuvem · farol"
"""

WORDS: list[str] = [
    # 0x00 – 0x0F
    "abismo", "aceno", "aço", "agulha", "alarme", "alvo", "âncora", "anel",
    "anzol", "arco", "ardor", "areia", "arma", "aroma", "asa", "astro",
    # 0x10 – 0x1F
    "átomo", "atum", "aureo", "aveia", "aviso", "azedo", "azul", "balsa",
    "bambu", "banco", "banda", "barco", "barril", "basalto", "beco", "beijo",
    # 0x20 – 0x2F
    "bigode", "bilha", "bispo", "bloco", "bolsa", "bomba", "borda", "bosque",
    "brasa", "bravo", "brilho", "bronze", "bruma", "bruxa", "bulbo", "busca",
    # 0x30 – 0x3F
    "cabra", "cacho", "caju", "calma", "campo", "canal", "canto", "carga",
    "carta", "casca", "casco", "cedro", "cepa", "cerco", "chama", "chave",
    # 0x40 – 0x4F
    "chuva", "cobra", "cobre", "colmo", "corvo", "costa", "couro", "cravo",
    "cripta", "crivo", "cume", "dados", "dardo", "desvio", "dique", "dobra",
    # 0x50 – 0x5F
    "domo", "dragão", "duelo", "duna", "ebano", "eco", "eixo", "elmo",
    "embolo", "enxó", "espada", "espiga", "estaca", "estepe", "estopa", "estufa",
    # 0x60 – 0x6F
    "faca", "fagulha", "farol", "feixe", "ferro", "fio", "flecha", "floco",
    "folha", "forno", "fosso", "frasco", "freio", "fronde", "funil", "fuzil",
    # 0x70 – 0x7F
    "gancho", "garfo", "garra", "gaveta", "gelo", "globo", "golfo", "grade",
    "granito", "graveto", "grilo", "grota", "grude", "gruta", "guizo", "guldo",
    # 0x80 – 0x8F
    "haste", "helice", "hiena", "hino", "hulha", "iceberg", "ígneo", "ilha",
    "íman", "indigo", "ingot", "íris", "isca", "ítem", "javali", "jato",
    # 0x90 – 0x9F
    "joelho", "joia", "junco", "lastro", "lava", "leme", "leste", "liame",
    "lima", "lixa", "loja", "lona", "lorpa", "losango", "lótus", "lúpulo",
    # 0xA0 – 0xAF
    "maça", "malha", "manto", "mapa", "marco", "mastro", "maxila", "meandro",
    "mecha", "menir", "mergulho", "mirra", "módulo", "moeda", "mosaico", "motor",
    # 0xB0 – 0xBF
    "muro", "musgo", "navio", "nebula", "nevoeiro", "nódulo", "nômade", "nórdico",
    "norte", "nuca", "nuvem", "ocre", "ódio", "olmo", "ônix", "órbita",
    # 0xC0 – 0xCF
    "orbe", "orça", "órgão", "osso", "ouriço", "palheta", "parafuso", "parede",
    "pasto", "pedra", "pelica", "pente", "peão", "pilar", "pinha", "pistão",
    # 0xD0 – 0xDF
    "pivô", "placa", "plano", "plasma", "platô", "pluma", "poço", "polvo",
    "ponta", "pórtico", "prego", "prima", "prisma", "proa", "pulso", "punho",
    # 0xE0 – 0xEF
    "quartzo", "queda", "quilha", "quisto", "racho", "raio", "remo", "resina",
    "risco", "rocha", "roda", "rosca", "rota", "runa", "sabre", "safira",
    # 0xF0 – 0xFF
    "salvo", "seixo", "selva", "seta", "silício", "silo", "sino", "siroco",
    "sorte", "talude", "tábua", "tocha", "torção", "trama", "trilho", "zinco",
]

assert len(WORDS) == 256, f"wordlist tem {len(WORDS)} palavras, esperado 256"


def pub_to_words(pub_key_hex: str, count: int = 5) -> str:
    """Retorna N palavras separadas por ' · ' derivadas da chave pública."""
    raw = bytes.fromhex(pub_key_hex)
    return " · ".join(WORDS[raw[i]] for i in range(count))
