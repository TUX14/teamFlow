"""Entry point do TeamFlow P2P."""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

# Windows usa ProactorEventLoop por padrão (Python 3.8+), que não suporta
# DatagramProtocol (UDP). SelectorEventLoop funciona em todas as plataformas.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from identity import load_or_create
from node import Node
from tui import TeamFlowApp

if __name__ == "__main__":
    identity = load_or_create()
    node     = Node(identity)
    TeamFlowApp(node).run()
