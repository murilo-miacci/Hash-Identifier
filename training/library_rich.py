from time import sleep

from rich.console import Console
from rich.panel import Panel
from rich.progress import track
from rich.table import Table

console = Console()

pedidos = [
    {"produto": "Caderno", "quantidade": 2, "estoque": 5},
    {"produto": "Caneta", "quantidade": 10, "estoque": 7},
    {"produto": "Mochila", "quantidade": 1, "estoque": 3},
    {"produto": "Lápis", "quantidade": 10, "estoque": 5},
    {"produto": "Borracha", "quantidade": 3, "estoque": 1},
    {"produto": "Apontador", "quantidade": 1, "estoque": 8},
    {"produto": "Lapiseira", "quantidade": 3, "estoque": 3},
    {"produto": "Régua", "quantidade": 1, "estoque": 2},
]

console.print(Panel("[bold blue]Relatório de Pedidos[/bold blue]"))

tabela = Table(title="Conferência de Estoque")
tabela.add_column("Produto")
tabela.add_column("Quantidade", justify="right")
tabela.add_column("Estoque", justify="right")
tabela.add_column("Situação")

tabela_em_falta = Table(title="[red]Em falta[/red]")
tabela_em_falta.add_column("Produto")
tabela_em_falta.add_column("Faltam", justify="right")

produtos_em_falta = 0
unidades_em_falta = 0

for pedido in track(pedidos, description="Conferindo..."):
    sleep(0.1)
    disponivel = pedido["estoque"] >= pedido["quantidade"]
    restante = pedido["estoque"] - pedido["quantidade"]
    if restante < 0:
        situacao = "[red]Em falta[/red]"
    elif restante == 0:
        situacao = "[gray70]Acabou estoque[/gray70]"
    elif 1 <= restante <= 2:
        situacao = "[yellow]Estoque baixo[/yellow]"
    else:
        situacao = "[green]Disponível[/green]"

    tabela.add_row(
        pedido["produto"],
        str(pedido["quantidade"]),
        str(pedido["estoque"]),
        situacao,
    )

    if not disponivel:
        tabela_em_falta.add_row(
            pedido["produto"], str(pedido["quantidade"] - pedido["estoque"])
        )
        produtos_em_falta += 1
        unidades_em_falta += pedido["quantidade"] - pedido["estoque"]

console.print(tabela)
console.print(tabela_em_falta)

print(f"\nItens faltando: {produtos_em_falta}")
print(f"\nUnidades faltando: {unidades_em_falta}\n")
