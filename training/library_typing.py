from typing import Literal

# def buscar_preco(produtos: dict[str, float], produto: str) -> float | None:
#     return produtos.get(produto)


# def calcular_total(
#     produtos: dict[str, float], produto: str, quantidade: int
# ) -> float | None:
#     preco = buscar_preco(produtos, produto)
#     return None if preco is None else preco * quantidade


# def calcular_carrinho(
#     produtos: dict[str, float], itens: list[tuple[str, int]]
# ) -> float | None:
#     total = 0.0
#     for nome, quantidade in itens:
#         subtotal = calcular_total(produtos, nome, quantidade)
#         if subtotal is None:
#             return "Itens incorretos/desconhecidos no carrinho"
#         total += subtotal
#     return total

# class ItemCarrinho(TypedDict):
#     nome: str
#     quantidade: int
#     observacao: NotRequired[str]


# def mostrar_itens(itens: list[ItemCarrinho]) -> str:
#     mensagem: str = ""
#     for item in itens:
#         mensagem += f"{item['quantidade']}x {item['nome']}"
#         if "observacao" in item:
#         mensagem += f" ({item['observacao']})"
#     mensagem += ", "
# return mensagem[:-2]

Status = Literal["pendente", "pago", "cancelado"]


def descrever_status(status: Status) -> str:
    mensagens = {
        "pendente": "Aguardando pagamento",
        "pago": "Pagamento confirmado",
        "cancelado": "Pedido cancelado",
    }
    return mensagens.get(status, "Status não identificado")
