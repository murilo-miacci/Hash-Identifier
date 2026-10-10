from dataclasses import dataclass


@dataclass
class Produto:
    nome: str
    preco: float
    estoque: int = 0

    def valor_em_estoque(self):
        return self.preco * self.estoque

    def vender(self, quantidade):
        if quantidade < 0:
            raise ValueError("A quantidade deve ser positiva")
        if quantidade > self.estoque:
            raise ValueError("Estoque insuficiente")
        else:
            self.estoque -= quantidade


cafe = Produto("Café", 18.50, 4)
cha = Produto("Chá", 12.00)

cafe.vender(2)
print(cafe.estoque)
cafe.vender(3)
