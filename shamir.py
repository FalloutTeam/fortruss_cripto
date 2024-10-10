"""
Этот модуль использует объект Shamir из Crypto.Protocol.SecretSharing который может разбивать только секреты длинной
не более 16 байт.
В модуле реализованно:
 1. Разбиение секрета длиной 32 байта на две части
 2. Использование разбиение по схеме Шамира для каждой из частей с помощью встроенного метода Shamir.split()
 3. Объединение частей половин секретов попарно и кодирование в формате HEX для получения частей секрета
 4. Получение секрета из частей при достаточном количестве
"""

from Crypto.Protocol.SecretSharing import Shamir

class Shamir256:
    @staticmethod
    def split_secret(secret: bytes, num_shares: int, num_required: int) -> list[tuple[int, str]]:
        if len(secret) != 32:
            raise ValueError(f"Unacceptable secret size ({len(secret)}). Expected 32 bytes")

        shamir = Shamir()
        secret1 , secret2 = secret[:16], secret[16:]
        id1, shares1 = list(zip(*shamir.split(num_required, num_shares, secret1, False)))
        id2, shares2 = list(zip(*shamir.split(num_required, num_shares, secret2, False)))
        # assert id1 == id2
        shares = [(pair[0] + pair[1]).hex() for pair in zip(shares1, shares2)]

        return list(zip(id1, shares))

    @staticmethod
    def combine_secret(shares:list[tuple[int, str]], num_required: int) -> bytes:
        if len(shares) < num_required:
            raise ValueError(f"Got {len(shares)} shares. At least {num_required} shares required!")

        shamir = Shamir()
        ids, shares2 = zip(*shares)
        shares2 = [bytes.fromhex(share) for share in shares2]
        shares2= [(share[:16], share[16:]) for share in shares2]
        secret1_shares, secret2_shares = zip(*shares2)
        secret1 = shamir.combine(list(zip(ids, secret1_shares)), False)
        secret2 = shamir.combine(list(zip(ids, secret2_shares)), False)

        return secret1 + secret2
