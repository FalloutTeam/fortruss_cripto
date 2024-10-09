import random
import json
import secrets
import multiprocessing
from functools import partial

class Shamir256:
    def __init__(self, divisor: int = 2 ** 64, high_value: int = 2 ** 65):
        self.divisor = divisor
        self.high_value = high_value

    @staticmethod
    def __bytes_to_ints(secret: bytes) -> list[tuple[int, int]]:
        chunks = [secret[i: i+8] for i in range(0, len(secret), 8)]
        secret_int_parts = [(i, int.from_bytes(chunk, "big")) for i, chunk in enumerate(chunks)]
        return secret_int_parts

    def __generate_coefficients(self, threshold: int) -> list[int]:
        return [secrets.randbelow(self.high_value) for _ in range(threshold - 1)]

    def __evaluate_polynomial_horner_scheme(self, x: int, coefficients: list) -> int:
        result = 0
        for coeff in reversed(coefficients):
            result = result * x + coeff
        return result % self.divisor

    def __add_paddings(self, s: bytes) -> bytes:
        if len(s) < 150:
            return s + bytes(0) * (150 - len(s))
        return s

    def __count_sub_secret(self, part: tuple[int, int], threshold: int, num_shares: int)\
            -> dict[str: int, str: list[tuple[int, int]]]:
        secret, secret_id = part
        coeffs = [secret] + self.__generate_coefficients(threshold)
        shares = list()

        for _ in range(num_shares):
            x = random.randint(1, self.high_value)
            y = self.__evaluate_polynomial_horner_scheme(x, coeffs)
            shares.append((x, y))
        response = {
            "id": secret_id,
            "shares": shares,
        }
        return response

    @staticmethod
    def __part_shares_to_bytes(secret_parts_shares: list[dict[str: int, str: list[tuple[int, int]]]])\
            -> list[tuple[int, bytes]]:
        shares = [s["shares"] for s in sorted(secret_parts_shares, key=lambda d: d["id"])]
        secret_shares = list(enumerate(map(json.dumps, list(zip(*shares)))))


    def split_secret(self, secret: bytes, threshold: int, num_shares: int) -> list[tuple[int, bytes]]:
        if len(secret) != 32:
            raise ValueError(f"Unacceptable secret size ({len(secret)}). Expected 32 bytes")
        secret_parts = self.__bytes_to_ints(secret)
        secret_count_with_param = partial(self.__count_sub_secret, threshold=threshold, num_shares=num_shares)
        secret_shares = list()

        with multiprocessing.Pool(processes=4) as pool:
            secret_parts_shares = pool.map(secret_count_with_param, secret_parts)

        for part_shares in secret_parts_shares:

            json.dumps()

        return secret_shares
"""
- pool.map() - как добавить дополнительные параметры
- мастер-секрет разбивается на 4 подсекрета
- каждый из подсекретов разбивается на части (кол-вом num_shares)
- от каждого подсекрета берётся одна часть в кучку
- получится num_shares кучек по 4 части в каждой
- для каждой кучки провести шифрование, чтобы потом можно было извлечь каждую часть и
 определить к какому подсекрету она относится
- зашифрованные кучки и есть части мастер-ключа, которые раздаются админам
- при объединении своих частей мастер-ключа,
 каждая из частей расшифровывается в кучку из 4х точек от разных подсекретов
- если частей достаточно, то эти кучки разбиваются по подсекретам
- новые разбивки по точкам каждого подсекрета объединяются в подсекрет
- подсекреты, соблюдая порядок, объединяются в секрет
- секрет возвращается в формате байт
"""
