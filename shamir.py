import random
import secrets
import multiprocessing


class Shamir256:
    def __init__(self, divisor: int = 2 ** 64, high_value: int = 2 ** 128):
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

    def __count_sub_secret(self, secret: int, threshold: int, num_shares: int) -> list[tuple[int, int]]:
        coeffs = [secret] + self.__generate_coefficients(threshold)
        shares = list()

        for _ in range(num_shares):
            x = random.randint(1, self.high_value)
            y = self.__evaluate_polynomial_horner_scheme(x, coeffs)
            shares.append((x, y))

        return shares

    def split_secret(self, secret: bytes, threshold: int, num_shares: int) -> list[tuple[int, bytes]]:
        if len(secret) != 32:
            raise ValueError(f"Unacceptable secret size ({len(secret)}). Expected 32 bytes")
        secret_parts = self.__bytes_to_ints(secret)

        with multiprocessing.Pool(processes=4) as pool:
            secret_parts_shares = pool.map(self.__count_sub_secret, secret_parts)
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
