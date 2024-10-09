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


def recover_secret(shares, p):
    """Восстановление секрета с использованием интерполяции Лагранжа"""
    x_s, y_s = zip(*shares)
    return lagrange_interpolation(0, x_s, y_s, p)


# Параметры схемы Шамира
k = 3  # Минимальное количество частей для восстановления секрета
n = 5  # Общее количество частей
p = 2 ** 257 - 93  # Простое число, которое больше, чем 256-битное значение

# Генерация 32-байтного ключа (256 бит)
secret_key = int.from_bytes(os.urandom(32), byteorder='big')

print(f"Секрет (ключ): {secret_key}")

# Разделяем секрет на n частей с минимальным порогом k
shares = split_secret(secret_key, k, n, p)

print("\nЧасти секрета:")
for i, share in enumerate(shares):
    print(f"Часть {i + 1}: (x={share[0]}, y={share[1]})")

# Восстановление секрета из первых k частей
selected_shares = shares[:k]
recovered_key = recover_secret(selected_shares, p)

print(f"\nВосстановленный секрет (ключ): {recovered_key}")

# Проверяем, совпадает ли восстановленный секрет с исходным
if recovered_key == secret_key:
    print("Секрет успешно восстановлен!")
else:
    print("Ошибка при восстановлении секрета!")
