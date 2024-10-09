import random
import secrets
import multiprocessing


class Shamir256:
    def __init__(self, divisor: int = 2 ** 64, high_value: int = 2 ** 128):
        self.divisor = divisor
        self.high_value = high_value

def eval_polynomial(coeffs, x, p):
    """Вычисление значения полинома в точке x с модулем p"""
    y = 0
    for i, coeff in enumerate(coeffs):
        y += coeff * (x ** i)
    return y % p


def lagrange_interpolation(x, x_s, y_s, p):
    """Интерполяция Лагранжа для восстановления секрета"""

    def _basis(j):
        terms = [(x - x_s[m]) * mod_inverse(x_s[j] - x_s[m], p) % p for m in range(len(x_s)) if m != j]
        return reduce(mul, terms, 1)

    return sum(y_s[j] * _basis(j) for j in range(len(x_s))) % p


def split_secret(secret, k, n, p):
    """Разделение секрета с использованием схемы Шамира"""
    coeffs = [secret] + [random.randint(0, p - 1) for _ in range(k - 1)]
    shares = [(i, eval_polynomial(coeffs, i, p)) for i in range(1, n + 1)]
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
