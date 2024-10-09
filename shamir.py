import random
import json
import secrets

class Shamir256:
    def __init__(self, prime: int = 2 ** 257 - 93, high_value: int = 2 ** 52):
        self.prime = prime
        self.high_value = high_value

    def __generate_coefficients(self, threshold: int) -> list[int]:
        return [secrets.randbelow(self.high_value) % self.prime for _ in range(threshold - 1)]

    def __evaluate_polynomial_horner_scheme(self, x: int, coefficients: list) -> int:
        result = 0
        for coeff in reversed(coefficients):
            result = result * x + coeff
        return result % self.prime

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

    def split_secret(self, secret: bytes, num_shares: int) -> list[tuple[int, str]]:
        if len(secret) != 32:
            raise ValueError(f"Unacceptable secret size ({len(secret)}). Expected 32 bytes")
        threshold = num_shares - 1
        secret_shares = list()
        coeffs = [int.from_bytes(secret, "big")] + self.__generate_coefficients(threshold)

        for i in range(1, num_shares + 1):
            x = random.randint(1, self.high_value)
            y = self.__evaluate_polynomial_horner_scheme(x, coeffs)
            point = (x, y)
            share = json.dumps(point).encode().hex()
            secret_shares.append((i, share))

        return secret_shares
