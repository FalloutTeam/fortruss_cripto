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

    @staticmethod
    def __encode_shares(points: list[tuple[int, int]]) -> list[str]:
        secret_shares = [json.dumps(point).encode().hex() for point in points]
        return secret_shares

    @staticmethod
    def __decode_shares(shares: list[str]) -> list[tuple[int, int]]:
        points = [json.loads(bytes.fromhex(share).decode()) for share in shares]
        return points

    def split_secret(self, secret: bytes, num_shares: int, num_required: int) -> list[tuple[int, str]]:
        if len(secret) != 32:
            raise ValueError(f"Unacceptable secret size ({len(secret)}). Expected 32 bytes")
        coeffs = [int.from_bytes(secret, "big")] + self.__generate_coefficients(num_required - 1)
        points = list()
        for i in range(1, num_shares + 1):
            x = random.randint(1, self.high_value)
            y = self.__evaluate_polynomial_horner_scheme(x, coeffs)
            points.append((x, y))

        secret_shares = list(enumerate(self.__encode_shares(points), start=1))

        return secret_shares
