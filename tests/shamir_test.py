import pytest
from ..shamir import Shamir256
from Crypto.Random import get_random_bytes

@pytest.fixture
def shamir():
    return Shamir256()

@pytest.fixture
def secret():
    return get_random_bytes(32)

def test_shamir_split(shamir, secret):
    num_shares = 5
    shares = shamir.split_secret(secret, num_shares)
    print(secret.hex())
    print(shares)
    assert len(shares) == 5