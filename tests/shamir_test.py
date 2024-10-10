import pytest
from ..shamir import Shamir256
from Crypto.Random import get_random_bytes

@pytest.fixture
def shamir():
    return Shamir256()

@pytest.fixture
def secret():
    return get_random_bytes(32)

@pytest.fixture
def shares(shamir, secret):
    num_shares = 5
    num_req = 3
    shares = shamir.split_secret(secret, num_shares, num_req)
    return shares

def test_shamir_split(shamir, secret):
    num_shares = 5
    num_req = 3
    shares = shamir.split_secret(secret, num_shares, num_req)
    assert len(shares) == num_shares

def test_shamir_combine(shamir, secret, shares):
    num_req = 3
    secret2 = shamir.combine_secret(shares, num_req)
    assert secret2 == secret