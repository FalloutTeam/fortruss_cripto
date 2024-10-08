import pytest
from Crypto.Random import get_random_bytes
from ..aes256_gcm import Aes256GSM

@pytest.fixture
def cipher():
    return Aes256GSM()

@pytest.fixture
def root_key():
    return get_random_bytes(32)

@pytest.fixture
def master_key():
    return get_random_bytes(32)

def test_encrypt_decrypt_master_key(cipher, root_key, master_key):
    ciphertext, nonce, tag = cipher.encrypt(root_key, master_key)
    decrypted_master_key, _ = cipher.decrypt(root_key, ciphertext, nonce, tag)
    assert master_key == decrypted_master_key, "Расшифрованный мастер-ключ не совпадает с оригиналом"
