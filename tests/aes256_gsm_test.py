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

@pytest.fixture
def ciphertext_nonce_tag(cipher, root_key, master_key):
    ciphertext, nonce, tag = cipher.encrypt(root_key, master_key)
    return ciphertext, nonce, tag

def test_encrypt_decrypt_master_key(cipher, root_key, ciphertext_nonce_tag):
    decrypted_master_key, _ = cipher.decrypt(root_key, *ciphertext_nonce_tag)
    assert master_key == decrypted_master_key, "Расшифрованный мастер-ключ не совпадает с оригиналом"

def test_decrypt_cipher_key_value_error(cipher, root_key, ciphertext_nonce_tag):
    wrong_root_key = root_key[:-1]
    decrypted_master_key, err = cipher.decrypt(wrong_root_key, *ciphertext_nonce_tag)
    assert "Cipher creation failed:" in err

def test_decrypt_cipher_key_type_error(cipher, root_key, ciphertext_nonce_tag):
    wrong_root_key = "123"
    decrypted_master_key, err = cipher.decrypt(wrong_root_key, *ciphertext_nonce_tag)
    assert "Cipher creation failed due to wrong data type:" in err

def test_decrypt_cipher_nones_type_error(cipher, root_key, ciphertext_nonce_tag):
    ciphertext, nonce, tag = ciphertext_nonce_tag
    wrong_nonce = 123
    decrypted_master_key, err = cipher.decrypt(root_key, ciphertext, wrong_nonce, tag)
    assert "Cipher creation failed due to wrong data type:" in err

def test_decrypt_cipher_nones_value_error(cipher, root_key, ciphertext_nonce_tag):
    ciphertext, nonce, tag = ciphertext_nonce_tag
    wrong_nonce = nonce[:-5]
    decrypted_master_key, err = cipher.decrypt(root_key, ciphertext, wrong_nonce, tag)
    assert "Decryption failed: MAC check failed" == err

def test_decrypt_data_value_error(cipher, root_key, ciphertext_nonce_tag):
    ciphertext, nonce, tag = ciphertext_nonce_tag
    wrong_data = ciphertext[:-2]
    decrypted_master_key, err = cipher.decrypt(root_key, wrong_data, nonce, tag)
    assert "Decryption failed: MAC check failed" == err

def test_decrypt_data_type_error(cipher, root_key, ciphertext_nonce_tag):
    ciphertext, nonce, tag = ciphertext_nonce_tag
    wrong_data = 123
    decrypted_master_key, err = cipher.decrypt(root_key, wrong_data, nonce, tag)
    assert "Decryption failed due to wrong data type:" in err

def test_decrypt_tag_type_error(cipher, root_key, ciphertext_nonce_tag):
    ciphertext, nonce, tag = ciphertext_nonce_tag
    wrong_tag = str(tag)
    decrypted_master_key, err = cipher.decrypt(root_key, ciphertext, nonce, wrong_tag)
    assert "Decryption failed due to wrong data type:" in err

def test_decrypt_tag_value_error(cipher, root_key, ciphertext_nonce_tag):
    ciphertext, nonce, tag = ciphertext_nonce_tag
    wrong_tag = tag[:-2]
    decrypted_master_key, err = cipher.decrypt(root_key, ciphertext, nonce, wrong_tag)
    assert "Decryption failed: MAC check failed" in err