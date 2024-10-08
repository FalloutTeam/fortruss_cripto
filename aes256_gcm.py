from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class Aes256GSM:
    @staticmethod
    def encrypt(key:bytes| bytearray | memoryview, data: any)\
            -> tuple[bytes, bytes| bytearray | memoryview, bytes]:
        cipher = AES.new(key, AES.MODE_GCM)
        encrypted_data, authorization_tag = cipher.encrypt_and_digest(data)

        return encrypted_data, cipher.nonce, authorization_tag

    @staticmethod
    def decrypt(key: bytes| bytearray | memoryview, data: any, nonce: bytes| bytearray | memoryview, tag: bytes) \
            -> tuple[bytes, str]:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        try:
            decrypted_data = cipher.decrypt_and_verify(data, tag)
        except Exception:
            return bytes(), "Error"

        return decrypted_data, "OK"

