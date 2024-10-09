from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class Aes256GSM:
    @staticmethod
    def get_random_bytes32() -> bytes:
        return get_random_bytes(32)

    @staticmethod
    def encrypt(key:bytes| bytearray | memoryview, data: bytes | bytearray | memoryview, nonce: bytes = None)\
            -> tuple[bytes, bytes| bytearray | memoryview, bytes]:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        encrypted_data, authorization_tag = cipher.encrypt_and_digest(data)

        return encrypted_data, cipher.nonce, authorization_tag

    @staticmethod
    def decrypt(key: bytes| bytearray | memoryview, data: bytes | bytearray | memoryview, nonce: bytes| bytearray | memoryview, tag: bytes) \
            -> tuple[bytes, str]:
        try:
            if type(key) is str:
                raise TypeError("Incorrect AES key type (str). Expected: bytes| bytearray | memoryview")

            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        except ValueError as e:
            return bytes(), f"Cipher creation failed: {str(e)}"
        except TypeError as e:
            return bytes(), f"Cipher creation failed due to wrong data type: {str(e)}"

        try:
            decrypted_data = cipher.decrypt_and_verify(data, tag)
        except ValueError as e:
            return bytes(), f"Decryption failed: {str(e)}"
        except TypeError as e:
            return bytes(), f"Decryption failed due to wrong data type: {str(e)}"

        return decrypted_data, ""
