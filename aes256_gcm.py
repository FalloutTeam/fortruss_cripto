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


# Генерация корневого ключа (256 бит) и мастер-ключа (256 бит)
root_key = get_random_bytes(32)  # Корневой ключ длиной 256 бит (32 байта)
master_key = get_random_bytes(32)  # Мастер-ключ длиной 256 бит (32 байта)

print(f"Корневой ключ (Root Key): {root_key.hex()}")
print(f"Мастер-ключ (Master Key): {master_key.hex()}")

aes = Aes256GSM()
# Шифруем мастер-ключ с помощью корневого ключа
ciphertext, nonce, tag = aes.encrypt(root_key, master_key)

print(f"Зашифрованный мастер-ключ (Ciphertext): {ciphertext.hex()}")
print(f"Nonce: {nonce.hex()}")
print(f"Tag: {tag.hex()}")

# Расшифровываем мастер-ключ
decrypted_master_key, _ = aes.decrypt(root_key, ciphertext, nonce, tag)

print(f"Расшифрованный мастер-ключ (Decrypted Master Key): {decrypted_master_key.hex()}")

# Проверяем, что расшифрованный мастер-ключ совпадает с исходным
if decrypted_master_key == master_key:
    print("Мастер-ключ успешно расшифрован!")
else:
    print("Ошибка: расшифрованный мастер-ключ не совпадает с исходным!")
