from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

root_key = get_random_bytes(16)
print(root_key)
cipher = AES.new(root_key, AES.MODE_GCM)

key = get_random_bytes(16)
protected_key = cipher.encrypt(key)

shares = Shamir.split(3, 5, root_key, False)

recover_root_key = Shamir.combine(shares[:3], False)
print(recover_root_key)
recover_cipher = AES.new(recover_root_key, AES.MODE_GCM)
recover_key = recover_cipher.decrypt(protected_key)

print(key)
print(recover_key)
"""
  1. Два созданных по одному ключу шифратора дают разные результаты.
     Это может помешать восстановлению зашифрованного ключа шифрования в случае перезапуска скрипта, содержащем шифратор
  2. Нужно модернизировать или реализовать самостоятельно Shamir,
     так как в этом нет возможности использовать 32 байтный ключ шифрования AES256
"""
