import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import getpass
import base64
​
​
def symmetric_key_gen(key, text, mode, algorithm=None):
    backend = default_backend()
    cipher = None
    block_size = 0
    if mode == 'AES':
        block_size = algorithms.AES(key).block_size
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    elif mode == '3DES':
        block_size = algorithms.TripleDES(key).block_size
        cipher = Cipher(algorithms.TripleDES(
            key), modes.ECB(), backend=backend)
    elif mode == 'ChaCha20':
        pass
        # block_size=algorithms.ChaCha20(key).block_size
        # cipher=Cipher(algorithms.ChaCha20(key),modes.ECB(),backend=backend)
    else:
        raise Exception("Mode not found")
​
    encryptor = cipher.encryptor()
    padding = block_size - len(text) % block_size
    padding = 16 if padding == 0 else padding
    text += bytes([padding]*padding)
    ct = encryptor.update(text)
    return ct
​
​
def symmetric_key_decrypt(key, text, mode, algorithm=None):
    backend = default_backend()
    cipher = None
    block_size = 0
    if mode == 'AES':
        block_size = algorithms.AES(key).block_size
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    elif mode == '3DES':
        block_size = algorithms.TripleDES(key).block_size
        cipher = Cipher(algorithms.TripleDES(
            key), modes.ECB(), backend=backend)
    elif mode == 'ChaCha20':
        pass
        # block_size = algorithms.ChaCha20(key).block_size
        # cipher = Cipher(algorithms.ChaCha20(key), modes.ECB(), backend=backend)
    else:
        raise Exception("Mode not found")
​
    decryptor = cipher.decryptor()
    ct = decryptor.update(text)+decryptor.finalize()
    return ct[:-ct[-1]]
​
​
key = os.urandom(32)
encrypted = symmetric_key_gen(key, b"ola", "AES")
print(encrypted)
decrypted = symmetric_key_decrypt(key, encrypted, "AES")
print(decrypted)
​
​
key = os.urandom(8)
encrypted2 = symmetric_key_gen(key, b"ola2", "3DES")
print(encrypted2)
decrypted2 = symmetric_key_decrypt(key, encrypted2, "3DES")
print(decrypted2)