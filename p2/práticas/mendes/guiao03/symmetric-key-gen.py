import getpass
import base64
import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def symmetric_key(filename, _algorithm, password):
    
    password = password.encode()
    salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    key = kdf.derive(password)

    if _algorithm == 'AES':
        final_key = key[:16]
    elif _algorithm == '3DES':
        final_key = key[:8]
    elif _algorithm == 'ChaCha20':
        final_key = key[:64]

    # save key to a file
    f = open(filename, 'wb')
    f.write(b"Key: ")
    f.write(final_key)
    f.write(b"Salt: ")
    f.write(salt)
    f.close()

    return key 

if __name__ == '__main__':
    try:
        pw = getpass.getpass(prompt='Password: ', stream=None)
    except Exception as error:
        print('ERROR', error)
    
    print("Password entered: " + pw)
    print("Symmetric key: " + str(symmetric_key('key.key','ChaCha20', pw)))


# backend = default_backend()
# key = os.urandom(32)
# iv = os.urandom(16)
# cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
# encryptor = cipher.encryptor()
# ct = encryptor.update(b"a secret message") + encryptor.finalize()
# decryptor = cipher.decryptor()
# msg = decryptor.update(ct) + decryptor.finalize()
# print(msg)