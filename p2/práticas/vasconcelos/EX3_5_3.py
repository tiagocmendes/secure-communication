from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import getpass
import base64


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

    decryptor = cipher.decryptor()
    ct = decryptor.update(text)+decryptor.finalize()
    return ct[:-ct[-1]]


def rsa_decryption (original_file_name,private_key_file,decrypted_file_name):
	with open(private_key_file, "rb") as f:
		private_key=serialization.load_pem_private_key(f.read(),password=None,backend=default_backend())
	
	with open(original_file_name,"rb") as fr:
		all_bytes=fr.read()
		C1=all_bytes[:32]# por em files diferentes

		C2=all_bytes[32:]
		
	ks=private_key.decrypt(C1,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
	print(ks)

rsa_decryption("my_encryption.txt","private_key.txt","dasd")
