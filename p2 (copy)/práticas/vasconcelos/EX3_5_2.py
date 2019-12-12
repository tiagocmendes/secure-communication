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

    encryptor = cipher.encryptor()
    padding = block_size - len(text) % block_size
    padding = 16 if padding == 0 else padding
    text += bytes([padding]*padding)
    ct = encryptor.update(text)
    return ct


def rsa_encryption (original_file_name,public_key_file,encrypted_file_name):
	with open(public_key_file, "rb") as f:
		public_key=serialization.load_pem_public_key(f.read(),backend=default_backend())
	ks=os.urandom(32)
	
	with open(original_file_name,"rb") as fr:
		my_text=fr.readlines()
		message=b''.join(my_text)
		#print(message)
	C0=symmetric_key_gen(ks,message,'AES')
	
	C1=public_key.encrypt(ks,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
	with open(encrypted_file_name, "wb") as f:
		print(len(C1))
		print(len(C0))
		# Write len de C0 e depois ler a primeira linha para saber o size a ler a seguir
		f.write(C0)
		f.write(C1)
		
		


rsa_encryption("text.txt","public_key.txt","my_encryption.txt")
