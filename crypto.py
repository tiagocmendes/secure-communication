import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import os
import getpass
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


​


"""
Class with several cryptography functions.
"""
class Crypto:
    """
    Default constructor

    @param symmetric_ciphers: symmetric ciphers algorithms
    @param cipher_modes: cipher_modes algorithms
    @param digest: digest algorithms
    """
    def __init__(self, symmetric_ciphers, cipher_modes, digest):
        
        self.symmetric_cipher = symmetric_ciphers
        self.cipher_mode = cipher_modes
        self.digest = digest
        self.symmetric_key=None
        self.mac=None
        self.encrypted_file_name="encrypted_file.txt"
    
    def digest_gen(self):

        if(self.digest=="SHA256"):
            digest_generated = hashes.Hash(hashes.SHA256(), backend=default_backend())
        elif(self.digest=="SHA384"):
            digest_generated = hashes.Hash(hashes.SHA384(), backend=default_backend())
        elif(self.digest=="MD5"):
            digest_generated = hashes.Hash(hashes.MD5(), backend=default_backend())
        elif(self.digest=="SHA512"):
            digest_generated = hashes.Hash(hashes.SHA512(), backend=default_backend())
        elif(self.digest=="BLAKE2"):
            digest_generated = hashes.Hash(hashes.BLAKE2b(64), backend=default_backend())
        
        with open(self.encrypted_file_name,"rb") as fr:
            my_text=fr.read(1024)
            digest_generated.update(my_text)
            while my_text:
                my_text=fr.read(1024)
                digest_generated.update(my_text)
                
      
        self.mac=binascii.hexlify(digest.finalize())
    
    """
    Symmetric key generation.

    It prompts the user to enter a password.
    """
    def symmetric_key_gen(self):
        
        try:
            password = getpass.getpass(prompt='Password for key: ', stream=None)
        except Exception as error:
            print('ERROR', error)
        
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

        if self.symmetric_cipher == 'AES':
            self.symmetric_key = key[:16]
        elif self.symmetric_cipher == '3DES':
            self.symmetric_key = key[:8]
        elif self.symmetric_cipher == 'ChaCha20':
            self.symmetric_key = key[:64]
        
        #return self.symmetric_key

    def file_encryption(self, file_name):
        backend = default_backend()
        cipher = None 
        block_size = 0
​
        mode = None
        if self.cipher_mode == 'EBC':
            mode = modes.ECB()
        
        elif self.cipher_mode == 'CBC':
            # FIXME initialization vector
            mode = modes.CBC(b"a" * 16)
        
        if self.symmetric_cipher == 'AES':
            block_size = algorithms.AES(self.symmetric_key).block_size
            cipher = Cipher(algorithms.AES(self.symmetric_key), mode, backend=backend)
        
        elif self.symmetric_cipher == '3DES':
            block_size = algorithms.TripleDES(self.symmetric_key).block_size
            cipher = Cipher(algorithms.TripleDES(self.symmetric_key), mode, backend=backend)
    
        elif self.symmetric_cipher == 'ChaCha20':
            # FIXME block size
            pass
            #block_size = algorithms.ChaCha20(self.symmetric_key).block_size
            #cipher = Cipher(algorithms.ChaCha20(key), mode, backend=backend)
​
        else:
            raise Exception("Symmetric cipher not found")
        
        data = ''
        with open(file_name, 'rb') as fr:
            data = fr.read()
​
        encryptor = cipher.encryptor()
        padding = block_size - len(data) % block_size
        padding = 16 if padding == 0 else padding
        
        data += bytes([padding]*padding)
        criptogram = encryptor.update(data)
​
        with open(self.encrypted_file_name, 'wb') as fw:
            fw.write(criptogram)