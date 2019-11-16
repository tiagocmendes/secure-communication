import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import os
import getpass
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes 
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

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
        self.public_key=None
        self.private_key=None
        self.shared_key=None
        self.mac=None
        self.encrypted_file_name="encrypted_file.txt"
    
    def diffie_helman_server(self,p,g,y,bytes_public_key):
        pn = dh.DHParameterNumbers(p, g)
        parameters = pn.parameters(default_backend())
        self.private_key = parameters.generate_private_key()
        
        peer_public_key=self.private_key.public_key()
        self.public_key=peer_public_key.public_bytes(crypto_serialization.Encoding.PEM,crypto_serialization.PublicFormat.SubjectPublicKeyInfo)
        

        public_key_client=crypto_serialization.load_pem_public_key(bytes_public_key,backend=default_backend())
        self.shared_key=self.private_key.exchange(public_key_client)
        
        return True


    def create_shared_key(self,bytes_public_key):
        public_key_server=crypto_serialization.load_pem_public_key(bytes_public_key,backend=default_backend())
        self.shared_key=self.private_key.exchange(public_key_server)


    def diffie_helman_client(self):
        parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())

        self.private_key = parameters.generate_private_key()
        a_peer_public_key = self.private_key.public_key()
        p=parameters.parameter_numbers().p
        g=parameters.parameter_numbers().g
        y=a_peer_public_key.public_numbers().y

        self.public_key=a_peer_public_key.public_bytes(crypto_serialization.Encoding.PEM,crypto_serialization.PublicFormat.SubjectPublicKeyInfo)

        return(self.public_key,p,g,y)
        
    def mac_gen (self,my_text):

        if(self.digest=="SHA256"):
            h=hmac.HMAC(self.shared_key, hashes.SHA256(), backend=default_backend())
        elif(self.digest=="SHA384"):
            h=hmac.HMAC(self.shared_key, hashes.SHA384(), backend=default_backend())
        elif(self.digest=="MD5"):
            h=hmac.HMAC(self.shared_key, hashes.MD5(), backend=default_backend())
        elif(self.digest=="SHA512"):
            h=hmac.HMAC(self.shared_key, hashes.SHA512(), backend=default_backend())
        elif(self.digest=="BLAKE2"):
            h=hmac.HMAC(self.shared_key, hashes.BLAKE2b(64), backend=default_backend())

        
        
       
        h.update(my_text) # TODO read 1024 
            
        
        self.mac=binascii.hexlify(h.finalize()) 


    
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
                
      
        self.mic=binascii.hexlify(digest.finalize()) # TODO Create MAC
    
    """
    Symmetric key generation.

    It derivates the shared key created with Diffie-Helman
    """
    def symmetric_key_gen(self):
        
       
        kdf = HKDF(
            algorithm=hashes.SHA256(), #TODO dynamic
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        )
        
        key = kdf.derive(self.shared_key)

        if self.symmetric_cipher == 'AES':
            self.symmetric_key = key[:16]
        elif self.symmetric_cipher == '3DES':
            self.symmetric_key = key[:8]
        elif self.symmetric_cipher == 'ChaCha20':
            self.symmetric_key = key[:64]
        
    """
    File encryption

    @param file_name: file to encrypt
    
    """
    def file_encryption(self, data):
        backend = default_backend()
        cipher = None 
        block_size = 0
        mode = None
        
        if self.cipher_mode == 'ECB':
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
        else:
            raise Exception("Symmetric cipher not found")
        
        #data = ''
        #with open(file_name, 'rb') as fr:
            #data = fr.read()
        encryptor = cipher.encryptor()
        padding = block_size - len(data) % block_size

        #TODO Check if paddings are correct
        padding = 16 if padding and self.symmetric_cipher == 'AES' == 0 else padding 
        padding = 8 if padding and self.symmetric_cipher == '3DES' == 0 else padding 
        padding = 64 if padding and self.symmetric_cipher == 'ChaCha20' == 0 else padding 

        data += bytes([padding]*padding)
        criptogram = encryptor.update(data)
        return criptogram

        #with open(self.encrypted_file_name, 'wb') as fw:
        #    fw.write(criptogram)

    def decryption(self, data):
        backend = default_backend() 
        cipher = None
        block_size = 0

        if self.cipher_mode == 'ECB':
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
            pass
            # block_size = algorithms.ChaCha20(key).block_size
            # cipher = Cipher(algorithms.ChaCha20(key), modes.ECB(), backend=backend)
        else:
            raise Exception("Mode not found")
            
        decryptor = cipher.decryptor()

        padding = block_size - len(data) % block_size

        #TODO Check if paddings are correct
        '''
        padding = 16 if padding and self.symmetric_cipher == 'AES' == 0 else padding 
        padding = 8 if padding and self.symmetric_cipher == '3DES' == 0 else padding 
        padding = 64 if padding and self.symmetric_cipher == 'ChaCha20' == 0 else padding 
        '''
    
        #data += bytes([padding]*padding)
        ct = decryptor.update(data)+decryptor.finalize()
        return ct[:-ct[-1]]