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
        self.iv=None
        self.gcm_tag=None
        self.encrypted_file_name="encrypted_file.txt"
    
    """
    Called to generate the shared key in the server.

    @param p
    @param g
    @param y
    @param bytes_public_key
    """
    def diffie_helman_server(self, p, g, y, bytes_public_key):
        pn = dh.DHParameterNumbers(p, g)
        parameters = pn.parameters(default_backend())
        self.private_key = parameters.generate_private_key()
        
        peer_public_key=self.private_key.public_key()
        self.public_key=peer_public_key.public_bytes(crypto_serialization.Encoding.PEM,crypto_serialization.PublicFormat.SubjectPublicKeyInfo)
        

        public_key_client=crypto_serialization.load_pem_public_key(bytes_public_key,backend=default_backend())
        self.shared_key=self.private_key.exchange(public_key_client)
        
        return True

    """
    Called to create a shared key between the client and the server in the Diffie Hellman algorithm.
    """
    def create_shared_key(self, bytes_public_key):
        public_key_server=crypto_serialization.load_pem_public_key(bytes_public_key,backend=default_backend())
        self.shared_key=self.private_key.exchange(public_key_server)

    """
    Called to generate the shared key in the client.
    """
    def diffie_helman_client(self):
        parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())

        self.private_key = parameters.generate_private_key()
        a_peer_public_key = self.private_key.public_key()
        p=parameters.parameter_numbers().p
        g=parameters.parameter_numbers().g
        y=a_peer_public_key.public_numbers().y

        self.public_key=a_peer_public_key.public_bytes(crypto_serialization.Encoding.PEM,crypto_serialization.PublicFormat.SubjectPublicKeyInfo)

        return(self.public_key,p,g,y)
    
    """
    Called to generate the MAC of a message with a digest function.
    """
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


        h.update(my_text) 
            
        
        self.mac=binascii.hexlify(h.finalize()) 

    """
    Digest generation function.
    """
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

    It derivates the shared key created with Diffie-Helman.
    """
    def symmetric_key_gen(self):
        
        if(self.digest=="SHA256"):
            alg=hashes.SHA256()
        elif(self.digest=="SHA384"):
            alg=hashes.SHA384()
        elif(self.digest=="MD5"):
            alg=hashes.MD5()
        elif(self.digest=="SHA512"):
            alg=hashes.SHA512()
        elif(self.digest=="BLAKE2"):
            alg=hashes.BLAKE2b(64)
        
        kdf = HKDF(
            algorithm=alg,
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        )
        
        key = kdf.derive(self.shared_key)

        #Generate IV


        if self.symmetric_cipher == 'AES':
            self.symmetric_key = key[:16]
        elif self.symmetric_cipher == '3DES':
            self.symmetric_key = key[:8]
        elif self.symmetric_cipher == 'ChaCha20':
            self.symmetric_key = key[:64]
        
    """
    File encryption with symmetric ciphers AES, 3DES or ChaCha20 with ECB or CBC cipher modes.

    @param file_name: file to encrypt
    """
    def file_encryption(self, data,associated_data=None):
        backend = default_backend()
        cipher = None 
        block_size = 0
        mode = None
        
        if self.cipher_mode == 'ECB':
            mode = modes.ECB()
        elif self.cipher_mode == 'GCM':
            self.iv=os.urandom(16)
            mode = modes.GCM(self.iv)
        elif self.cipher_mode == 'CBC':
            # FIXME initialization vector
            self.iv=os.urandom(16)
            mode = modes.CBC(self.iv)
        
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
        
        
        encryptor = cipher.encryptor()
        if self.cipher_mode!='GCM':
            padding = block_size - len(data) % block_size

            padding = 16 if padding and self.symmetric_cipher == 'AES' == 0 else padding 
            padding = 8 if padding and self.symmetric_cipher == '3DES' == 0 else padding 
            padding = 64 if padding and self.symmetric_cipher == 'ChaCha20' == 0 else padding 

            data += bytes([padding]*padding)
            criptogram = encryptor.update(data)

        else:
            encryptor.authenticate_additional_data(associated_data)
            criptogram = encryptor.update(data)+encryptor.finalize()
            self.gcm_tag=encryptor.tag


        return criptogram

    """
    File decryption with symmetric ciphers AES, 3DES or ChaCha20 with ECB or CBC cipher modes.
    """
    
    def decryption(self, data,iv=None,tag=None,associated_data=None):
        backend = default_backend() 
        cipher = None
        block_size = 0

        if self.cipher_mode == 'ECB':
            mode = modes.ECB()
        elif self.cipher_mode == 'GCM':
            self.iv=os.urandom(16)
            mode = modes.GCM(iv,tag)
        elif self.cipher_mode == 'CBC':
            # FIXME initialization vector
            if iv is not None:

                mode = modes.CBC(iv)

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

        if self.cipher_mode=='GCM':
            decryptor.authenticate_additional_data(associated_data)
       
    
        ct = decryptor.update(data)+decryptor.finalize()
        
        if self.cipher_mode=='GCM':
            return ct
        return ct[:-ct[-1]]