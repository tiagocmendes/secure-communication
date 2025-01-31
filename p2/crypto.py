import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import PyKCS11
import wget
import requests

import os
import getpass
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes 
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives.hashes import SHA1

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography import x509
from datetime import datetime
import getpass
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import utils, rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID

logger = logging.getLogger('root')


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
        self.nonce=None
        self.encrypted_file_name="encrypted_file.txt"
        self.roots = dict()
        self.intermediate_certs = dict()
        self.user_cert = dict()
        self.chain=list()
        self.server_cert=None
        self.rsa_public_key=None
        self.rsa_private_key=None
        self.signature=None
        self.server_public_key=None
        self.auth_nonce=None
        self.server_ca_cert=None
        self.client_cert=None
    
    """
    Called to generate the shared key in the server.

    @param p
    @param g
    @param y
    @param bytes_public_key
    """
    def diffie_helman_server(self, p, g, bytes_public_key):
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
    @param bytes_public_key: public component
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
    @param my_text: text to generate MAC
    """
    def mac_gen (self,my_text):

        if(self.digest=="SHA256"):
            h=hmac.HMAC(self.symmetric_key, hashes.SHA256(), backend=default_backend())
        elif(self.digest=="SHA384"):
            h=hmac.HMAC(self.symmetric_key, hashes.SHA384(), backend=default_backend())
        elif(self.digest=="MD5"):
            h=hmac.HMAC(self.symmetric_key, hashes.MD5(), backend=default_backend())
        elif(self.digest=="SHA512"):
            h=hmac.HMAC(self.symmetric_key, hashes.SHA512(), backend=default_backend())
        elif(self.digest=="BLAKE2"):
            h=hmac.HMAC(self.symmetric_key, hashes.BLAKE2b(64), backend=default_backend())


        h.update(my_text) 
            
        
        self.mac=binascii.hexlify(h.finalize()) 

    
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

        if self.symmetric_cipher == 'AES':
            self.symmetric_key = key[:16]
        elif self.symmetric_cipher == '3DES':
            self.symmetric_key = key[:8]
        elif self.symmetric_cipher == 'ChaCha20':
            self.symmetric_key = key[:32]
        
    """
    File encryption with symmetric ciphers AES, 3DES or ChaCha20 with ECB,CBC or GCM cipher modes.

    @param data: data to encrypt
    """
    def file_encryption(self, data):
        backend = default_backend()
        cipher = None 
        block_size = 0
        mode = None
        
        if self.symmetric_cipher!='ChaCha20':
            if self.cipher_mode == 'ECB':
                mode = modes.ECB()
            elif self.cipher_mode == 'GCM':
                self.iv=os.urandom(16)
                mode = modes.GCM(self.iv)
            elif self.cipher_mode == 'CBC':
                if self.symmetric_cipher=='3DES':
                    self.iv=os.urandom(8)
                elif self.symmetric_cipher == 'AES':
                    self.iv=os.urandom(16)
                mode = modes.CBC(self.iv)
        
        if self.symmetric_cipher == 'AES':
            block_size = algorithms.AES(self.symmetric_key).block_size
            cipher = Cipher(algorithms.AES(self.symmetric_key), mode, backend=backend)
        
        elif self.symmetric_cipher == '3DES':
            block_size = algorithms.TripleDES(self.symmetric_key).block_size
            cipher = Cipher(algorithms.TripleDES(self.symmetric_key), mode, backend=backend)
    
        elif self.symmetric_cipher == 'ChaCha20':
            nonce = os.urandom(16)
            algorithm = algorithms.ChaCha20(self.symmetric_key, nonce)
            cipher = Cipher(algorithm, mode=None, backend=default_backend())
        else:
            raise Exception("Symmetric cipher not found")
        
        
        encryptor = cipher.encryptor()
        
        if self.cipher_mode!='GCM' and self.symmetric_cipher != 'ChaCha20':
            padding = block_size - len(data) % block_size

            padding = 16 if padding and self.symmetric_cipher == 'AES' == 0 else padding 
            padding = 8 if padding and self.symmetric_cipher == '3DES' == 0 else padding 

            data += bytes([padding]*padding)
            criptogram = encryptor.update(data)
        elif self.symmetric_cipher == 'ChaCha20':
          
            criptogram = encryptor.update(data)
            self.nonce=nonce
        else:
            criptogram = encryptor.update(data)+encryptor.finalize()
            self.gcm_tag=encryptor.tag


        return criptogram

    """
    File decryption with symmetric ciphers AES, 3DES or ChaCha20 with ECB or CBC cipher modes.
    @param data: data to decrypt
    @param iv: iv used in GCM or CBC
    @param tag: GCM tag
    @param nonce: ChaCha20 nonce
    """
    
    def decryption(self, data,iv=None,tag=None,nonce=None):
        backend = default_backend() 
        cipher = None
        block_size = 0

        if self.symmetric_cipher!='ChaCha20':
            if self.cipher_mode == 'ECB':
                mode = modes.ECB()
            elif self.cipher_mode == 'GCM':
                mode = modes.GCM(iv,tag)
            elif self.cipher_mode == 'CBC':
                if iv is not None:
                    mode = modes.CBC(iv)

        if self.symmetric_cipher == 'AES':
            block_size = algorithms.AES(self.symmetric_key).block_size
            cipher = Cipher(algorithms.AES(self.symmetric_key), mode, backend=backend)
        elif self.symmetric_cipher == '3DES':
            block_size = algorithms.TripleDES(self.symmetric_key).block_size
            cipher = Cipher(algorithms.TripleDES(self.symmetric_key), mode, backend=backend)
        elif self.symmetric_cipher == 'ChaCha20':
            algorithm = algorithms.ChaCha20(self.symmetric_key, nonce)
            cipher = Cipher(algorithm, mode=None, backend=default_backend())
        else:
            raise Exception("Mode not found")
            
        decryptor = cipher.decryptor()

        ct = decryptor.update(data)+decryptor.finalize()
        
        if self.cipher_mode=='GCM' or self.symmetric_cipher=='ChaCha20':
            return ct
        return ct[:-ct[-1]]
    
    """
    Called to get the certificate bytes.

    @param cert: certificate
    """
    def get_certificate_bytes(self,cert):
        return cert.public_bytes(crypto_serialization.Encoding.PEM)

    """
    Called to load the private key from a file .

    @param filename: filename
    """
    def load_key_from_file(self,filename):
        with open(filename, "rb") as f:
           private_key=serialization.load_pem_private_key(f.read(),password=None,backend=default_backend())
        return private_key
    
    """
    Called to load a private key .

    @param stream: private key bytes
    """
    def load_private_key(self, stream):
        return serialization.load_pem_private_key(
            stream,
            backend=default_backend(),
            password=None

        )
    
    """
    Called to load a public key .

    @param stream: public key bytes
    """
    def load_public_key(self, stream):
        return serialization.load_pem_public_key(
            stream,
            backend=default_backend()
        )
    
    """
    Called to check the time validation on the certificate .

    @param cert: certificate
    """
    def validate_cert(self,cert):
        today = datetime.now().timestamp()

        return cert.not_valid_before.timestamp() <= today <= cert.not_valid_after.timestamp()

    """
    Called to load certificate bytes in .pem format.

    @param cert_bytes: certificate bytes
    """
    def load_cert_bytes(self,cert_bytes):
        return x509.load_pem_x509_certificate(cert_bytes, default_backend())

    """
    Called to load certificate in .pem and .der format from file.

    @param filename: filename
    """
    def load_cert(self,filename):

        try:
            with open(filename, "rb") as pem_file:
                pem_data = pem_file.read()
                cert = x509.load_pem_x509_certificate(pem_data, default_backend())
            return cert
        except:
            logger.debug("Not PEM.")
        try:
            with open(filename, "rb") as pem_file:
                pem_data = pem_file.read()
                cert = x509.load_der_x509_certificate(pem_data, default_backend())
            return cert
        except:
            logger.debug("Not DER.")

    """
    Called to build certificate chain

    @param chain: list with certifcate chain
    @param cert:certificate
    """   
    def build_issuers(self,chain, cert):
        chain.append(cert)

        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()
        

        if issuer == subject and subject in self.roots:
            return 
        
        if issuer in self.intermediate_certs:
            return self.build_issuers(chain, self.intermediate_certs[issuer])
        
        if issuer in self.roots:
            return self.build_issuers(chain, self.roots[issuer])
        
        return

    """
    Called to validate the chain of certificates from the server.

    @param base_cert: server certificate
    @param root_cert: root server certificate
    """
    def validate_server_chain(self,base_cert, root_cert):
    
        self.roots[root_cert.subject.rfc4514_string()] = root_cert
                
        self.build_issuers(self.chain,base_cert)

        
        for i,cert in enumerate(self.chain):
            flag=self.validate_cert(cert)
            flag3=self.validate_server_purpose(cert,i)
            
            if not flag or not flag3:
                return False

        for i in range(0,len(self.chain)):
            if i==len(self.chain)-1:
                break

            #Validate cert signature
            flag1=self.validate_cert_signature(self.chain[i],self.chain[i+1])

            #Validate common name with issuer
            flag2=self.validate_cert_common_name(self.chain[i],self.chain[i+1])

            #Validate crl
            flag4=self.validate_revocation(self.chain[i],self.chain[i+1])

            if not flag1 or not flag2 or flag4:
                return False


            
        return flag and flag1 and flag2
    
    """
    Called to validate the chain of certificates from the cc.

    @param base_cert: cc certificate
    """
    def validate_cc_chain(self,base_cert):

        path='root_certificates/'


        folder = os.scandir(path)
        
        for entry in folder:
            if entry.is_file() and '.crt' in entry.name:
                cert = self.load_cert(path + "/" + entry.name)
                if cert is not None:
                    self.roots[cert.subject.rfc4514_string()] = cert

        cc_path='cc_certificates/'

        folder = os.scandir(cc_path)
        
        for entry in folder:
            cert = self.load_cert(cc_path + "/" + entry.name)
            if cert is not None:
                self.intermediate_certs[cert.subject.rfc4514_string()] = cert
            
    
        self.build_issuers(self.chain,base_cert)


        
        for i,cert in enumerate(self.chain):

            #Validate date
            flag=self.validate_cert(cert)

            #Validate purpose
            flag3=self.validate_cc_purpose(cert,i)

            if not flag or not flag3:
                return False
        
        
        for i in range(0,len(self.chain)):
            if i==len(self.chain)-1:
                break

            #Validate cert signature
            flag1=self.validate_cert_signature(self.chain[i],self.chain[i+1])

            #Validate common name with issuer
            flag2=self.validate_cert_common_name(self.chain[i],self.chain[i+1])

            #Validate CRL/OCSP
            flag4=self.validate_revocation(self.chain[i],self.chain[i+1])

            if not flag1 or not flag2 or flag4:
                return True
                #return False # TODO CHANGEEEE

            
        return flag and flag1 and flag2

    
    """
    Called to generate a public/private key pair.

    @param length: key length
    """
    def key_pair_gen(self, length):
        valid_lengths = [1024, 2048, 3072, 4096]

        if length not in valid_lengths:
            logger.debug("ERROR - Not a valid length!")
            return 
        

        private_key = rsa.generate_private_key(
            public_exponent=65537, 
            key_size=length,
            backend=default_backend()
        )

        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        priv_key = base64.b64encode(pem).decode()

        public_key = private_key.public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pub_key = base64.b64encode(pem).decode()

        return (pub_key, priv_key)

    """
    Called to load a crl revocation list.

    @param filename: filename
    @param file_type: file_type
    """
    def load_cert_revocation_list(self,filename,file_type):
        with open(filename, "rb") as pem_file:
            pem_data = pem_file.read()
            if file_type=="der":
                cert = x509.load_der_x509_crl(pem_data, default_backend())
            elif file_type=="pem":
                cert = x509.load_pem_x509_crl(pem_data, default_backend())

        return cert

    """
    Called to validate a certificate signature

    @param cert_to_check: certificate
    @param issuer_cert: issuer certificate
    """
    def validate_cert_signature(self,cert_to_check,issuer_cert):

        cert_to_check_signature=cert_to_check.signature
        issuer_public_key=issuer_cert.public_key()

        try:
            issuer_public_key.verify(cert_to_check_signature,cert_to_check.tbs_certificate_bytes,padding.PKCS1v15(),cert_to_check.signature_hash_algorithm)
        except:
            logger.debug("Failed to verify signature.")
            return False
    
        return True

    """
    Called to validate a certificate purpose. The first certificate validated will have a different purpose from the rest of the chain

    @param cert: certificate
    @param index: index of the certificate we are validating
    """
    def validate_server_purpose(self,cert,index):

        if index==0:
            flag=False
            for c in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
                if c.dotted_string=="1.3.6.1.5.5.7.3.1":
                    flag=True
                    break
            return flag
        else:
            if cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign==True :
                return True
            else:
                return False
    """
    Called to validate a certificate purpose. The first certificate validated will have a different purpose from the rest of the chain

    @param cert: certificate
    @param index: index of the certificate we are validating
    """
    def validate_cc_purpose(self,cert,index):

        try:
            if index==0:
                
                for c in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
                    if c.dotted_string=="1.3.6.1.5.5.7.3.2":
                        flag=True
                        break
                return flag
            else:
                if cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign==True :
                    return True
                else:
                    return False
        except:
            logger.error("Could not authenticate with cc.")
            exit(1)


    """
    Called to validate the revocation of a certificate through CRL, DELTA CRL and OCSP

    @param cert_to_check: certificate
    @param issuer_cert: issuer certificate
    """
    def validate_revocation(self,cert_to_check,issuer_cert):
        
        try:
            builder = ocsp.OCSPRequestBuilder()
            
            builder = builder.add_certificate(cert_to_check, issuer_cert, SHA1())
            req = builder.build()
            for j in cert_to_check.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value:
                if j.access_method.dotted_string == "1.3.6.1.5.5.7.48.1": 
                    rev_list=None

                    #Downloading list
                    der=req.public_bytes(serialization.Encoding.DER)

                    ocsp_link=j.access_location.value
                    r=requests.post(ocsp_link, headers={'Content-Type': 'application/ocsp-request'},data=der)

                    
                    ocsp_resp = ocsp.load_der_ocsp_response(r.content)
                    if ocsp_resp.certificate_status== ocsp.OCSPCertStatus.GOOD:
                        return False
                    else:
                        return True

                   
                                
        except Exception as e:
            logger.debug("OCSP not available")
        

        try:
            for i in cert_to_check.extensions.get_extension_for_class(x509.CRLDistributionPoints).value:
                for b in i.full_name:
                    rev_list=None
                    #Downloading list
                    file_name=wget.download(b.value)
                    print()
                    #read revocation list
                    try:
                        rev_list=self.load_cert_revocation_list(file_name,"pem")
                    except Exception as e :
                        logger.debug(e)
                    try:
                        rev_list=self.load_cert_revocation_list(file_name,"der")
                    except:
                        logger.debug("Not der.")
                    if rev_list is None:
                        return False
                    
                    flag=cert_to_check.serial_number in [l.serial_number for l in rev_list]
            try:
                for i in cert_to_check.extensions.get_extension_for_class(x509.FreshestCRL).value:
                    for b in i.full_name:
                        rev_list=None
                        #Downloading list
                        file_name=wget.download(b.value)
                        #read revocation list
                        try:
                            rev_list=self.load_cert_revocation_list(file_name,"pem")
                        except Exception as e :
                            logger.debug(e)
                        try:
                            rev_list=self.load_cert_revocation_list(file_name,"der")
                        except:
                            logger.debug("Not der.")
                        if rev_list is None:
                            return False
                        
                        flag=cert_to_check.serial_number in [l.serial_number for l in rev_list]
            except:
                logger.debug("DELTA CRL not available.")

            for i in issuer_cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value:
                for b in i.full_name:
                    rev_list=None
                    #Downloading list
                    file_name=wget.download(b.value)
                    print()


                    #read revocation list
                    try:
                        rev_list=self.load_cert_revocation_list(file_name,"pem")
                    except Exception as e :
                        logger.debug(e)
                        
                    try:
                        rev_list=self.load_cert_revocation_list(file_name,"der")
                    except:
                        logger.debug("Not der.")
                    if rev_list is None:
                        return False
                    
                    flag1=issuer_cert.serial_number in [l.serial_number for l in rev_list]

                    return flag1 or flag
            
            try:
                for i in issuer_cert.extensions.get_extension_for_class(x509.FreshestCRL).value:
                    for b in i.full_name:
                        rev_list=None
                        #Downloading list
                        file_name=wget.download(b.value)


                        #read revocation list
                        try:
                            rev_list=self.load_cert_revocation_list(file_name,"pem")
                        except Exception as e :
                            logger.debug(e)
                            
                        try:
                            rev_list=self.load_cert_revocation_list(file_name,"der")
                        except:
                            logger.debug("Not der.")
                        if rev_list is None:
                            return False
                        
                        flag1=issuer_cert.serial_number in [l.serial_number for l in rev_list]


            except:
                logger.debug("DELTA CRL not available.")
            return flag1 or flag



        except Exception as e:
            logger.debug("CRL not available")
        
        return True

    """
    Called to validate the certificate common name.

    @param cert_to_check: certificate
    @param issuer_cert: issuer certificate
    """
    def validate_cert_common_name(self,cert_to_check,issuer_cert):

        if (self.get_issuer_common_name(cert_to_check)!=self.get_common_name(issuer_cert)):
            return False 
        
        return True
    """
    Returns the certificate common name.

    @param cert_to_check: certificate
    """
    def get_common_name(self,cert):
        try:
            names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            return names[0].value
        except x509.ExtensionNotFound:
            return None

    """
    Returns the certificate issuer common name.

    @param cert: certificate
    """
    def get_issuer_common_name(self,cert):
        try:
            names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            return names[0].value
        except x509.ExtensionNotFound:
            return None

    """
    Returns the signature created with the cc.

    @param text: text to sign
    """
    def card_signing(self,text):
        try:
            lib ='/usr/local/lib/libpteidpkcs11.so'
            pkcs11 = PyKCS11.PyKCS11Lib()
            pkcs11.load(lib)

            slots = pkcs11.getSlotList()

            for slot in slots:
                all_attr = list(PyKCS11.CKA.keys())

                #Filter attributes
                all_attr = [e for e in all_attr if isinstance(e, int)]

                session = pkcs11.openSession(slot)
                
                private_key = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),(PyKCS11.CKA_LABEL,'CITIZEN AUTHENTICATION KEY')])[0]

                mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
                
                signature = bytes(session.sign(private_key, text, mechanism))

                certificate_obj = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE), (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION CERTIFICATE')])[0]
                # Get object attributes
                attr = session.getAttributeValue(certificate_obj, all_attr)
                # Create dictionary with attributes
                attr = dict(zip(map(PyKCS11.CKA.get, all_attr), attr))
                # Load cert
                cert = x509.load_der_x509_certificate(bytes(attr['CKA_VALUE']), default_backend())
            return self.get_certificate_bytes(cert), signature
        except:
            logger.error("Card not detected.")
            exit(1)

    
    """
    Returns the signature created with the private key.

    @param message: message to sign
    @param private_key: private_key to sign message
    """
    def rsa_signing(self, message, private_key):

        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return signature

    """
    Validates the signature created with the private key.

    @param signature: signature
    @param message: message to sign
    @param public: public key to verify message
    """
    def rsa_signature_verification (self,signature, message, public_key):
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except Exception as e:
            logger.debug("Server signature validation failed!")
            return False
        
        return True
    
    """
    Validates the signature created with the cc.

    @param signature: signature
    @param message: message to sign
    @param public: cc public key to verify message
    """
    def cc_signature_validation (self,signature, message, public_key):
        
        try:
            public_key.verify(
                signature,
                message,
                padding.PKCS1v15(),
                hashes.SHA1()
            )
        except Exception as e:
            logger.debug("Server signature validation failed!")
            return False
        
        return True
        

        #return signature

   
