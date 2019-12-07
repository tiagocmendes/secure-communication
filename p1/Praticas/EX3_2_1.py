import base64
import os
import getpass 
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def get_key(alg_name,file_name):
    password_provided = getpass.getpass()
    password = password_provided.encode() # Convert to type bytes
    backend = default_backend()
    salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000, backend=backend)
    
	
    key = kdf.derive(password) # Can only use kdf once
    final_key=""
    if(alg_name=="AES-128"):
        #16 bytes
        final_key=key[:16]           
    elif(alg_name=="3DES"):
        #8 bytes
        final_key=key[:8]       
    elif (alg_name=="ChaCha20"):
        #64 bytes
        final_key=key[:64]
    f = open(file_name, "wb")
    f.write(final_key)
    f.close()
        
    
    

get_key("ChaCha20","key.txt")
