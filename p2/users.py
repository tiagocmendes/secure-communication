import random
import string
import asyncio
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes 
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography import x509
from datetime import datetime

first_names = ["André", "Bernardo", "Carlos",
               "Diogo", "João", "Pedro", "Tiago", "Vasco"]
last_names = ["Amorim", "Barroso", "Carvalho",
              "Pereira", "Mendes", "Vasconcelos", "Silva"]

def randomString(stringLength=10):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    letters += "123456789_~^!/"
    return ''.join(random.choice(letters) for i in range(stringLength))

permissions = ['AUTHENTICATION', 'AUTHENTICATION:PERMISSION']

with open('plain_passwords.csv', 'w') as p:
    with open('users.csv', 'w') as f:
        f.write("Username\tPassword\tAccess\n")
        for i in range(10):
            fname = random.choice(first_names)
            lname = random.choice(last_names)
            username = fname.lower() + "_" + lname.lower() + str(i) + "@ua.pt"
            plain_password = randomString(20)
            password = str(base64.b64encode(plain_password.encode('utf-8')))
            
            f.write(username + "\t" + password + "\t" + random.choice(permissions) + "\n")
            p.write(username + "\t" + plain_password + "\n")
