import getpass
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import utils, rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def key_pair_gen(password, length, private_file, public_file):
    valid_lengths = [1024, 2048, 3072, 4096]

    if length not in valid_lengths:
        print("ERROR - Not a valid length!")
        return 
    
    password = password.encode()

    private_key = rsa.generate_private_key(
        public_exponent=65537, 
        key_size=length,
        backend=default_backend()
    )

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )

    private_file = open(private_file, 'wb')
    private_file.write(pem)
    private_file.close()

    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    public_file = open(public_file, 'wb')
    public_file.write(pem)
    public_file.close()

def rsa_encryption(file_name, key_file, encrypted_file):
    
    f = open(file_name, 'r')

    message = b''
    for line in f:
        message += line.encode()
    
    with open(key_file, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(encrypted_file, 'wb') as encrypted_file:
        encrypted_file.write(ciphertext)

def rsa_decryption(pw, file_name, key_file, decrypted_file):
    
    with open(key_file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=pw.encode(),
            backend=default_backend()
        )
    
    with open(file_name, 'rb') as file_name:
        ciphertext = file_name.read()

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(decrypted_file, 'w') as encrypted_file:
        encrypted_file.write(plaintext.decode())

    
if __name__ == '__main__':
    try:
        pw = getpass.getpass(prompt='Password: ', stream=None)
    except Exception as error:
        print('ERROR', error)
        
    key_pair_gen(pw, 4096, 'private_file.key', 'public_file.key')
    rsa_encryption('secret-message.txt', 'public_file.key', 'encrypted-message.txt')
    rsa_decryption(pw,'encrypted-message.txt', 'private_file.key', 'decrypted-message.txt')