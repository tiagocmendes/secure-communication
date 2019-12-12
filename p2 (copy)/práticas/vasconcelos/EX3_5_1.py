from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend

def key_pair_generation(key_length,file_name_public,file_name_private):
	valid_key_length=[1024,2048,3072,4096]
	if key_length not in valid_key_length:
		print("Invalid length")
		return
	
	key = rsa.generate_private_key(
		backend=crypto_default_backend(),
		public_exponent=65537,
		key_size=key_length
	)
	private_key = key.private_bytes(
		crypto_serialization.Encoding.PEM,
		crypto_serialization.PrivateFormat.TraditionalOpenSSL,
		crypto_serialization.NoEncryption())
		
	public_key = key.public_key().public_bytes(
		crypto_serialization.Encoding.PEM,
		crypto_serialization.PublicFormat.SubjectPublicKeyInfo
	)
	with open(file_name_public, "wb") as f:
		f.write(public_key)
	
    
	with open(file_name_private, "wb") as f:
		f.write(private_key)
	
	
key_pair_generation(2048,"public_key.txt","private_key.txt")
