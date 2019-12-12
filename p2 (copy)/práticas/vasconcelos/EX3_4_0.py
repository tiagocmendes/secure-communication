from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import binascii

def hashing (original_file_name,hash_function,file_name_write):

	if(hash_function=="SHA256"):
		digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
	elif(hash_function=="SHA384"):
		digest = hashes.Hash(hashes.SHA384(), backend=default_backend())
	elif(hash_function=="MD5"):
		digest = hashes.Hash(hashes.MD5(), backend=default_backend())
	elif(hash_function=="SHA512"):
		digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
	elif(hash_function=="BLAKE2"):
		digest = hashes.Hash(hashes.BLAKE2b(64), backend=default_backend())
	
	with open(original_file_name,"rb") as fr:
		my_text=fr.read(1024)
		digest.update(my_text)
		while my_text:
			my_text=fr.read(1024)
			digest.update(my_text)
			
	with open(file_name_write, "wb") as f:
		f.write(binascii.hexlify(digest.finalize()))

	
hashing("text_v2.txt","SHA256","SHA256_text_v2.txt")
