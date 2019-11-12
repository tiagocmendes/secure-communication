from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import binascii
from random import randrange


def statistical_analysis (n_messages,hash_function):
	hash_list=[]
	for i in range(n_messages):
		
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
		
		my_string=b"Ola,Ola,Ola,OlaOla,OlaOla,OlaOla,OlaOla,OlaOla,Ola"
		if i!=0:
			print("adsdas")
			random_index=randrange(len(my_string))
			message_array=bytearray(my_string)
			message_array[random_index]=message_array[random_index]^i
			my_string=str.encode(str(message_array[0]))
			
			
		digest.update(my_string)
		hash_list.append(binascii.hexlify(digest.finalize()))
	#print(hash_list)
	ones=0
	avg=0
	c=0	
	for j in range(len(hash_list)):
		for i in range (len(hash_list[0])):
			if(j!=0):
				ones+=bin(hash_list[0][i]^hash_list[j][i]).count('1')
				avg+=ones
				c+=1
	ones=avg/c
	print(ones)
	print(ones/(32*32))
			
				
		

	
statistical_analysis(200,"SHA256")

