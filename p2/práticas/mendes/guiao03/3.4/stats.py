import binascii
import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def hash_content(file_name, hash_function, N=5):

    # possible cryptographic hash function
    options = {'MD5': hashes.MD5(), 'SHA-256': hashes.SHA256(), 'SHA-384': hashes.SHA384() \
        ,'SHA-512': hashes.SHA512(), 'BLAKE-2': hashes.BLAKE2b(64)}
    
    if hash_function not in options:
        print(f"Incorrect cryptographic hash function: {hash_function}")
        print(f"Available cryptographic hash functions: {hashes}")
    
    digest = hashes.Hash(options[hash_function], backend=default_backend())

    blob = b''
    with open(file_name, "r") as fr:
        for line in fr:
            blob += line.encode()
    
    for i in range(N):
        byte_arr = bytearray(blob)
        rand_bit = random.randint(0, len(blob))
        byte_arr[rand_bit] = byte_arr[rand_bit] ^ 1

        

    

def main():
    options = ['MD5', 'SHA-256', 'SHA-384', 'SHA-512', 'BLAKE-2']
    for o in options:
        # change third field if you want to change a single bit in the string
        hash_content('data.txt', o, 20)

if __name__ == '__main__':
    main()