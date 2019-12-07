import binascii
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def hash_content(file_name, hash_function):

    # possible cryptographic hash function
    options = {'MD5': hashes.MD5(), 'SHA-256': hashes.SHA256(), 'SHA-384': hashes.SHA384() \
        ,'SHA-512': hashes.SHA512(), 'BLAKE-2': hashes.BLAKE2b()}
    
    if hash_function not in hashes:
        print(f"Incorrect cryptographic hash function: {hash_function}")
        print(f"Available cryptographic hash functions: {hashes}")
    
    digest = hashes.Hash(options[hash_function], backend=default_backend())

    data = []
    with open("file_name", "r") as fr:
        blob = fr.read(1024)
        digest.update(blob)
        while blob:
            blob = fr.read(1024)
            digest.update(blob)
            
    print(binascii.hexlify(digest.finalize()))
    

def main():
    hash_content('data.txt', 'MD5')

if __name__ == '__main__':
    main()