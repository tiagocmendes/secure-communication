import binascii
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def hash_content(file_name, hash_function, avalanche=""):

    # possible cryptographic hash function
    options = {'MD5': hashes.MD5(), 'SHA-256': hashes.SHA256(), 'SHA-384': hashes.SHA384() \
        ,'SHA-512': hashes.SHA512(), 'BLAKE-2': hashes.BLAKE2b(64)}
    
    if hash_function not in options:
        print(f"Incorrect cryptographic hash function: {hash_function}")
        print(f"Available cryptographic hash functions: {hashes}")
    
    digest = hashes.Hash(options[hash_function], backend=default_backend())

    data = []
    with open(file_name, "r") as fr:
        blob = fr.read(1024)
        encoded = blob.encode()
        byte_arr = bytearray(encoded)
        byte_arr[0] = byte_arr[0] ^ 1
        digest.update(byte_arr)
        while blob:
            blob = fr.read(1024)
            digest.update(blob.encode())
    
    with open(hash_function.lower() + avalanche + ".txt", "w") as fw:
        fw.write(f"{hash_function}: {binascii.hexlify(digest.finalize())}")
    

def main():
    options = ['MD5', 'SHA-256', 'SHA-384', 'SHA-512', 'BLAKE-2']
    for o in options:
        # change third field if you want to change a single bit in the string
        hash_content('data.txt', o, "_avalanche")

if __name__ == '__main__':
    main()