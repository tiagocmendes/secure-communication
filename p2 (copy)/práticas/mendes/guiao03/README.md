# 3. Applied Cryptography

## Symmetric Cryptography

Symmetric cryptography is used by creating an object that represents a given cipher, with some parameters specifyingthe mode, as well as a key. The cipher object presents an encryptor method, that is applied (update) to the text in chunks (may require alignment with the cipher block size). After the text is ciphered, a finalize method may be used. Decryption is done in a similar way.

## Symmetric key generation

Before a cipher is used, it is required the generation of proper arguments. These arguments are the key, the cipher mode, and potentially the Initialization Vector (IV). The cipher mode is chosen at design time, and the IV should always be a large random number (size similar to the block size or key) that is never repeated. This lab will discuss the IVs in the next sections.

The key can be obtained from good sources of random numbers, or generated from other primitive material such as a password. When choosing the last source (a password), it is imperative to transform the user text into a key of the correct complexity. While there are many methods, we will consider the Password Based Key Derivation Function 2 (PKBDF2), which takes a key, a random value named salt, a digest algorithm and a number of iterations (you should use several thousands).  The algorithm will iterate the digest algorithm in a chain starting in the concatenation of the salt and key, for the specified number of iterations. Using Secure Hash Algorithm 2 (SHA-2), the result is at least 256 bits, which can be used as a key.

