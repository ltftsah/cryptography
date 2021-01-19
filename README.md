# Cryptography
University assignments for the Cryptography and Security Protocols module

## Grades
Assignment 1: 15/15
Assignment 2: 12/15

## Assignment 1
The aim of this assignment is to perform symmetric encryption using the block cipher AES. Before this encryption can be done, a key must be exchanged with the receiver of the message (me); this will be done using Diffie-Hellman key agreement. The values which you need to know for this exchange are provided.
In order to perform the Diffie-Hellman key exchange, you should do the following:

    Generate a random 1023-bit integer; this will be your secret value b.
    Generate your public shared value B given by gb (mod p)
    Calculate the shared secret s given by Ab (mod p)
   
Now that you have the value of the shared secret s, you can use this for your AES encryption. However, it is too large (1024 bits) to be used directly as the AES key. You should therefore use SHA-256 to produce a 256-bit digest from the shared secret s, giving a 256-bit AES key k.

You will then encrypt an input binary file using AES in CBC mode with the 256-bit key k and a block size of 128-bits. The IV for this encryption will be a randomly generated 128-bit value. You will use the following padding scheme (as given in lectures): if the final part of the message is less than the block size, append a 1-bit and fill the rest of the block with 0-bits; if the final part of the message is equal to the block size, then create an extra block starting with a 1-bit and fill the rest of the block with 0-bits. 

The implementation language must be Java. Your program should take an additional filename in the command line and output to standard output the result of encrypting this file. The input binary file will be the Java class file resulting from compiling your program.

You will have to make use of the BigInteger class (java.math.BigInteger), the security libraries (java.security.*) and the crypto libraries (javax.crypto.*). You must not make use of the methods provided by the BigInteger class to implement the modular exponentiation; all modular exponentiation must be done using one of the two square and multiply algorithms described in the lectures (left-to-right method or right-to-left method). You can however make use of the crypto libraries to perform the AES encryption and the SHA-256 hashing.

## Assignment 2

The aim of this assignment is to implement a digital signature using RSA. Before the digital signature can be implemented, you will need to set up an appropriate public/private RSA key pair. This should be done as follows:

    Generate two distinct 512-bit probable primes p and q
    Calculate the product of these two primes n = pq
    Calculate the Euler totient function phi(n)
    You will be using an encryption exponent e = 65537, so you will need to ensure that this is relatively prime to phi(n). If it is not, go back to step 1 and generate new values for p and q
    Compute the value for the decryption exponent d, which is the multiplicative inverse of e (mod phi(n)). This should use your own implementation of the extended Euclidean GCD algorithm to calculate the inverse rather than using a library method for this purpose.

You should then write code to implement a decryption method which calculates h(m)d (mod n) for message digest h(m). You should use your own implementation of the Chinese Remainder Theorem to calculate this more efficiently; this can also make use of your multiplicative inverse implementation.

You will then digitally sign the digest of an input binary file using your RSA decryption method. The 256-bit digest will be produced using SHA-256. Note that, for the purpose of this assignment, no randomness or redundancy should be added to the message before performing the digital signature.

The implementation language must be Java. Your program should take an additional filename in the command line and output to standard output the result of digitally signing this file. The input binary file will be the Java class file resulting from compiling your program.

You can make use of the BigInteger class (java.math.BigInteger), the security libraries (java.security.*) and the crypto libraries (javax.crypto.*). You must not make use of the multiplicative inverse or GCD methods provided by the BigInteger class; you will need to implement these yourself. You can however make use of the crypto libraries to perform the SHA-256 hashing.
