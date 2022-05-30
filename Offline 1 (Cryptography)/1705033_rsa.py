from cgitb import reset
import math
from unittest import result
from BitVector import *
from audioop import add
import stat
import numpy as np
import time

def getRelativePrime(n) :
    p = 3
    while True :
        if math.gcd(p, n) == 1:
            return p
        p = p + 2

# Take Input
plainTextInput = input("\n\nPlain Text : ")

keys = [16, 32, 64, 128]

# count variable to run rsa algorithm using different key size
count = 0

while count < 4:
    print("\n\nUsing Key of Length", keys[count])
    print("\n\n")
    # Key-Pair Generation
    # Select Two Prime Numbers p & q where p != q
    # generate p
    st = time.time()
    while True:
        bv = BitVector(intVal = 0)
        bv = bv.gen_random_bits(keys[count])  
        check = bv.test_for_primality()
        if check > 0.9:
            p = int(bv)
            break

    # generate q
    while True:
        bv = BitVector(intVal = 0)
        bv = bv.gen_random_bits(8)  
        check = bv.test_for_primality()
        if check > 0.9 and int(bv) != p:
            q = int(bv)
            break

    # Calculate n = p * q
    n = p * q

    # Calculate Phi(n)
    phi_n = (p - 1) * (q - 1)

    # Select e such that e is relatively co-prime to phi_n
    # Euler's Totient Algorithm
    e = getRelativePrime(phi_n)
    # print(e)

    # Multiplicative inverse of e mod phi_n
    bv_modulus = BitVector(intVal = phi_n)
    bv = BitVector(intVal = e) 
    d = int(bv.multiplicative_inverse( bv_modulus ))

    print("Public Key = {", e, ",", n, "}")
    print("Private Key = {", d, ",", n, "}")
    et = time.time()

    keyGenerationTime = et - st

    # Take plain text as input
    plainText = list(plainTextInput)
    print(plainText)

    # Do Encryption character by character
    st = time.time()
    cypherText = []
    for i in range(len(plainText)):
        asciiValue = ord(plainText[i])
        cypherText.append(pow(asciiValue, e, n))
    print("After Encryption:")
    print(cypherText)
    et = time.time()

    encryptionTime = et - st

    #Do Decryption character by character
    st = time.time()
    decypheredText = []
    decypheredString = ""
    for i in range(len(cypherText)):
        decypheredCharacter = pow(cypherText[i], d, n)
        decypheredText.append(decypheredCharacter)
        decypheredString += chr(decypheredCharacter)
    et = time.time()
    decryptionTime = et - st

    print("After Decryption:")
    print(decypheredText)
    print(decypheredString)

    print("\n\nTime Info:")
    print("Key Generation Time:", keyGenerationTime, "seconds")
    print("Encryption Time:", encryptionTime, "seconds")
    print("Decryption Time:", decryptionTime, "seconds")
    count += 1

 

